package com.flow.validator.mitm;

import android.net.VpnService;
import android.util.Log;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.flow.validator.vpn.ConnTrack;
import com.flow.validator.vpn.PacketParser;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * MitmProxy -- Local HTTPS interception proxy.
 *
 * Architecture:
 *
 *   Client App
 *     | TLS (spoofed cert, selected via SNI from ClientHello)
 *     v
 *   MitmProxy  [SSLServerSocket on LOCAL_PORT=8443]
 *     | SniKeyManager selects per-domain cert from CertificateManager
 *     | StreamInspector inspects decrypted stream
 *     |   match  -> inject mock 200 response, close
 *     |   no match -> relay to real server
 *     | SSLSocket to real server (VpnService.protect()-ed)
 *     v
 *   Real HTTPS Server
 *
 * Threading: each accepted connection is submitted to the shared
 * ForkJoinPool (work-stealing) provided by ValidatorVpnService.
 */
public final class MitmProxy {

    private static final String TAG        = "MitmProxy";
    public  static final int    LOCAL_PORT = 8443;

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 15_000;
    private static final int HTTPS_PORT         = 443;

    // Domains whose HTTPS traffic should be intercepted
    private static final Set<String> INTERCEPT_DOMAINS = new HashSet<>(Arrays.asList(
            "admob.googleapis.com",
            "unityads.unity3d.com",
            "applovin.com",
            "an.facebook.com",
            "ads.mopub.com",
            "app-measurement.com",
            "analytics.google.com"
    ));

    private SSLServerSocket  serverSocket;
    private VpnService       vpnService;
    private ForkJoinPool     workerPool;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread acceptThread;

    // Connection table: addr:port -> hostname (for logging)
    private final ConcurrentHashMap<String, String> connectionTable = new ConcurrentHashMap<>();

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public void start(VpnService vpn, ForkJoinPool pool) throws Exception {
        if (!running.compareAndSet(false, true)) return;

        this.vpnService = vpn;
        this.workerPool = pool;

        CertificateManager.getInstance().initialize(vpn);

        // Build an SSLContext whose KeyManager selects per-SNI certificates
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(
            new KeyManager[]{ new SniKeyManager() },
            new TrustManager[]{ TRUST_ALL },
            null
        );

        SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket();
        serverSocket.setReuseAddress(true);

        // Enable SNI on the server socket
        SSLParameters params = serverSocket.getSSLParameters();
        params.setNeedClientAuth(false);
        serverSocket.setSSLParameters(params);

        serverSocket.bind(new InetSocketAddress("127.0.0.1", LOCAL_PORT));

        acceptThread = new Thread(this::acceptLoop, "mitm-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();

        Log.i(TAG, "MitmProxy started on port " + LOCAL_PORT);
    }

    public void stop() {
        running.set(false);
        try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        if (acceptThread != null) acceptThread.interrupt();
        Log.i(TAG, "MitmProxy stopped");
    }

    // -------------------------------------------------------------------------
    // Accept loop
    // -------------------------------------------------------------------------

    private void acceptLoop() {
        while (running.get()) {
            try {
                SSLSocket client = (SSLSocket) serverSocket.accept();
                client.setSoTimeout(READ_TIMEOUT_MS);
                workerPool.execute(() -> handleConnection(client));
            } catch (Exception e) {
                if (running.get()) Log.e(TAG, "Accept error: " + e.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Per-connection handler
    // -------------------------------------------------------------------------

    private void handleConnection(SSLSocket client) {
        String clientKey = client.getInetAddress().getHostAddress() + ":" + client.getPort();
        try {
            // Trigger handshake -- SniKeyManager will select the right cert
            client.startHandshake();

            // Retrieve the hostname the client used (set by SniKeyManager during handshake)
            String hostname = getSniHostname(client);
            if (hostname == null || hostname.isEmpty()) {
                // Fallback: смотрим оригинальный dst из ConnTrack по адресу клиента
                try {
                    java.net.InetSocketAddress clientAddr =
                        (java.net.InetSocketAddress) client.getRemoteSocketAddress();
                    if (clientAddr != null) {
                        byte[] addrBytes = clientAddr.getAddress().getAddress();
                        int srcIp = ((addrBytes[0] & 0xFF) << 24)
                                  | ((addrBytes[1] & 0xFF) << 16)
                                  | ((addrBytes[2] & 0xFF) << 8)
                                  |  (addrBytes[3] & 0xFF);
                        String origDst = ConnTrack.getOrigDstString(srcIp, clientAddr.getPort());
                        if (origDst != null && origDst.contains(":")) {
                            hostname = origDst.split(":")[0];
                            Log.d(TAG, "hostname from ConnTrack: " + hostname);
                        }
                    }
                } catch (Exception ignored) {}
            }
            if (hostname == null || hostname.isEmpty()) {
                Log.w(TAG, "Cannot determine hostname for " + clientKey + ", closing");
                client.close();
                return;
            }

            connectionTable.put(clientKey, hostname);
            Log.d(TAG, "Handshake done: " + clientKey + " -> " + hostname);

            boolean shouldIntercept = shouldInterceptDomain(hostname);

            if (!shouldIntercept) {
                // Transparent passthrough -- relay raw bytes
                transparentRelay(client.getInputStream(), client.getOutputStream(),
                                 hostname, HTTPS_PORT);
                return;
            }

            // Open protected upstream connection to the real server
            SSLSocket upstream = openUpstream(hostname, HTTPS_PORT);
            if (upstream == null) {
                client.close();
                return;
            }

            InputStream  clientIn  = client.getInputStream();
            OutputStream clientOut = client.getOutputStream();
            InputStream  serverIn  = upstream.getInputStream();
            OutputStream serverOut = upstream.getOutputStream();

            StreamInspector inspector = StreamInspector.getInstance();
            boolean intercepted = inspector.inspect(clientIn, clientOut, serverOut, hostname);

            if (!intercepted) {
                inspector.pipeResponse(serverIn, clientOut);
            }

            upstream.close();

        } catch (Exception e) {
            Log.e(TAG, "Handler error [" + clientKey + "]: " + e.getMessage());
        } finally {
            connectionTable.remove(clientKey);
            try { client.close(); } catch (Exception ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // Upstream connection (VpnService.protect -- bypasses VPN tunnel)
    // -------------------------------------------------------------------------

    private SSLSocket openUpstream(String host, int port) {
        try {
            Socket raw = new Socket();
            vpnService.protect(raw);
            raw.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            raw.setSoTimeout(READ_TIMEOUT_MS);

            SSLSocketFactory factory = buildTrustAllContext().getSocketFactory();
            SSLSocket ssl = (SSLSocket) factory.createSocket(raw, host, port, true);
            ssl.setUseClientMode(true);

            SSLParameters p = ssl.getSSLParameters();
            p.setServerNames(java.util.Collections.singletonList(new SNIHostName(host)));
            ssl.setSSLParameters(p);

            ssl.startHandshake();
            Log.d(TAG, "Upstream TLS connected: " + host + ":" + port);
            return ssl;
        } catch (Exception e) {
            Log.e(TAG, "Upstream connect failed [" + host + "]: " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Transparent relay (no TLS break -- just pipe bytes)
    // -------------------------------------------------------------------------

    private void transparentRelay(InputStream clientIn, OutputStream clientOut,
                                  String host, int port) {
        try {
            Socket upstream = new Socket();
            vpnService.protect(upstream);
            upstream.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            upstream.setSoTimeout(READ_TIMEOUT_MS);

            final InputStream upIn   = upstream.getInputStream();
            final OutputStream upOut = upstream.getOutputStream();

            Thread t = new Thread(() ->
                StreamInspector.getInstance().pipeResponse(upIn, clientOut), "mitm-relay");
            t.setDaemon(true);
            t.start();

            StreamInspector.getInstance().pipeResponse(clientIn, upOut);
            try { t.join(5000); } catch (InterruptedException ignored) {}
            upstream.close();
        } catch (Exception e) {
            Log.d(TAG, "Transparent relay ended: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // SNI extraction from SSLSocket after handshake
    // -------------------------------------------------------------------------

    private String getSniHostname(SSLSocket socket) {
        try {
            if (socket.getSession() instanceof ExtendedSSLSession) {
                ExtendedSSLSession session = (ExtendedSSLSession) socket.getSession();
                List<SNIServerName> names = session.getRequestedServerNames();
                if (names != null && !names.isEmpty()) {
                    SNIServerName sni = names.get(0);
                    if (sni instanceof SNIHostName) {
                        return ((SNIHostName) sni).getAsciiName();
                    }
                    // Fallback: raw ASCII bytes (SNI hostnames are always ASCII)
                    return new String(sni.getEncoded(), StandardCharsets.US_ASCII);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // -------------------------------------------------------------------------
    // Domain routing
    // -------------------------------------------------------------------------

    private boolean shouldInterceptDomain(String hostname) {
        if (hostname == null) return false;
        String lower = hostname.toLowerCase();
        for (String target : INTERCEPT_DOMAINS) {
            if (lower.equals(target) || lower.endsWith("." + target)) return true;
        }
        return lower.contains("ads.") || lower.contains(".ads.")
                || lower.contains("analytics") || lower.contains("tracking");
    }

    // -------------------------------------------------------------------------
    // SNI-aware KeyManager -- selects per-domain certificate during handshake
    //
    // When the TLS client sends a ClientHello with SNI, the JVM calls
    // chooseEngineServerAlias(). We extract the SNI from the SSLEngine's
    // handshake session and return a per-domain certificate from
    // CertificateManager.
    // -------------------------------------------------------------------------

    private static final class SniKeyManager extends X509ExtendedKeyManager {

        // Cache: alias (== hostname) -> [leafCert, caCert]
        private final ConcurrentHashMap<String, X509Certificate[]> certCache
                = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, PrivateKey> keyCache
                = new ConcurrentHashMap<>();

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers,
                                              SSLEngine engine) {
            try {
                if (engine.getHandshakeSession() instanceof ExtendedSSLSession) {
                    ExtendedSSLSession hs = (ExtendedSSLSession) engine.getHandshakeSession();
                    List<SNIServerName> names = hs.getRequestedServerNames();
                    if (names != null && !names.isEmpty()) {
                        SNIServerName sni = names.get(0);
                        String hostname = (sni instanceof SNIHostName)
                                ? ((SNIHostName) sni).getAsciiName()
                                : new String(sni.getEncoded(), StandardCharsets.US_ASCII);
                        ensureCertLoaded(hostname);
                        return hostname;
                    }
                }
            } catch (Exception e) {
                Log.e("SniKeyManager", "chooseEngineServerAlias error: " + e.getMessage());
            }
            return "default";
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers,
                                        java.net.Socket socket) {
            return "default";
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            X509Certificate[] chain = certCache.get(alias);
            if (chain != null) return chain;
            // Fallback: return CA cert chain
            try {
                X509Certificate ca = CertificateManager.getInstance().getCaCert();
                return new X509Certificate[]{ ca };
            } catch (Exception e) {
                return new X509Certificate[0];
            }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return keyCache.get(alias);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return certCache.keySet().toArray(new String[0]);
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) { return null; }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers,
                                        java.net.Socket socket) { return null; }

        private void ensureCertLoaded(String hostname) {
            if (certCache.containsKey(hostname)) return;
            try {
                // Build a temporary SSLContext to extract the KeyStore entry
                SSLContext ctx = CertificateManager.getInstance()
                        .getOrCreateSpoofedCert(hostname);
                if (ctx == null) return;

                // Re-extract the leaf key pair by re-generating (or from cache)
                // For simplicity, use CertificateManager to build a fresh KeyStore
                KeyStore ks = buildKeyStore(hostname);
                if (ks == null) return;

                PrivateKey pk = (PrivateKey) ks.getKey("leaf", new char[0]);
                java.security.cert.Certificate[] chain = ks.getCertificateChain("leaf");

                if (pk != null && chain != null) {
                    keyCache.put(hostname, pk);
                    X509Certificate[] x509chain = new X509Certificate[chain.length];
                    for (int i = 0; i < chain.length; i++) {
                        x509chain[i] = (X509Certificate) chain[i];
                    }
                    certCache.put(hostname, x509chain);
                }
            } catch (Exception e) {
                Log.e("SniKeyManager", "Failed to load cert for " + hostname + ": " + e.getMessage());
            }
        }

        private KeyStore buildKeyStore(String hostname) throws Exception {
            // Ask CertificateManager for the cert materials via a temp SSLContext
            // We use a trick: build the context then pull the KeyStore out of our own init
            // Actually, we call CertificateManager.buildKeyStoreForHost() -- see below
            return CertificateManager.getInstance().buildKeyStoreForHost(hostname);
        }
    }

    // -------------------------------------------------------------------------
    // Trust-all SSLContext (for upstream outbound leg)
    // -------------------------------------------------------------------------

    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };

    private SSLContext buildTrustAllContext() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{ TRUST_ALL }, null);
            return ctx;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build trust-all context", e);
        }
    }
}

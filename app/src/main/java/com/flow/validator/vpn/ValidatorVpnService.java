package com.flow.validator.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.flow.validator.audit.LogAnalyzer;
import com.flow.validator.mitm.MitmProxy;
import com.flow.validator.util.LatencyTracker;

import android.os.Binder;
import android.os.IBinder;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * ValidatorVpnService — DPI + DNS-блокировка + HTTPS MITM перехватчик.
 *
 * ИСПРАВЛЕННАЯ АРХИТЕКТУРА:
 *
 *  TUN Interface (MTU=1500, IP 10.99.0.1/24)
 *      │ readPacket()
 *      ▼
 *  Reader Thread (MAX_PRIORITY-1)
 *      │ snapshot() → ForkJoinPool
 *      ▼
 *  processPacket():
 *    1. IPv4 validity check
 *    2. Whitelist IP bypass
 *    3. DNS/UDP-53 → buildDnsBlockResponse() → inject proper DNS reply packet
 *    4. HTTPS/TCP-443 → TcpProxy.redirect() перенаправляет в MitmProxy:8443
 *    5. HTTP/TCP-80 DPI → buildTcpRstPacket() для блокировки
 *    6. LatencyTracker
 *
 *  MitmProxy (SSLServerSocket @ 127.0.0.1:8443)
 *    - SNI extraction
 *    - CertificateManager dynamic cert
 *    - StreamInspector URI matching
 *
 * ВАЖНО: HTTPS MITM требует установки CA сертификата в User Trusted Credentials
 * через CertInstallActivity. На Android 7+ без root работает только для приложений
 * с android:networkSecurityConfig разрешающим user certs, либо при Device Owner.
 */
public class ValidatorVpnService extends VpnService {

    private static final String TAG              = "ValidatorVPN";
    private static final String NOTIF_CHANNEL_ID = "sentinel_vpn";
    private static final int    NOTIF_ID         = 1001;

    // Правильный MTU — стандартный Ethernet MTU
    private static final int TUN_MTU = 1500;

    // =========================================================================
    // LAYER-7 URL PATTERNS
    // =========================================================================
    private static final String[] RAW_PATTERNS = {
            "/v1/verify", "/get_reward", "/complete_task", "/ads/v2/callback",
            "/v[0-9]+/verify", "/reward[s]?(/.*)?", "/ad[s]?/.*callback",
            "/events?/track", "/collect", "/pixel", "/beacon",
            "/impression", "/click[s]?/", ".*analytics.*",
    };
    private static final Pattern[] URL_PATTERNS;
    static {
        URL_PATTERNS = new Pattern[RAW_PATTERNS.length];
        for (int i = 0; i < RAW_PATTERNS.length; i++) {
            URL_PATTERNS[i] = Pattern.compile(RAW_PATTERNS[i], Pattern.CASE_INSENSITIVE);
        }
    }

    // =========================================================================
    // BLOCKED DOMAINS
    // =========================================================================
    private static volatile Set<String> BLOCKED_DOMAINS = buildBlockList();

    private static Set<String> buildBlockList() {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                "admob.googleapis.com",
                "googleads.g.doubleclick.net",
                "pubads.g.doubleclick.net",
                "pagead2.googlesyndication.com",
                "unityads.unity3d.com",
                "config.unityads.unity3d.com",
                "auctions.unityads.unity3d.com",
                "applovin.com", "d.applovin.com", "rt.applovin.com",
                "graph.facebook.com", "an.facebook.com",
                "ads.mopub.com", "analytics.mopub.com",
                "e.crashlytics.com", "settings.crashlytics.com",
                "app-measurement.com",
                "sentry.io", "ingest.sentry.io",
                "analytics.google.com",
                "ssl.google-analytics.com",
                "stats.g.doubleclick.net"
        )));
    }

    // =========================================================================
    // IP WHITELIST
    // =========================================================================
    private static final String[] WHITELIST_PREFIXES = {
            "216.58.", "172.217.", "142.250.",
            "34.104.", "34.105.",
            "8.8.8.",  "1.1.1.",
            "10.99.",  "127.",
    };
    private static final Set<String> WHITELIST_DOMAINS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "play.googleapis.com",
                    "android.googleapis.com",
                    "fcm.googleapis.com",
                    "accounts.google.com",
                    "oauth2.googleapis.com",
                    "android.clients.google.com"
            ))
    );

    // =========================================================================
    // UID TIGHTENING
    // =========================================================================
    private final ConcurrentHashMap<Integer, Long> tightenedUids = new ConcurrentHashMap<>();
    private static final long TIGHTEN_MS = 60_000L;

    // =========================================================================
    // Runtime state
    // =========================================================================
    // BUG FIX: volatile для thread-safe доступа из reader thread и onDestroy()
    private volatile ParcelFileDescriptor vpnPfd;
    private volatile TunChannel           tun;
    private LogAnalyzer                   logAnalyzer;
    private LatencyTracker                latencyTracker;
    private MitmProxy                     mitmProxy;

    private final AtomicBoolean running = new AtomicBoolean(false);

    private ForkJoinPool             workerPool;
    private ScheduledExecutorService scheduler;
    private Thread                   readerThread;

    // =========================================================================
    // LocalBinder — для ServiceConnection из MainService
    // =========================================================================

    public class LocalBinder extends Binder {
        public ValidatorVpnService getService() { return ValidatorVpnService.this; }
    }

    private final IBinder localBinder = new LocalBinder();

    @Override
    public IBinder onBind(Intent intent) {
        // VpnService.onBind() обрабатывает android.net.VpnService intent
        IBinder b = super.onBind(intent);
        return b != null ? b : localBinder;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    public void attachLogAnalyzer(LogAnalyzer a)       { this.logAnalyzer   = a; }
    public void attachLatencyTracker(LatencyTracker t) { this.latencyTracker = t; }
    public LatencyTracker getLatencyTracker()           { return latencyTracker; }

    public void tightenUid(int uid) {
        tightenedUids.put(uid, System.currentTimeMillis() + TIGHTEN_MS);
        Log.i(TAG, "Tighten ON | uid=" + uid);
    }

    public static void updateBlockedDomains(Set<String> domains) {
        BLOCKED_DOMAINS = Collections.unmodifiableSet(new HashSet<>(domains));
        Log.i(TAG, "Blocklist updated: " + domains.size() + " domains");
    }

    // =========================================================================
    // VpnService lifecycle
    // =========================================================================

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        startForeground(NOTIF_ID, buildNotification());

        int cpus = Runtime.getRuntime().availableProcessors();
        workerPool = new ForkJoinPool(
                Math.max(2, cpus),
                ForkJoinPool.defaultForkJoinWorkerThreadFactory,
                (t, e) -> Log.e(TAG, "Uncaught in pool: " + e.getMessage()),
                true
        );

        scheduler = new ScheduledThreadPoolExecutor(1, r -> {
            Thread t = new Thread(r, "vpn-scheduler");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::purgeTightenedUids, 15, 15, TimeUnit.SECONDS);

        if (latencyTracker == null) latencyTracker = new LatencyTracker();
        mitmProxy = new MitmProxy();

        Log.i(TAG, "ValidatorVpnService created | cpus=" + cpus);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (running.compareAndSet(false, true)) {
            if (establishTun()) {
                startMitmProxy();
                startReaderThread();
            }
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running.set(false);
        if (readerThread != null) readerThread.interrupt();
        if (mitmProxy    != null) mitmProxy.stop();
        if (workerPool   != null) workerPool.shutdownNow();
        if (scheduler    != null) scheduler.shutdownNow();
        closeTun();
        super.onDestroy();
        Log.i(TAG, "ValidatorVpnService destroyed");
    }

    // =========================================================================
    // TUN interface
    // BUG FIX #1: MTU исправлен с 32768 → 1500 (стандартный Ethernet MTU)
    // BUG FIX #2: проверка vpnPfd на null перед использованием
    // =========================================================================

    private boolean establishTun() {
        try {
            Builder b = new Builder();
            b.setSession("SentinelNode")
             .addAddress("10.99.0.1", 24)
             .addRoute("0.0.0.0", 0)
             .addDnsServer("8.8.8.8")
             .addDnsServer("1.1.1.1")
             .setMtu(TUN_MTU)          // FIX: было BUF_SIZE=32768, теперь 1500
             .setBlocking(true);

            for (String pkg : SYSTEM_PACKAGES) {
                try { b.addDisallowedApplication(pkg); } catch (Exception ignored) {}
            }
            // Исключить само приложение из VPN чтобы MitmProxy upstream не зациклился
            try { b.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}

            vpnPfd = b.establish();

            // FIX: establish() возвращает null если разрешение не выдано
            if (vpnPfd == null) {
                Log.e(TAG, "VPN permission not granted — vpnPfd is null");
                running.set(false);
                stopSelf();
                return false;
            }

            tun = new TunChannel(vpnPfd.getFileDescriptor());
            tun.open();
            Log.i(TAG, "TUN established | mtu=" + TUN_MTU);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "TUN establish failed: " + e.getMessage());
            running.set(false);
            stopSelf();
            return false;
        }
    }

    private void closeTun() {
        TunChannel localTun = tun;
        tun = null;
        if (localTun != null) localTun.close();

        ParcelFileDescriptor pfd = vpnPfd;
        vpnPfd = null;
        if (pfd != null) {
            try { pfd.close(); } catch (Exception ignored) {}
        }
    }

    private static final String[] SYSTEM_PACKAGES = {
            "com.android.vending",
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.providers.downloads",
            "com.android.systemui",
    };

    // =========================================================================
    // MITM proxy startup
    // =========================================================================

    private void startMitmProxy() {
        try {
            mitmProxy.start(this, workerPool);
        } catch (Exception e) {
            Log.e(TAG, "MitmProxy start failed: " + e.getMessage());
        }
    }

    // =========================================================================
    // Reader thread
    // BUG FIX #3: volatile snapshot tun перед использованием → безопасно при onDestroy
    // =========================================================================

    private void startReaderThread() {
        readerThread = new Thread(() -> {
            Log.i(TAG, "Reader thread started");
            while (running.get()) {
                // FIX: берём snapshot volatile поля tun
                TunChannel localTun = tun;
                if (localTun == null) break;

                ByteBuffer slice = localTun.readPacket();
                if (slice == null) continue;

                ByteBuffer pkt = TunChannel.snapshot(slice);
                workerPool.execute(() -> processPacket(pkt));
            }
            Log.i(TAG, "Reader thread exited");
        }, "vpn-reader");
        readerThread.setDaemon(true);
        readerThread.setPriority(Thread.MAX_PRIORITY - 1);
        readerThread.start();
    }

    // =========================================================================
    // Packet processing pipeline
    //
    // АРХИТЕКТУРНЫЕ ИСПРАВЛЕНИЯ:
    // #4 - DNS блокировка: строим настоящий DNS NXDOMAIN UDP-пакет
    // #5 - HTTP блокировка: строим TCP RST пакет вместо голого HTTP в TUN
    // #6 - HTTPS: перенаправляем через TcpProxy в MitmProxy (порт 8443)
    // =========================================================================

    private void processPacket(ByteBuffer pkt) {
        if (latencyTracker != null) latencyTracker.begin();

        try {
            if (!PacketParser.isValidIPv4(pkt)) return;

            String dstIp = intToIp(PacketParser.dstIp(pkt));
            if (isWhitelistedIp(dstIp)) return;

            // ── DNS блокировка: возвращаем корректный NXDOMAIN пакет ─────────
            if (PacketParser.isDns(pkt)) {
                String host = PacketParser.dnsQueryName(pkt);
                if (host != null && isDomainBlocked(host, false)) {
                    byte[] dnsReply = buildDnsNxdomainPacket(pkt);
                    if (dnsReply != null) {
                        injectRawPacket(dnsReply, "DNS-BLOCK:" + host);
                    }
                    return;
                }
            }

            // ── HTTPS: перенаправляем в MitmProxy через TCP proxy ────────────
            // MitmProxy слушает на 127.0.0.1:8443.
            // Для реального перехвата нужно переписать dst IP+port в пакете
            // и отправить его обратно в TUN. TcpProxy обрабатывает state machine.
            if (PacketParser.isHttps(pkt)) {
                // Передаём пакет в TcpProxy для обработки HTTPS редиректа
                byte[] redirected = TcpProxy.redirectToMitm(pkt, "127.0.0.1", MitmProxy.LOCAL_PORT);
                if (redirected != null) {
                    injectRawPacket(redirected, "HTTPS-MITM");
                }
                return;
            }

            // ── HTTP DPI: RST соединение для заблокированных ─────────────────
            if (PacketParser.isHttp(pkt)) {
                String payload = PacketParser.tcpPayloadString(pkt, 2048);
                if (!payload.isEmpty()) {
                    String path = extractPath(firstLine(payload));
                    if (matchesPattern(path)) {
                        byte[] rst = buildTcpRstPacket(pkt);
                        if (rst != null) injectRawPacket(rst, "L7-HTTP-RST");
                        return;
                    }
                    String host = extractHostHeader(payload);
                    if (host != null && isDomainBlocked(host, false)) {
                        byte[] rst = buildTcpRstPacket(pkt);
                        if (rst != null) injectRawPacket(rst, "HOST-HDR-RST");
                        return;
                    }
                }
            }

            // ── UID-tightened scan ───────────────────────────────────────────
            if (PacketParser.isTcp(pkt) && !tightenedUids.isEmpty()) {
                String payload = PacketParser.tcpPayloadString(pkt, 512);
                if (hasTightenedSignal(payload)) {
                    byte[] rst = buildTcpRstPacket(pkt);
                    if (rst != null) injectRawPacket(rst, "TIGHTENED-RST");
                }
            }

        } finally {
            pkt.position(pkt.limit());
            if (latencyTracker != null) latencyTracker.end();
        }
    }

    // =========================================================================
    // Packet injection — thread-safe via TunChannel.write()
    // =========================================================================

    private void injectRawPacket(byte[] packetBytes, String reason) {
        TunChannel localTun = tun;
        if (localTun == null || !localTun.isOpen()) return;
        try {
            localTun.write(ByteBuffer.wrap(packetBytes));
        } catch (IOException e) {
            Log.e(TAG, "Packet inject error [" + reason + "]: " + e.getMessage());
        }
        String event = "[SENTINEL][" + reason + "] ts=" + System.currentTimeMillis();
        Log.d(TAG, event);
        if (logAnalyzer != null) logAnalyzer.injectFilteredEvent(event);
    }

    // =========================================================================
    // DNS NXDOMAIN packet builder
    // BUG FIX #4: возвращаем корректный DNS UDP пакет вместо HTTP-мусора
    //
    // Строим полный IPv4 + UDP + DNS ответ с RCODE=3 (NXDOMAIN)
    // =========================================================================

    private static byte[] buildDnsNxdomainPacket(ByteBuffer originalPkt) {
        try {
            int ipHdrLen  = PacketParser.ipHeaderLen(originalPkt);
            int udpOffset = ipHdrLen;

            // Исходный DNS payload
            int dnsOffset = udpOffset + 8;
            int dnsLen    = originalPkt.limit() - dnsOffset;
            if (dnsLen < 12) return null;

            // Читаем Transaction ID из DNS header
            int txId = ((originalPkt.get(dnsOffset) & 0xFF) << 8)
                     | (originalPkt.get(dnsOffset + 1) & 0xFF);

            // Копируем вопрос из оригинала (нужен для корректного ответа)
            byte[] dnsQuestion = new byte[dnsLen];
            for (int i = 0; i < dnsLen; i++) {
                dnsQuestion[i] = originalPkt.get(dnsOffset + i);
            }

            // Строим DNS ответ: тот же вопрос + flags=NXDOMAIN
            // DNS flags: QR=1(response), OPCODE=0, AA=0, TC=0, RD=1, RA=1, RCODE=3(NXDOMAIN)
            dnsQuestion[2] = (byte) 0x81; // flags high: QR=1, RD=1
            dnsQuestion[3] = (byte) 0x83; // flags low:  RA=1, RCODE=3 (NXDOMAIN)
            // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 уже 0 в скопированных данных обычно
            dnsQuestion[6] = 0; dnsQuestion[7] = 0; // ANCOUNT = 0
            dnsQuestion[8] = 0; dnsQuestion[9] = 0; // NSCOUNT = 0
            dnsQuestion[10]= 0; dnsQuestion[11]= 0; // ARCOUNT = 0

            // Адреса: меняем src/dst местами
            int srcIp = PacketParser.srcIp(originalPkt);
            int dstIp = PacketParser.dstIp(originalPkt);
            int srcPort = PacketParser.srcPort(originalPkt);
            int dstPort = PacketParser.dstPort(originalPkt);

            int udpPayloadLen = dnsQuestion.length;
            int udpTotalLen   = 8 + udpPayloadLen;
            int ipTotalLen    = 20 + udpTotalLen;

            byte[] pkt = new byte[ipTotalLen];

            // IPv4 header
            pkt[0]  = 0x45;                                    // version=4, IHL=5
            pkt[1]  = 0x00;                                    // DSCP/ECN
            pkt[2]  = (byte)(ipTotalLen >> 8);
            pkt[3]  = (byte)(ipTotalLen & 0xFF);
            pkt[4]  = 0x00; pkt[5] = 0x01;                    // ID
            pkt[6]  = 0x40; pkt[7] = 0x00;                    // Flags=DF, FragOffset=0
            pkt[8]  = 64;                                      // TTL
            pkt[9]  = 17;                                      // Protocol=UDP
            pkt[10] = 0x00; pkt[11] = 0x00;                   // checksum placeholder
            // src = original dst (DNS server), dst = original src (client)
            pkt[12] = (byte)(dstIp >> 24); pkt[13] = (byte)(dstIp >> 16);
            pkt[14] = (byte)(dstIp >> 8);  pkt[15] = (byte)(dstIp);
            pkt[16] = (byte)(srcIp >> 24); pkt[17] = (byte)(srcIp >> 16);
            pkt[18] = (byte)(srcIp >> 8);  pkt[19] = (byte)(srcIp);

            // IPv4 checksum
            int ipCsum = ipChecksum(pkt, 0, 20);
            pkt[10] = (byte)(ipCsum >> 8);
            pkt[11] = (byte)(ipCsum & 0xFF);

            // UDP header
            pkt[20] = (byte)(dstPort >> 8); pkt[21] = (byte)(dstPort & 0xFF); // src port = DNS(53)
            pkt[22] = (byte)(srcPort >> 8); pkt[23] = (byte)(srcPort & 0xFF); // dst port = client
            pkt[24] = (byte)(udpTotalLen >> 8);
            pkt[25] = (byte)(udpTotalLen & 0xFF);
            pkt[26] = 0x00; pkt[27] = 0x00; // UDP checksum (0 = disabled для UDP)

            // DNS payload
            System.arraycopy(dnsQuestion, 0, pkt, 28, dnsQuestion.length);

            return pkt;
        } catch (Exception e) {
            Log.e(TAG, "buildDnsNxdomainPacket error: " + e.getMessage());
            return null;
        }
    }

    // =========================================================================
    // TCP RST packet builder
    // BUG FIX #5: корректный TCP RST вместо HTTP-байт в TUN
    //
    // Строим IPv4 + TCP RST в ответ на входящий TCP пакет
    // =========================================================================

    private static byte[] buildTcpRstPacket(ByteBuffer originalPkt) {
        try {
            int ipHdrLen = PacketParser.ipHeaderLen(originalPkt);

            int srcIp   = PacketParser.srcIp(originalPkt);
            int dstIp   = PacketParser.dstIp(originalPkt);
            int srcPort = PacketParser.srcPort(originalPkt);
            int dstPort = PacketParser.dstPort(originalPkt);

            // Читаем SEQ из входящего пакета для правильного ACK
            long seqNum = 0;
            if (originalPkt.limit() >= ipHdrLen + 8) {
                seqNum = ((originalPkt.get(ipHdrLen + 4) & 0xFFL) << 24)
                       | ((originalPkt.get(ipHdrLen + 5) & 0xFFL) << 16)
                       | ((originalPkt.get(ipHdrLen + 6) & 0xFFL) << 8)
                       |  (originalPkt.get(ipHdrLen + 7) & 0xFFL);
            }

            // IP + TCP = 20 + 20 = 40 байт
            byte[] pkt = new byte[40];

            // IPv4 header (20 байт)
            pkt[0]  = 0x45;
            pkt[1]  = 0x00;
            pkt[2]  = 0x00; pkt[3] = 0x28; // total length = 40
            pkt[4]  = 0x00; pkt[5] = 0x01;
            pkt[6]  = 0x40; pkt[7] = 0x00; // DF flag
            pkt[8]  = 64;                   // TTL
            pkt[9]  = 6;                    // Protocol = TCP
            pkt[10] = 0x00; pkt[11] = 0x00; // checksum placeholder
            // RST идёт от dst к src (как будто сервер отвечает)
            pkt[12] = (byte)(dstIp >> 24); pkt[13] = (byte)(dstIp >> 16);
            pkt[14] = (byte)(dstIp >> 8);  pkt[15] = (byte)(dstIp);
            pkt[16] = (byte)(srcIp >> 24); pkt[17] = (byte)(srcIp >> 16);
            pkt[18] = (byte)(srcIp >> 8);  pkt[19] = (byte)(srcIp);

            int ipCsum = ipChecksum(pkt, 0, 20);
            pkt[10] = (byte)(ipCsum >> 8);
            pkt[11] = (byte)(ipCsum & 0xFF);

            // TCP header (20 байт, offset 20)
            pkt[20] = (byte)(dstPort >> 8); pkt[21] = (byte)(dstPort & 0xFF); // src port
            pkt[22] = (byte)(srcPort >> 8); pkt[23] = (byte)(srcPort & 0xFF); // dst port

            // SEQ = ACK из входящего пакета или 0
            long rstSeq = seqNum + 1;
            pkt[24] = (byte)(rstSeq >> 24); pkt[25] = (byte)(rstSeq >> 16);
            pkt[26] = (byte)(rstSeq >> 8);  pkt[27] = (byte)(rstSeq);

            // ACK number = 0
            pkt[28] = 0; pkt[29] = 0; pkt[30] = 0; pkt[31] = 0;

            pkt[32] = 0x50;        // data offset = 5 (20 bytes), reserved = 0
            pkt[33] = 0x04;        // flags: RST=1
            pkt[34] = 0x00; pkt[35] = 0x00; // window size = 0
            pkt[36] = 0x00; pkt[37] = 0x00; // checksum placeholder
            pkt[38] = 0x00; pkt[39] = 0x00; // urgent pointer

            // TCP checksum (pseudo-header + TCP header)
            int tcpCsum = tcpChecksum(pkt, 12, 16, 20, 20);
            pkt[36] = (byte)(tcpCsum >> 8);
            pkt[37] = (byte)(tcpCsum & 0xFF);

            return pkt;
        } catch (Exception e) {
            Log.e(TAG, "buildTcpRstPacket error: " + e.getMessage());
            return null;
        }
    }

    // =========================================================================
    // IP/TCP checksum helpers
    // =========================================================================

    private static int ipChecksum(byte[] buf, int offset, int len) {
        int sum = 0;
        for (int i = offset; i < offset + len - 1; i += 2) {
            sum += ((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF);
        }
        if ((len & 1) == 1) sum += (buf[offset + len - 1] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return ~sum & 0xFFFF;
    }

    /**
     * TCP checksum с pseudo-header.
     * @param pkt    полный пакет
     * @param srcOff offset src IP в pkt
     * @param dstOff offset dst IP в pkt
     * @param tcpOff offset TCP header в pkt
     * @param tcpLen длина TCP segment (header + data)
     */
    private static int tcpChecksum(byte[] pkt, int srcOff, int dstOff,
                                    int tcpOff, int tcpLen) {
        int sum = 0;
        // Pseudo-header: src IP
        sum += ((pkt[srcOff]     & 0xFF) << 8) | (pkt[srcOff + 1] & 0xFF);
        sum += ((pkt[srcOff + 2] & 0xFF) << 8) | (pkt[srcOff + 3] & 0xFF);
        // dst IP
        sum += ((pkt[dstOff]     & 0xFF) << 8) | (pkt[dstOff + 1] & 0xFF);
        sum += ((pkt[dstOff + 2] & 0xFF) << 8) | (pkt[dstOff + 3] & 0xFF);
        // Protocol + TCP length
        sum += 6; // TCP protocol
        sum += tcpLen;
        // TCP header + data
        for (int i = tcpOff; i < tcpOff + tcpLen - 1; i += 2) {
            sum += ((pkt[i] & 0xFF) << 8) | (pkt[i + 1] & 0xFF);
        }
        if ((tcpLen & 1) == 1) sum += (pkt[tcpOff + tcpLen - 1] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return ~sum & 0xFFFF;
    }

    // =========================================================================
    // Matching helpers
    // =========================================================================

    private boolean matchesPattern(String path) {
        if (path == null || path.isEmpty()) return false;
        for (Pattern p : URL_PATTERNS) {
            if (p.matcher(path).find()) return true;
        }
        return false;
    }

    private boolean isDomainBlocked(String host, boolean tightened) {
        String lower = host.toLowerCase();
        if (WHITELIST_DOMAINS.contains(lower)) return false;
        Set<String> blocked = BLOCKED_DOMAINS;
        if (blocked.contains(lower)) return true;
        for (String d : blocked) {
            if (lower.endsWith("." + d)) return true;
        }
        if (tightened) {
            for (String kw : new String[]{"ads", "analytics", "track", "beacon"}) {
                if (lower.contains(kw)) return true;
            }
        }
        return false;
    }

    private boolean isWhitelistedIp(String ip) {
        for (String prefix : WHITELIST_PREFIXES) {
            if (ip.startsWith(prefix)) return true;
        }
        return false;
    }

    private boolean hasTightenedSignal(String payload) {
        if (payload == null) return false;
        String lower = payload.toLowerCase();
        for (String sig : new String[]{"/ads/", "analytics", "track", "beacon", "/verify", "reward"}) {
            if (lower.contains(sig)) return true;
        }
        return false;
    }

    // =========================================================================
    // HTTP parsing helpers
    // =========================================================================

    private static String firstLine(String payload) {
        int nl = payload.indexOf('\n');
        return (nl > 0 ? payload.substring(0, nl) : payload).trim();
    }

    private static String extractPath(String requestLine) {
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 2) return "";
        String u = parts[1];
        int q = u.indexOf('?');
        return q > 0 ? u.substring(0, q) : u;
    }

    private static String extractHostHeader(String payload) {
        int idx = payload.toLowerCase().indexOf("host:");
        if (idx < 0) return null;
        int s = idx + 5;
        int e = payload.indexOf('\n', s);
        return payload.substring(s, e < 0 ? payload.length() : e).trim().toLowerCase();
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    private static String intToIp(int ip) {
        // FIX: используем & 0xFF для всех байт, включая старший
        return ((ip >>> 24) & 0xFF) + "." + ((ip >>> 16) & 0xFF) + "."
             + ((ip >>>  8) & 0xFF) + "." + (ip & 0xFF);
    }

    private void purgeTightenedUids() {
        long now = System.currentTimeMillis();
        tightenedUids.entrySet().removeIf(e -> e.getValue() < now);
    }

    // =========================================================================
    // Foreground notification
    // =========================================================================

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    NOTIF_CHANNEL_ID, "Network Filter",
                    NotificationManager.IMPORTANCE_MIN);
            ch.setShowBadge(false);
            ch.setSound(null, null);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    @SuppressWarnings("deprecation")
    private Notification buildNotification() {
        Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, NOTIF_CHANNEL_ID)
                : new Notification.Builder(this).setPriority(Notification.PRIORITY_MIN);
        return b.setContentTitle("Network Protection")
                .setContentText("Active")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .build();
    }
}

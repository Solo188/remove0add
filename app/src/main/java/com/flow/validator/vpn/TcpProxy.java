package com.flow.validator.vpn;

import android.util.Log;

import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * TcpProxy — перенаправляет TCP пакеты на порт 443 в локальный MitmProxy.
 *
 * ПРОБЛЕМА которую решает этот класс:
 * MitmProxy слушает на 127.0.0.1:8443. Трафик от приложений идёт на реальные
 * серверы (port 443). Чтобы MITM работал, нужно изменить dst IP+port в IPv4/TCP
 * пакете и вернуть его в TUN. Ядро Android увидит пакет адресованный 127.0.0.1:8443
 * и доставит его в наш MitmProxy.
 *
 * Также нужно сохранить оригинальный dst для того чтобы MitmProxy знал
 * к какому серверу подключаться upstream. Для этого используем ConnTrack.
 *
 * ВАЖНО: Для корректной работы full MITM нужен полный TCP state machine
 * (SYN/SYN-ACK/ACK handshake rewrite). Данный класс реализует базовый
 * redirect для SYN пакетов.
 */
public final class TcpProxy {

    private static final String TAG = "TcpProxy";

    private TcpProxy() {}

    /**
     * Переписывает dst IP и dst port в TCP/IP пакете для редиректа в MitmProxy.
     *
     * @param originalPkt  входящий пакет (SYN на порт 443)
     * @param mitmHost     адрес MitmProxy (127.0.0.1)
     * @param mitmPort     порт MitmProxy (8443)
     * @return             модифицированный пакет для записи в TUN, или null при ошибке
     */
    public static byte[] redirectToMitm(ByteBuffer originalPkt,
                                         String mitmHost, int mitmPort) {
        try {
            int ipHdrLen = PacketParser.ipHeaderLen(originalPkt);
            int totalLen = PacketParser.ipTotalLen(originalPkt);

            if (totalLen > originalPkt.limit()) totalLen = originalPkt.limit();

            byte[] pkt = new byte[totalLen];
            for (int i = 0; i < totalLen; i++) {
                pkt[i] = originalPkt.get(i);
            }

            // Сохраняем оригинальный dst IP для ConnTrack
            int origDstIp   = PacketParser.dstIp(originalPkt);
            int origDstPort = PacketParser.dstPort(originalPkt);
            int srcIp       = PacketParser.srcIp(originalPkt);
            int srcPort     = PacketParser.srcPort(originalPkt);

            ConnTrack.put(srcIp, srcPort, origDstIp, origDstPort);

            // Записываем новый dst IP = 127.0.0.1
            byte[] mitmAddr = InetAddress.getByName(mitmHost).getAddress();
            pkt[16] = mitmAddr[0];
            pkt[17] = mitmAddr[1];
            pkt[18] = mitmAddr[2];
            pkt[19] = mitmAddr[3];

            // Записываем новый dst port
            pkt[ipHdrLen + 2] = (byte)(mitmPort >> 8);
            pkt[ipHdrLen + 3] = (byte)(mitmPort & 0xFF);

            // Сбрасываем IP checksum
            pkt[10] = 0; pkt[11] = 0;
            int ipCsum = ipChecksum(pkt, 0, ipHdrLen);
            pkt[10] = (byte)(ipCsum >> 8);
            pkt[11] = (byte)(ipCsum & 0xFF);

            // Сбрасываем TCP checksum
            int tcpLen = totalLen - ipHdrLen;
            pkt[ipHdrLen + 16] = 0; pkt[ipHdrLen + 17] = 0;
            int tcpCsum = tcpChecksumFull(pkt, 12, 16, ipHdrLen, tcpLen);
            pkt[ipHdrLen + 16] = (byte)(tcpCsum >> 8);
            pkt[ipHdrLen + 17] = (byte)(tcpCsum & 0xFF);

            return pkt;
        } catch (Exception e) {
            Log.e(TAG, "redirectToMitm error: " + e.getMessage());
            return null;
        }
    }

    // =========================================================================
    // IP/TCP checksum
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

    private static int tcpChecksumFull(byte[] pkt, int srcOff, int dstOff,
                                        int tcpOff, int tcpLen) {
        int sum = 0;
        sum += ((pkt[srcOff]     & 0xFF) << 8) | (pkt[srcOff + 1] & 0xFF);
        sum += ((pkt[srcOff + 2] & 0xFF) << 8) | (pkt[srcOff + 3] & 0xFF);
        sum += ((pkt[dstOff]     & 0xFF) << 8) | (pkt[dstOff + 1] & 0xFF);
        sum += ((pkt[dstOff + 2] & 0xFF) << 8) | (pkt[dstOff + 3] & 0xFF);
        sum += 6;
        sum += tcpLen;
        for (int i = tcpOff; i < tcpOff + tcpLen - 1; i += 2) {
            sum += ((pkt[i] & 0xFF) << 8) | (pkt[i + 1] & 0xFF);
        }
        if ((tcpLen & 1) == 1) sum += (pkt[tcpOff + tcpLen - 1] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return ~sum & 0xFFFF;
    }
}

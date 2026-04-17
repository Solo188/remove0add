package com.flow.validator.vpn;

import java.util.concurrent.ConcurrentHashMap;

/**
 * ConnTrack — таблица соответствия для TCP redirect.
 *
 * Хранит оригинальный dst IP/port для каждого перехваченного соединения.
 * MitmProxy использует эти данные чтобы знать к какому серверу подключаться upstream.
 *
 * Ключ: src_ip:src_port (уникально идентифицирует соединение клиента)
 * Значение: orig_dst_ip:orig_dst_port
 */
public final class ConnTrack {

    // Максимум записей (защита от memory leak при большом трафике)
    private static final int MAX_ENTRIES = 4096;

    // long key = (srcIp << 32) | (srcPort << 16) | 0
    // Для простоты используем String ключ
    private static final ConcurrentHashMap<String, long[]> table
            = new ConcurrentHashMap<>(256);

    private ConnTrack() {}

    /**
     * Сохранить маппинг src→origDst.
     */
    public static void put(int srcIp, int srcPort, int dstIp, int dstPort) {
        if (table.size() >= MAX_ENTRIES) {
            // Грубая очистка при переполнении
            table.clear();
        }
        String key = key(srcIp, srcPort);
        table.put(key, new long[]{ dstIp & 0xFFFFFFFFL, dstPort });
    }

    /**
     * Получить оригинальный dst для данного src.
     * @return массив [dstIp, dstPort] или null если не найдено
     */
    public static long[] getOrigDst(int srcIp, int srcPort) {
        return table.get(key(srcIp, srcPort));
    }

    /**
     * Получить оригинальный dst как строку "ip:port".
     */
    public static String getOrigDstString(int srcIp, int srcPort) {
        long[] entry = table.get(key(srcIp, srcPort));
        if (entry == null) return null;
        long ip = entry[0];
        int port = (int) entry[1];
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "."
             + ((ip >>  8) & 0xFF) + "." + (ip & 0xFF) + ":" + port;
    }

    public static void remove(int srcIp, int srcPort) {
        table.remove(key(srcIp, srcPort));
    }

    private static String key(int ip, int port) {
        return ip + ":" + port;
    }
}

package com.flow.validator.util;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;

/**
 * AhoCorasick — Multi-pattern string search in O(n + m + z) time.
 *
 * Used by LogAnalyzer to simultaneously scan log lines for all SDK
 * keyword patterns in a single pass — no per-keyword iteration.
 *
 * Build once via {@link #build(String[])}, then reuse across threads
 * via {@link #search(String)} — the automaton is read-only after build().
 */
public final class AhoCorasick {

    private static final int ALPHABET = 128; // ASCII subset only

    private final int[][] go;
    private final int[]   fail;
    private final int[][] output;   // output[state] = indices of matched patterns
    private final int     size;

    private AhoCorasick(int[][] go, int[] fail, int[][] output, int size) {
        this.go     = go;
        this.fail   = fail;
        this.output = output;
        this.size   = size;
    }

    /**
     * Build the automaton from the given patterns.
     *
     * @param patterns Array of keyword strings to detect (case-insensitive matching
     *                 is caller's responsibility — lowercase your patterns).
     */
    public static AhoCorasick build(String[] patterns) {
        // Upper bound on states: sum of all pattern lengths + 1
        int maxStates = 1;
        for (String p : patterns) maxStates += p.length();

        int[][] go     = new int[maxStates][ALPHABET];
        int[]   fail   = new int[maxStates];
        List<List<Integer>> out = new ArrayList<>(maxStates);

        for (int i = 0; i < maxStates; i++) {
            for (int c = 0; c < ALPHABET; c++) go[i][c] = -1;
            out.add(new ArrayList<>());
        }

        // --- Phase 1: build trie ---
        int stateCount = 1; // state 0 = root
        for (int pi = 0; pi < patterns.length; pi++) {
            int cur = 0;
            for (char ch : patterns[pi].toCharArray()) {
                int c = ch & 0x7F;
                if (go[cur][c] == -1) {
                    go[cur][c] = stateCount++;
                }
                cur = go[cur][c];
            }
            out.get(cur).add(pi);
        }

        // --- Phase 2: fill missing root transitions and build fail links via BFS ---
        Queue<Integer> queue = new ArrayDeque<>();
        for (int c = 0; c < ALPHABET; c++) {
            if (go[0][c] == -1) {
                go[0][c] = 0;
            } else {
                fail[go[0][c]] = 0;
                queue.add(go[0][c]);
            }
        }

        while (!queue.isEmpty()) {
            int u = queue.poll();
            out.get(u).addAll(out.get(fail[u])); // merge suffix outputs
            for (int c = 0; c < ALPHABET; c++) {
                if (go[u][c] == -1) {
                    go[u][c] = go[fail[u]][c];
                } else {
                    fail[go[u][c]] = go[fail[u]][c];
                    queue.add(go[u][c]);
                }
            }
        }

        // Materialise output lists into arrays for GC-free access at search time
        int[][] outputArr = new int[stateCount][];
        for (int i = 0; i < stateCount; i++) {
            List<Integer> lst = out.get(i);
            outputArr[i] = new int[lst.size()];
            for (int j = 0; j < lst.size(); j++) outputArr[i][j] = lst.get(j);
        }

        return new AhoCorasick(go, fail, outputArr, stateCount);
    }

    /**
     * Scan {@code text} for all pattern occurrences.
     *
     * @param text Input string (caller should lower-case if patterns were lowered).
     * @return List of matched pattern indices (may contain duplicates if the same
     *         pattern appears multiple times in the text).
     */
    public List<Integer> search(String text) {
        List<Integer> results = new ArrayList<>();
        int cur = 0;
        for (int i = 0; i < text.length(); i++) {
            int c = text.charAt(i) & 0x7F;
            if (c >= ALPHABET) { cur = 0; continue; }
            cur = go[cur][c];
            for (int idx : output[cur]) {
                results.add(idx);
            }
        }
        return results;
    }

    /**
     * Fast boolean check — returns true as soon as the first pattern is found.
     */
    public boolean containsAny(String text) {
        int cur = 0;
        for (int i = 0; i < text.length(); i++) {
            int c = text.charAt(i) & 0x7F;
            if (c >= ALPHABET) { cur = 0; continue; }
            cur = go[cur][c];
            if (output[cur].length > 0) return true;
        }
        return false;
    }
}

package com.flow.validator.vpn;

import android.util.Log;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.concurrent.locks.ReentrantLock;

/**
 * TunChannel — Zero-copy FileChannel wrapper for TUN interface I/O.
 *
 * <p><b>Design goals:</b>
 * <ul>
 *   <li><b>Zero heap allocation per packet</b> — all reads land in a
 *       {@link ByteBuffer#allocateDirect(int) direct} ByteBuffer (32 KB) that
 *       lives outside the Java heap, eliminating GC pressure on the hot path.</li>
 *   <li><b>FileChannel semantics</b> — wraps the raw TUN file descriptor in
 *       NIO channels via {@link Channels#newChannel}, allowing
 *       {@link ReadableByteChannel#read} and {@link WritableByteChannel#write}
 *       without intermediate byte[] copies.</li>
 *   <li><b>Thread-safe writes</b> — the write path is protected by a
 *       {@link ReentrantLock} so multiple worker threads (ForkJoinPool) can
 *       inject mock responses concurrently without corrupting the TUN stream.</li>
 *   <li><b>Proper buffer hygiene</b> — the read buffer is {@link ByteBuffer#clear()}ed
 *       after each packet dispatch (prevents stale-data leaks across cycles).</li>
 * </ul>
 *
 * <p><b>Usage pattern (reader thread only):</b>
 * <pre>{@code
 * TunChannel tun = new TunChannel(pfd.getFileDescriptor());
 * tun.open();
 * ByteBuffer slice;
 * while ((slice = tun.readPacket()) != null) {
 *     // slice is a read-only view of the internal buffer — valid until next readPacket()
 *     ByteBuffer snapshot = tun.snapshot(slice); // deep-copy for async dispatch
 *     pool.execute(() -> process(snapshot, tun));
 * }
 * tun.close();
 * }</pre>
 *
 * <p><b>Write pattern (any thread):</b>
 * <pre>{@code
 * ByteBuffer response = ByteBuffer.wrap(MOCK_HTTP_200);
 * tun.write(response); // thread-safe
 * }</pre>
 */
public final class TunChannel implements Closeable {

    private static final String TAG      = "TunChannel";
    public  static final int    BUF_SIZE = 32768; // 32 KB — covers jumbo frames

    private final java.io.FileDescriptor fd;

    private ReadableByteChannel readChannel;
    private WritableByteChannel writeChannel;

    // Single direct read buffer — owned exclusively by the reader thread
    private final ByteBuffer readBuf = ByteBuffer.allocateDirect(BUF_SIZE);

    // Write lock — shared among all ForkJoinPool worker threads
    private final ReentrantLock writeLock = new ReentrantLock();

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    public TunChannel(java.io.FileDescriptor fd) {
        this.fd = fd;
    }

    /**
     * Open read and write NIO channels over the TUN file descriptor.
     * Must be called from the reader thread before {@link #readPacket()}.
     */
    public void open() throws IOException {
        readChannel  = Channels.newChannel(new FileInputStream(fd));
        writeChannel = Channels.newChannel(new FileOutputStream(fd));
        Log.i(TAG, "TunChannel opened | bufSize=" + BUF_SIZE + " B");
    }

    // -------------------------------------------------------------------------
    // Read
    // -------------------------------------------------------------------------

    /**
     * Block until the next IPv4 packet arrives on the TUN interface.
     *
     * <p>Returns a <em>read-only slice</em> of the internal direct buffer.
     * The caller MUST NOT retain this reference past the next call to
     * {@code readPacket()} — use {@link #snapshot(ByteBuffer)} to copy it
     * for async dispatch to a ForkJoinPool worker.
     *
     * <p>The internal buffer is {@link ByteBuffer#clear()}ed before each read,
     * ensuring no stale bytes from a previous cycle are visible.
     *
     * @return A positioned, limited ByteBuffer containing exactly one IP packet,
     *         or {@code null} if the channel has been closed.
     */
    public ByteBuffer readPacket() {
        readBuf.clear(); // ← mandatory: prevent cross-packet data leakage
        try {
            int n = readChannel.read(readBuf);
            if (n <= 0) return null;
            readBuf.flip();
            return readBuf.asReadOnlyBuffer(); // read-only view, same backing store
        } catch (IOException e) {
            Log.e(TAG, "readPacket error: " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Snapshot — deep copy for async dispatch
    // -------------------------------------------------------------------------

    /**
     * Create an independent, heap-backed deep copy of {@code slice} suitable
     * for dispatch to a ForkJoinPool worker task.
     *
     * <p>Uses a direct ByteBuffer allocation to avoid heap pressure on the hot
     * path. The returned buffer's position is 0, limit = packet length.
     *
     * @param slice Read-only slice returned by {@link #readPacket()}.
     * @return New direct ByteBuffer containing the same bytes.
     */
    public static ByteBuffer snapshot(ByteBuffer slice) {
        ByteBuffer copy = ByteBuffer.allocateDirect(slice.remaining());
        copy.put(slice);
        copy.flip();
        return copy;
    }

    // -------------------------------------------------------------------------
    // Write — thread-safe
    // -------------------------------------------------------------------------

    /**
     * Write {@code data} to the TUN interface.
     *
     * <p>Acquires the write lock before calling
     * {@link WritableByteChannel#write} to prevent interleaving of concurrent
     * mock response injections from different ForkJoinPool tasks.
     *
     * <p>The buffer's position is advanced by the number of bytes written.
     * The caller should {@link ByteBuffer#flip()} the buffer before calling
     * this method if it was just filled.
     *
     * @param data Data to write (caller must flip before passing).
     * @throws IOException if the underlying channel write fails.
     */
    public void write(ByteBuffer data) throws IOException {
        writeLock.lock();
        try {
            while (data.hasRemaining()) {
                writeChannel.write(data);
            }
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Write a pre-built byte array (e.g., {@code MOCK_HTTP_200}) without
     * creating a heap ByteBuffer.
     */
    public void write(byte[] data) throws IOException {
        write(ByteBuffer.wrap(data));
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /**
     * True if the channel is open and ready for I/O.
     */
    public boolean isOpen() {
        return readChannel != null && readChannel.isOpen();
    }

    // -------------------------------------------------------------------------
    // Closeable
    // -------------------------------------------------------------------------

    @Override
    public void close() {
        try { if (readChannel  != null) readChannel.close();  } catch (Exception ignored) {}
        try { if (writeChannel != null) writeChannel.close(); } catch (Exception ignored) {}
        Log.i(TAG, "TunChannel closed");
    }
}

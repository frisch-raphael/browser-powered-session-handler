package lab.auth;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;

/** Counts actual bytes before HTTP parsing. TLS handshakes are not application ingress. */
public final class IngressSentinel implements AutoCloseable {
    public record Snapshot(long connections, long tlsHandshakes, long applicationBytes) {}
    private final ServerSocket listener;
    private final Set<Socket> sockets = Collections.synchronizedSet(new HashSet<>());
    private final ExecutorService tasks = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicLong connections = new AtomicLong(), handshakes = new AtomicLong(), bytes = new AtomicLong();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Object changed = new Object();
    private volatile Thread acceptThread;
    public IngressSentinel(SSLContext tls) throws IOException {
        listener = tls == null ? new ServerSocket() : tls.getServerSocketFactory().createServerSocket();
        listener.bind(new InetSocketAddress("127.0.0.1", 0)); tasks.submit(this::accept);
    }
    public InetSocketAddress address() { return new InetSocketAddress("127.0.0.1", listener.getLocalPort()); }
    public Snapshot snapshot() { return new Snapshot(connections.get(), handshakes.get(), bytes.get()); }
    private void accept() {
        acceptThread = Thread.currentThread();
        while (!closed.get()) {
            try {
                Socket socket = listener.accept();
                synchronized (sockets) { if (closed.get()) { socket.close(); return; } sockets.add(socket); }
                connections.incrementAndGet(); signal();
                tasks.submit(() -> read(socket));
            } catch (IOException | RejectedExecutionException ex) { if (!closed.get()) close(); return; }
        }
    }
    private void read(Socket socket) {
        try (socket) {
            socket.setSoTimeout(2000);
            if (socket instanceof SSLSocket tls) { tls.startHandshake(); handshakes.incrementAndGet(); signal(); }
            byte[] buffer = new byte[8192];
            int count;
            while ((count = socket.getInputStream().read(buffer)) != -1) { bytes.addAndGet(count); signal(); }
        } catch (IOException ignored) { /* Only observed decrypted application bytes count. */ }
        finally { sockets.remove(socket); signal(); }
    }
    private void signal() { synchronized (changed) { changed.notifyAll(); } }
    public Snapshot await(java.util.function.Predicate<Snapshot> observation, java.time.Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        synchronized (changed) {
            while (!observation.test(snapshot())) {
                long remaining = deadline - System.nanoTime(); if (remaining <= 0) throw new IllegalStateException("Sentinel observation deadline.");
                TimeUnit.NANOSECONDS.timedWait(changed, remaining);
            }
            return snapshot();
        }
    }
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        try { listener.close(); } catch (IOException ignored) { }
        synchronized (sockets) { for (var socket : sockets) try { socket.close(); } catch (IOException ignored) { } }
        tasks.shutdownNow(); signal();
        if (Thread.currentThread() != acceptThread) try {
            if (!tasks.awaitTermination(3, TimeUnit.SECONDS)) throw new IllegalStateException("Sentinel cleanup incomplete.");
        } catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException("Sentinel cleanup interrupted."); }
    }
}

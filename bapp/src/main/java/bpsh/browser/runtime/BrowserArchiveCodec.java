package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Objects;
import org.tukaani.xz.MemoryLimitException;
import org.tukaani.xz.XZIOException;
import org.tukaani.xz.XZInputStream;
import static bpsh.browser.runtime.BrowserManifestCodec.*;

/** Streams one authenticated XZ resource to a bounded ZIP; owns input, never output or cache paths. */
final class BrowserArchiveCodec {
    private static final int DECODER_MEMORY_KIB = 128 * 1024;
    private static final int BUFFER_BYTES = 65536;
    private static final long ARCHIVE_CEILING = 2L << 30;

    private BrowserArchiveCodec() {}

    /** Preserves the runtime owner's original cancellation, shutdown and deadline checks. */
    @FunctionalInterface interface Checkpoint {
        /** @throws AuthenticationFailure If the original attempt is no longer active. */
        void check() throws AuthenticationFailure;
    }

    /**
     * Verifies an archive in the build's isolated classloader without a runtime attempt.
     * @param source Compressed resource; ownership transfers even if decoder construction fails.
     * @param output Caller-owned sink, which is neither closed nor flushed here.
     * @param compressedBytes Exact bounded compressed length.
     * @param compressedHash Exact lowercase compressed SHA-256.
     * @param expandedBytes Exact bounded ZIP length.
     * @throws IOException On invalid data, bounds, integrity, decoder memory or unrelated I/O failure.
     * @throws AuthenticationFailure If the supplied attempt checkpoint fails.
     */
    static void decode(InputStream source, OutputStream output, long compressedBytes, String compressedHash,
                       long expandedBytes) throws IOException, AuthenticationFailure {
        decode(source, output, compressedBytes, compressedHash, expandedBytes, () -> {});
    }

    /**
     * Reads through decoder EOF so checks, footers, concatenation and trailing input are verified.
     * @param source Compressed resource; ownership transfers even if decoder construction fails.
     * @param output Caller-owned sink, which is neither closed nor flushed here.
     * @param compressedBytes Exact bounded compressed length.
     * @param compressedHash Exact lowercase compressed SHA-256.
     * @param expandedBytes Exact bounded ZIP length; no excess byte reaches the sink.
     * @param checkpoint Original attempt check, run before every source read and between writes.
     * @throws IOException On invalid data, bounds, integrity, decoder memory or unrelated I/O failure.
     * @throws AuthenticationFailure If the original attempt is cancelled, closed or expired.
     */
    static void decode(InputStream source, OutputStream output, long compressedBytes, String compressedHash,
                       long expandedBytes, Checkpoint checkpoint) throws IOException, AuthenticationFailure {
        var compressed = new CompressedInput(source, compressedBytes, compressedHash, checkpoint);
        try (XZInputStream decoded = openDecoder(compressed, expandedBytes)) {
            byte[] buffer = new byte[BUFFER_BYTES]; long expanded = 0;
            while (true) {
                checkpoint.check();
                int count = decoded.read(buffer, 0, (int) Math.min(buffer.length, expandedBytes - expanded + 1));
                checkpoint.check();
                if (count < 0) break;
                require(count <= expandedBytes - expanded, "Decoded ZIP exceeds its declared size.");
                output.write(buffer, 0, count); expanded += count;
            }
            require(expanded == expandedBytes, "Decoded ZIP size mismatch.");
            compressed.verify();
        } catch (CheckpointFailure failure) {
            throw failure.outcome;
        } catch (MemoryLimitException failure) {
            throw new InvalidAsset("Browser archive exceeds the decoder memory ceiling.");
        } catch (XZIOException | EOFException failure) {
            throw new InvalidAsset("Invalid or incomplete XZ browser archive.");
        }
    }

    /**
     * Transfers source ownership to the decoder, closing it exactly once on constructor failure.
     * @param source Bounded compressed resource wrapper.
     * @param expandedBytes Approved positive expanded length.
     * @return Owning streaming decoder with integrity verification enabled.
     * @throws IOException If declarations, header, checkpoint or source reading fail.
     */
    private static XZInputStream openDecoder(CompressedInput source, long expandedBytes) throws IOException {
        try {
            require(source.expected > 0 && source.expected <= ARCHIVE_CEILING
                    && expandedBytes > 0 && expandedBytes <= ARCHIVE_CEILING, "Invalid browser archive byte bounds.");
            hashText(source.expectedHash);
            return new XZInputStream(source, DECODER_MEMORY_KIB);
        } catch (IOException | RuntimeException | Error failure) {
            try { source.close(); } catch (IOException closeFailure) { failure.addSuppressed(closeFailure); }
            throw failure;
        }
    }

    /** Bridges a checked attempt outcome through InputStream without losing its typed reason. */
    private static final class CheckpointFailure extends IOException {
        private static final long serialVersionUID = 1L;
        private final AuthenticationFailure outcome;
        /** @param outcome Safe original attempt outcome. */
        private CheckpointFailure(AuthenticationFailure outcome) { this.outcome = outcome; }
    }

    /** Delivers no more than declared input; a single extra read proves actual resource EOF. */
    private static final class CompressedInput extends InputStream {
        private final InputStream source;
        private final long expected;
        private final String expectedHash;
        private final Checkpoint checkpoint;
        private final MessageDigest digest = sha();
        private final byte[] single = new byte[1];
        private long bytes;
        private boolean eof;

        /** @param source Owned input. @param expected Exact size. @param expectedHash Exact hash. @param checkpoint Attempt check. */
        private CompressedInput(InputStream source, long expected, String expectedHash, Checkpoint checkpoint) {
            this.source = source; this.expected = expected; this.expectedHash = expectedHash; this.checkpoint = checkpoint;
        }

        /** @return One unsigned byte, or EOF. @throws IOException On bound, checkpoint or source failure. */
        @Override public int read() throws IOException {
            int count = read(single, 0, 1); return count < 0 ? -1 : Byte.toUnsignedInt(single[0]);
        }

        /** @param buffer Destination. @param offset Offset. @param length Maximum count. @return Bounded count or EOF. @throws IOException On invalid input or I/O. */
        @Override public int read(byte[] buffer, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, buffer.length);
            if (length == 0) return 0;
            try { checkpoint.check(); } catch (AuthenticationFailure failure) { throw new CheckpointFailure(failure); }
            if (eof) return -1;
            if (bytes == expected) {
                require(source.read() == -1, "Compressed archive exceeds its declared size."); eof = true; return -1;
            }
            int count = source.read(buffer, offset, (int) Math.min(Math.min(length, BUFFER_BYTES), expected - bytes));
            if (count > 0) { digest.update(buffer, offset, count); bytes += count; }
            return count;
        }

        /** @throws IOException If exact length, resource EOF or compressed SHA-256 do not match. */
        private void verify() throws IOException {
            require(bytes == expected, "Compressed archive size mismatch.");
            require(read() == -1 && hex(digest.digest()).equals(expectedHash), "Compressed archive digest/EOF mismatch.");
        }

        /** @throws IOException If closing the sole owned resource fails. */
        @Override public void close() throws IOException { source.close(); }
    }
}

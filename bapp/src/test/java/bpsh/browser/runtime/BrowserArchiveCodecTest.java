package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZOutputStream;
import static org.junit.jupiter.api.Assertions.*;

/** Checks untrusted compressed input, byte ceilings, bounded streaming and exact stream ownership. */
class BrowserArchiveCodecTest {
    private static final byte[] DATA = "small ZIP stand-in".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    static byte[] encode(byte[] data) throws IOException {
        var bytes = new ByteArrayOutputStream();
        var options = new LZMA2Options(0); options.setDictSize(4096);
        try (var out = new XZOutputStream(bytes, options)) { out.write(data); }
        return bytes.toByteArray();
    }

    private static void decode(TrackedInput input, OutputStream out, long bytes, String hash, long expanded,
                               BrowserArchiveCodec.Checkpoint checkpoint) throws Exception {
        BrowserArchiveCodec.decode(input, out, bytes, hash, expanded, checkpoint);
    }

    @Test void exactBoundsStreamToCallerOwnedOutputAndCloseSourceOnce() throws Exception {
        byte[] data = new byte[2 * 1024 * 1024 + 17];
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i * 31);
        byte[] archive = encode(data); var input = new TrackedInput(archive); var output = new TrackedOutput();
        decode(input, output, archive.length, BrowserAssetsTest.sha(archive), data.length, () -> {});
        assertArrayEquals(data, output.toByteArray()); assertEquals(1, input.closes);
        assertFalse(output.closed); assertTrue(output.maxWrite <= 65536); assertTrue(input.maxRead <= 65536);
        assertEquals(archive.length, input.consumed);
    }

    @Test void badHeaderAndTruncatedHeaderCloseSourceOnceEvenWhenConstructorFails() throws Exception {
        for (byte[] archive : new byte[][] {new byte[0], new byte[] {1, 2, 3}, new byte[24]}) {
            var input = new TrackedInput(archive);
            assertThrows(InvalidAsset.class, () -> decode(input, OutputStream.nullOutputStream(),
                    Math.max(1, archive.length), BrowserAssetsTest.sha(archive), DATA.length, () -> {}));
            assertEquals(1, input.closes);
        }
    }

    @Test void corruptChecksFootersAndTruncatedBodiesFailBeforeSuccessfulReturn() throws Exception {
        byte[] valid = encode(DATA);
        for (int index : new int[] {16, valid.length / 2, valid.length - 8, valid.length - 1}) {
            byte[] bad = valid.clone(); bad[index] ^= 1; assertInvalid(bad, bad.length, BrowserAssetsTest.sha(bad), DATA.length);
        }
        for (int length : new int[] {12, 20, valid.length - 1, valid.length - 12}) {
            byte[] shortInput = Arrays.copyOf(valid, length);
            assertInvalid(shortInput, shortInput.length, BrowserAssetsTest.sha(shortInput), DATA.length);
        }
    }

    @Test void compressedLengthHashAndTrailingInputAreAllEnforced() throws Exception {
        byte[] valid = encode(DATA);
        assertInvalid(valid, valid.length - 1, BrowserAssetsTest.sha(valid), DATA.length);
        assertInvalid(valid, valid.length + 1, BrowserAssetsTest.sha(valid), DATA.length);
        assertInvalid(valid, valid.length, "0".repeat(64), DATA.length);
        byte[] extra = Arrays.copyOf(valid, valid.length + 4); extra[valid.length] = 1;
        assertInvalid(extra, extra.length, BrowserAssetsTest.sha(extra), DATA.length);
        var input = new TrackedInput(extra);
        assertThrows(InvalidAsset.class, () -> decode(input, OutputStream.nullOutputStream(),
                valid.length, BrowserAssetsTest.sha(valid), DATA.length, () -> {}));
        assertTrue(input.consumed <= valid.length + 1, "only an EOF sentinel may cross the compressed bound");
        assertEquals(1, input.closes);
    }

    @Test void expansionOverflowNeverWritesTheFirstExcessByteAndUnderflowFails() throws Exception {
        byte[] valid = encode(DATA); var output = new TrackedOutput(); var input = new TrackedInput(valid);
        assertThrows(InvalidAsset.class, () -> decode(input, output, valid.length,
                BrowserAssetsTest.sha(valid), DATA.length - 1, () -> {}));
        assertTrue(output.size() <= DATA.length - 1); assertEquals(1, input.closes);
        assertInvalid(valid, valid.length, BrowserAssetsTest.sha(valid), DATA.length + 1);
    }

    @Test void concatenatedStreamsMustSatisfyCombinedInputAndOutputBounds() throws Exception {
        byte[] first = encode(DATA); var joined = new ByteArrayOutputStream(); joined.write(first); joined.write(first);
        byte[] archive = joined.toByteArray(); var input = new TrackedInput(archive); var output = new TrackedOutput();
        decode(input, output, archive.length, BrowserAssetsTest.sha(archive), DATA.length * 2, () -> {});
        var expected = new ByteArrayOutputStream(); expected.write(DATA); expected.write(DATA);
        assertArrayEquals(expected.toByteArray(), output.toByteArray()); assertEquals(1, input.closes);
        assertInvalid(archive, archive.length, BrowserAssetsTest.sha(archive), DATA.length);
    }

    @Test void dictionaryHeaderExceeding128MiBFailsBeforeOutputOrDictionaryAllocation() throws Exception {
        byte[] archive = encode(DATA);
        int headerBytes = (Byte.toUnsignedInt(archive[12]) + 1) * 4;
        assertEquals(0x21, Byte.toUnsignedInt(archive[14])); assertEquals(1, archive[15]);
        archive[16] = 32; // 256 MiB dictionary advertised by LZMA2, without constructing a large encoder.
        var crc = new CRC32(); crc.update(archive, 12, headerBytes - 4);
        ByteBuffer.wrap(archive, 12 + headerBytes - 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt((int) crc.getValue());
        var input = new TrackedInput(archive); var output = new TrackedOutput();
        var error = assertThrows(InvalidAsset.class, () -> decode(input, output, archive.length,
                BrowserAssetsTest.sha(archive), DATA.length, () -> {}));
        assertTrue(error.getMessage().contains("memory")); assertEquals(0, output.size());
        assertTrue(input.consumed <= 12 + headerBytes); assertEquals(1, input.closes);
    }

    @Test void cancellationBetweenUnderlyingReadsPreservesTypedOutcomeAndClosesSource() throws Exception {
        byte[] archive = encode(DATA); var input = new TrackedInput(archive); input.chunk = 1;
        var cancelled = new AtomicBoolean(); input.afterRead = () -> { if (input.consumed >= 16) cancelled.set(true); };
        var error = assertThrows(AuthenticationFailure.class, () -> decode(input, OutputStream.nullOutputStream(),
                archive.length, BrowserAssetsTest.sha(archive), DATA.length,
                () -> AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, Long.MAX_VALUE, cancelled::get)));
        assertEquals(AuthenticationFailure.Cause.CANCELLED, error.reason()); assertEquals(16, input.consumed);
        assertEquals(1, input.closes);
    }

    @Test void originalDeadlineAndCancellationAreCheckedBetweenExpandedWrites() throws Exception {
        byte[] data = new byte[131073], archive = encode(data); var output = new TrackedOutput();
        var input = new TrackedInput(archive);
        var error = assertThrows(AuthenticationFailure.class, () -> decode(input, output, archive.length,
                BrowserAssetsTest.sha(archive), data.length, () -> {
                    if (output.size() >= 65536) throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,
                            AuthenticationFailure.Cause.CANCELLED, "Cancelled");
                }));
        assertEquals(AuthenticationFailure.Cause.CANCELLED, error.reason()); assertEquals(65536, output.size());
        assertEquals(1, input.closes);
        var expired = new TrackedInput(archive);
        error = assertThrows(AuthenticationFailure.class, () -> decode(expired, OutputStream.nullOutputStream(),
                archive.length, BrowserAssetsTest.sha(archive), data.length,
                () -> AuthenticationFailure.checkpoint(AuthenticationFailure.Phase.SETUP, System.nanoTime() - 1, () -> false)));
        assertEquals(AuthenticationFailure.Cause.TIMEOUT, error.reason()); assertEquals(0, expired.consumed);
        assertEquals(1, expired.closes);
    }

    @Test void unrelatedReadWriteAndCloseFailuresRemainIoAndReleaseSourceExactlyOnce() throws Exception {
        byte[] archive = encode(DATA); var readFailure = new TrackedInput(archive); readFailure.failAt = 16;
        var read = assertThrows(IOException.class, () -> decode(readFailure, OutputStream.nullOutputStream(),
                archive.length, BrowserAssetsTest.sha(archive), DATA.length, () -> {}));
        assertFalse(read instanceof InvalidAsset); assertEquals(1, readFailure.closes);
        var writeFailure = new TrackedInput(archive);
        assertThrows(IOException.class, () -> decode(writeFailure, new OutputStream() {
            @Override public void write(int value) throws IOException { throw new IOException("fixture write failure"); }
        }, archive.length, BrowserAssetsTest.sha(archive), DATA.length, () -> {}));
        assertEquals(1, writeFailure.closes);
        var closeFailure = new TrackedInput(archive); closeFailure.failClose = true;
        assertThrows(IOException.class, () -> decode(closeFailure, OutputStream.nullOutputStream(),
                archive.length, BrowserAssetsTest.sha(archive), DATA.length, () -> {}));
        assertEquals(1, closeFailure.closes);
    }

    private static void assertInvalid(byte[] archive, long bytes, String hash, long expanded) {
        var input = new TrackedInput(archive);
        assertThrows(InvalidAsset.class, () -> decode(input, OutputStream.nullOutputStream(), bytes, hash, expanded, () -> {}));
        assertEquals(1, input.closes);
    }

    private static final class TrackedInput extends InputStream {
        private final ByteArrayInputStream input;
        int closes, consumed, maxRead, chunk = 65536, failAt = Integer.MAX_VALUE;
        boolean failClose;
        Runnable afterRead = () -> {};
        TrackedInput(byte[] bytes) { input = new ByteArrayInputStream(bytes); }
        @Override public int read() throws IOException {
            byte[] value = new byte[1]; int n = read(value, 0, 1); return n < 0 ? -1 : Byte.toUnsignedInt(value[0]);
        }
        @Override public int read(byte[] bytes, int offset, int count) throws IOException {
            maxRead = Math.max(maxRead, count);
            if (consumed >= failAt) throw new IOException("fixture read failure");
            int n = input.read(bytes, offset, Math.min(count, Math.min(chunk, failAt - consumed)));
            if (n > 0) consumed += n; afterRead.run(); return n;
        }
        @Override public void close() throws IOException { closes++; if (failClose) throw new IOException("fixture close failure"); }
    }

    private static final class TrackedOutput extends ByteArrayOutputStream {
        int maxWrite;
        boolean closed;
        @Override public void write(byte[] bytes, int offset, int count) { maxWrite = Math.max(maxWrite, count); super.write(bytes, offset, count); }
        @Override public void close() { closed = true; }
    }
}

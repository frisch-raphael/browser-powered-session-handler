package bpsh.config;

import bpsh.io.PrivateFiles;
import bpsh.model.ConfigurationException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Bounded native transfer I/O; presentation and explicit overwrite decisions remain in the UI. */
public final class NativeJourneyFiles {
    private NativeJourneyFiles() {}
    public static void write(Path file, String json, boolean replace) throws Exception {
        if (!replace) Files.createFile(file, PrivateFiles.creationAttributes(file.toAbsolutePath().getParent(), false));
        Files.writeString(file, json, StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.WRITE, java.nio.file.StandardOpenOption.TRUNCATE_EXISTING);
    }
    /**
     * Reads only an explicitly chosen bounded UTF-8 native import without logging its contents.
     *
     * @param file Explicit import source.
     * @return Bounded strictly decoded native JSON, without logging its contents.
     */
    public static String read(Path file) throws Exception {
        try (var input = Files.newInputStream(file)) {
            byte[] bytes = input.readNBytes((4 << 20) + 1);
            if (bytes.length > (4 << 20)) throw new ConfigurationException("Native import exceeds 4 MiB; export fewer journeys and retry.");
            try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString(); }
            catch (java.nio.charset.CharacterCodingException ex) { throw new ConfigurationException("Native import is not valid UTF-8; convert a native journey export to UTF-8 and retry."); }
        }
    }
}

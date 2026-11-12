package lab.auth;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.math.BigDecimal;
import java.nio.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Shared strict JSON and bounded file primitives. Errors never echo input data. */
public final class LabJson {
    private LabJson() {}
    public static final Gson JSON = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();

    public static JsonElement parse(byte[] bytes) {
        var decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try (var reader = new JsonReader(new StringReader(decoder.decode(ByteBuffer.wrap(bytes)).toString()))) {
            reader.setStrictness(Strictness.STRICT);
            var result = readValue(reader, 0);
            require(reader.peek() == JsonToken.END_DOCUMENT, "JSON_TRAILING_CONTENT");
            return result;
        } catch (IOException | IllegalStateException | NumberFormatException ex) {
            throw invalid("INVALID_JSON");
        }
    }

    private static JsonElement readValue(JsonReader reader, int depth) throws IOException {
        require(depth <= 64, "JSON_DEPTH");
        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                var object = new JsonObject(); reader.beginObject();
                while (reader.hasNext()) {
                    String key = reader.nextName(); require(!object.has(key), "JSON_DUPLICATE_FIELD");
                    object.add(key, readValue(reader, depth + 1));
                }
                reader.endObject(); yield object;
            }
            case BEGIN_ARRAY -> {
                var array = new JsonArray(); reader.beginArray();
                while (reader.hasNext()) array.add(readValue(reader, depth + 1));
                reader.endArray(); yield array;
            }
            case STRING -> new JsonPrimitive(reader.nextString());
            case NUMBER -> new JsonPrimitive(new BigDecimal(reader.nextString()));
            case BOOLEAN -> new JsonPrimitive(reader.nextBoolean());
            case NULL -> { reader.nextNull(); yield JsonNull.INSTANCE; }
            default -> throw invalid("INVALID_JSON_TOKEN");
        };
    }

    public static JsonObject read(Path path, int limit) throws IOException {
        require(limit > 0, "INVALID_LIMIT");
        try (var input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(limit + 1);
            require(bytes.length <= limit, "JSON_SIZE");
            return object(parse(bytes));
        }
    }
    public static JsonObject object(JsonElement value, String... fields) {
        var result = object(value);
        require(result.keySet().equals(Set.of(fields)), "JSON_FIELDS"); return result;
    }
    public static JsonObject object(JsonElement value) {
        require(value != null && value.isJsonObject(), "JSON_OBJECT"); return value.getAsJsonObject();
    }
    public static String text(JsonElement value) {
        String result = string(value); require(!result.isBlank(), "JSON_BLANK"); return result;
    }
    public static String string(JsonElement value) {
        require(value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString(), "JSON_STRING");
        return value.getAsString();
    }
    public static String text(JsonObject object, String name) { return text(object.get(name)); }
    public static long positive(JsonElement value) {
        require(value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber(), "JSON_INTEGER");
        try {
            long result = new BigDecimal(value.getAsString()).longValueExact();
            require(result > 0, "JSON_POSITIVE"); return result;
        } catch (ArithmeticException | NumberFormatException ex) { throw invalid("JSON_INTEGER"); }
    }
    public static List<String> strings(JsonElement value) {
        require(value != null && value.isJsonArray(), "JSON_ARRAY");
        var result = value.getAsJsonArray().asList().stream().map(LabJson::text).toList();
        require(new HashSet<>(result).size() == result.size(), "JSON_DUPLICATE_VALUE"); return result;
    }
    public static String member(JsonElement value, String... allowed) {
        String result = text(value); require(Set.of(allowed).contains(result), "JSON_ENUM"); return result;
    }
    public static String hash(JsonElement value) {
        String result = text(value); require(result.matches("[0-9a-f]{64}"), "SHA256_FORMAT"); return result;
    }
    public static UUID uuid(JsonElement value) {
        String text = text(value);
        try { var result = UUID.fromString(text); require(result.toString().equals(text), "UUID_FORMAT"); return result; }
        catch (IllegalArgumentException ex) { throw invalid("UUID_FORMAT"); }
    }
    public static String relative(JsonElement value) {
        String path = text(value);
        require(!path.contains("\\") && !path.contains(":") && !path.startsWith("/")
                && Arrays.stream(path.split("/", -1)).noneMatch(p -> p.isEmpty() || p.equals(".") || p.equals("..")), "RELATIVE_PATH");
        require(path.chars().noneMatch(c -> c < 32 || c == 127), "PATH_CONTROL"); return path;
    }
    public static Path owned(Path root, String relative) throws IOException {
        relative(new JsonPrimitive(relative));
        Path resolved = root.toRealPath().resolve(relative).normalize();
        require(resolved.startsWith(root.toRealPath()), "PATH_ESCAPE");
        Path existing = resolved;
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) existing = existing.getParent();
        require(existing.toRealPath().startsWith(root.toRealPath()), "PATH_ESCAPE"); return resolved;
    }
    public static String sha256(Path path) throws IOException {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            try (var input = Files.newInputStream(path)) {
                byte[] buffer = new byte[65536]; int count;
                while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA256_UNAVAILABLE"); }
    }
    public static void writeNew(Path path, Object value) throws IOException {
        Files.writeString(path, JSON.toJson(value), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }
    public static void require(boolean condition, String code) { if (!condition) throw invalid(code); }
    public static IllegalArgumentException invalid(String code) { return new IllegalArgumentException(code); }
}

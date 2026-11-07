package bpsh.runtime;

import bpsh.model.AuthenticationFailure;
import bpsh.runtime.BrowserRuntimeManager.Entry;
import bpsh.runtime.BrowserRuntimeManager.Limits;
import bpsh.runtime.BrowserRuntimeManager.Manifest;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import static bpsh.runtime.BrowserRuntimeManager.ARCHIVE_RESOURCE;
import static bpsh.runtime.BrowserRuntimeManager.platformResource;

/** Bounded manifest parsing, archive metadata and path validation; performs no cache publication. */
final class BrowserManifestCodec {
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private BrowserManifestCodec() {}
    /**
     * Parses a strict manifest and validates selectors, declared tree and overflow-safe size totals.
     * @param raw Exact UTF-8 bytes used to derive the bundle identity.
     * @param expectedPlatform Exact normalized current target.
     * @param limits Approved or lowered test ceilings.
     * @return Fully checked manifest; no filesystem or browser calls occur.
     * @throws AuthenticationFailure If syntax, version, platform, fields or tree semantics are invalid.
     */
    static Manifest parseManifest(byte[] raw, String expectedPlatform, Limits limits) throws AuthenticationFailure {
        try {
            requireSupportedPlatform(expectedPlatform);
            require(raw.length <= limits.manifestBytes(), "Manifest exceeds its size ceiling.");
            JsonNode n = JSON.readTree(utf8(raw));
            object(n, "formatVersion", "platform", "playwrightJavaVersion", "browserName", "browserVersion", "browserRevision",
                    "driverPackageVersion", "nodeVersion", "browserRoot", "browserExecutable", "nodeExecutable", "driverEntryPoint", "helpers",
                    "archive", "unpackedBytes", "entries");
            number(n.get("formatVersion"), 1, 1);
            if (!text(n, "platform").equals(expectedPlatform))
                throw failure(AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM, "This browser bundle was built for a different operating system or processor architecture.", "Reload the complete universal extension JAR.");
            require(text(n, "playwrightJavaVersion").equals("1.64.0") && text(n, "browserName").equals("chromium"), "Unsupported bundled runtime version.");
            text(n, "browserVersion"); text(n, "driverPackageVersion"); text(n, "nodeVersion");
            require(text(n, "browserRevision").matches("[0-9]+"), "Invalid browser revision.");
            String browserRoot = path(text(n, "browserRoot"), limits), browser = path(text(n, "browserExecutable"), limits);
            String node = path(text(n, "nodeExecutable"), limits), driver = path(text(n, "driverEntryPoint"), limits);
            JsonNode archive = n.get("archive"); object(archive, "resource", "sha256", "bytes");
            require(text(archive, "resource").equals(platformResource(ARCHIVE_RESOURCE, expectedPlatform)), "Unexpected archive resource.");
            String archiveHash = hashText(text(archive, "sha256")); long archiveBytes = number(archive.get("bytes"), 1, limits.zipBytes());
            long declaredTotal = number(n.get("unpackedBytes"), 0, limits.totalBytes()), sum = 0;
            Map<String, Entry> entries = new HashMap<>(); Map<String, String> filesystemNames = new HashMap<>();
            Set<String> directories = new HashSet<>();
            JsonNode rows = n.get("entries"); require(rows != null && rows.isArray() && rows.size() <= limits.entries(), "Invalid entry list.");
            for (JsonNode row : rows) {
                String type = text(row, "type"), name = path(text(row, "path"), limits); Entry entry;
                if (type.equals("file")) {
                    object(row, "path", "type", "bytes", "sha256", "executable");
                    require(row.get("executable").isBoolean(), "Executable mode must be boolean.");
                    long bytes = number(row.get("bytes"), 0, limits.fileBytes()); sum = Math.addExact(sum, bytes);
                    require(sum <= limits.totalBytes(), "Expanded size exceeds its ceiling.");
                    entry = new Entry(name, false, bytes, hashText(text(row, "sha256")), row.get("executable").booleanValue(), null);
                } else if (type.equals("symlink")) {
                    object(row, "path", "type", "target"); String target = text(row, "target");
                    relativeTarget(name, target, limits);
                    entry = new Entry(name, true, 0, null, false, target);
                } else throw new IOException("Unsupported entry type.");
                require(entries.put(name, entry) == null, "Duplicate entry.");
                String[] components = name.split("/"); String prefix = "";
                for (int i = 0; i < components.length; i++) {
                    if (expectedPlatform.startsWith("windows-"))
                        require(!components[i].matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\..*)?")
                                && !components[i].endsWith(".") && !components[i].endsWith(" ")
                                && !components[i].matches(".*[<>\"|?*].*"), "Unsafe Windows path component.");
                    prefix = prefix.isEmpty() ? components[i] : prefix + "/" + components[i];
                    String key = expectedPlatform.startsWith("windows-") || expectedPlatform.startsWith("macos-") ? prefix.toLowerCase(Locale.ROOT) : prefix;
                    String previous = filesystemNames.putIfAbsent(key, prefix);
                    require(previous == null || previous.equals(prefix), "Target-filesystem name collision.");
                    if (i < components.length - 1) directories.add(prefix);
                }
            }
            require(sum == declaredTotal, "Expanded byte sum mismatch.");
            for (String dir : directories) require(!entries.containsKey(dir), "File/link conflicts with a directory.");
            for (Entry e : entries.values()) if (e.link()) resolve(e.path(), entries, directories, limits);
            require(directories.contains(resolve(browserRoot, entries, directories, limits)), "Browser root is not a directory.");
            for (String selector : List.of(browser, node, driver)) {
                Entry e = entries.get(resolve(selector, entries, directories, limits));
                require(e != null && !e.link(), "Executable/driver selector is not a regular file.");
                if (!selector.equals(driver)) require(e.executable(), "Executable selector lacks executable mode.");
            }
            require(n.get("helpers").isArray(), "Invalid helper list.");
            List<String> helpers = new ArrayList<>(); Set<String> helperNames = new HashSet<>();
            for (JsonNode helper : n.get("helpers")) {
                object(helper, "name", "revision", "path"); require(helperNames.add(text(helper, "name")), "Duplicate helper.");
                require(text(helper, "revision").matches("[0-9]+"), "Invalid helper revision.");
                String value = path(text(helper, "path"), limits); resolve(value, entries, directories, limits); helpers.add(value);
            }
            return new Manifest(expectedPlatform, browserRoot, browser, node, driver, archiveHash, archiveBytes, sum,
                    Map.copyOf(entries), Set.copyOf(directories), List.copyOf(helpers));
        } catch (AuthenticationFailure ex) { throw ex; }
        catch (Exception ex) {
            throw failure(AuthenticationFailure.Cause.ASSET_CORRUPT, "The bundled browser configuration is invalid.",
                    "Rebuild or download the complete universal extension JAR, then reload it.");
        }
    }
    /**
     * Resolves declared links, including links in selector ancestors, with bounded cycle detection.
     * @param value Declared path/selector to resolve.
     * @param entries Declared nondirectory records.
     * @param directories Implicit parent directories.
     * @param limits Link hop and path ceilings.
     * @return Existing final file or implicit-directory path within the bundle.
     * @throws IOException If dangling, cyclic, escaping or over the hop limit.
     */
    static String resolve(String value, Map<String, Entry> entries, Set<String> directories, Limits limits) throws IOException {
        Set<String> visited = new HashSet<>(); int hops = 0;
        while (true) {
            require(visited.add(value), "Cyclic link chain."); String[] parts = value.split("/"); String prefix = ""; boolean changed = false;
            for (int i = 0; i < parts.length; i++) {
                prefix = prefix.isEmpty() ? parts[i] : prefix + "/" + parts[i]; Entry entry = entries.get(prefix);
                if (entry != null && entry.link()) {
                    require(++hops <= limits.linkHops(), "Link chain exceeds its ceiling.");
                    String resolved = relativeTarget(prefix, entry.target(), limits);
                    if (i + 1 < parts.length) resolved += "/" + String.join("/", Arrays.copyOfRange(parts, i + 1, parts.length));
                    value = path(resolved, limits); changed = true; break;
                }
            }
            if (!changed) { require(entries.containsKey(value) || directories.contains(value), "Dangling selector/link."); return value; }
        }
    }
    /**
     * Resolves a relative link payload lexically, permitting dot/parent only within the bundle.
     * @param link Bundle-relative link path.
     * @param target Relative UTF-8 payload without drive/backslash/absolute forms.
     * @param limits Target-byte/path ceilings.
     * @return Normalized contained destination.
     * @throws IOException If the link escapes or its representation is invalid.
     */
    static String relativeTarget(String link, String target, Limits limits) throws IOException {
        require(!target.isEmpty() && target.getBytes(StandardCharsets.UTF_8).length <= limits.pathBytes() && !target.startsWith("/")
                && !target.contains("\\") && !target.contains(":") && !target.contains("\0"), "Invalid link target.");
        ArrayDeque<String> stack = new ArrayDeque<>(); int slash = link.lastIndexOf('/');
        if (slash >= 0) stack.addAll(List.of(link.substring(0, slash).split("/")));
        for (String component : target.split("/", -1)) {
            require(!component.isEmpty(), "Empty link component.");
            if (component.equals("..")) { require(!stack.isEmpty(), "Escaping link."); stack.removeLast(); }
            else if (!component.equals(".")) stack.addLast(component);
        }
        require(!stack.isEmpty(), "Link targets bundle root."); return path(String.join("/", stack), limits);
    }
    /**
     * Validates safe relative member/selector syntax before any path is written.
     * @param value Relative POSIX path, without trailing directory slash.
     * @param limits UTF-8 byte and component ceilings.
     * @return Unchanged validated spelling.
     * @throws IOException If absolute, reserved, traversal-shaped or too long/deep.
     */
    static String path(String value, Limits limits) throws IOException {
        require(!value.isEmpty() && !value.startsWith("/") && !value.contains("\\") && !value.contains(":") && !value.contains("\0")
                && value.getBytes(StandardCharsets.UTF_8).length <= limits.pathBytes(), "Invalid relative asset path.");
        String[] parts = value.split("/", -1); require(parts.length <= limits.depth() && !parts[0].equals(".complete.json"), "Reserved/deep asset path.");
        for (String part : parts) require(!part.isEmpty() && !part.equals(".") && !part.equals(".."), "Unsafe asset path component.");
        return value;
    }
    /**
     * Reads a small resource with an inclusive byte ceiling before allocating an unbounded byte array.
     *
     * @param input Owned input managed by the caller.
     * @param max Inclusive byte ceiling.
     * @return Bounded bytes.
     * @throws IOException On overflow/read failure.
     */
    static byte[] bounded(InputStream input, long max) throws IOException {
        byte[] bytes = input.readNBytes((int) Math.min(Integer.MAX_VALUE, max + 1)); require(bytes.length <= max, "Resource exceeds byte ceiling."); return bytes;
    }
    /**
     * Decodes metadata strictly so malformed UTF-8 cannot silently change a manifest path or field.
     *
     * @param bytes UTF-8 representation.
     * @return Strictly decoded text.
     * @throws IOException On malformed encoding.
     */
    static String utf8(byte[] bytes) throws IOException { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
    /**
     * Returns required SHA-256 primitive; no global provider configuration changes occur.
     *
     * @return Required SHA-256 primitive; no global provider configuration changes occur.
     */
    static MessageDigest sha() { try { return MessageDigest.getInstance("SHA-256"); } catch (Exception ex) { throw new IllegalStateException("SHA-256 unavailable."); } }
    /**
     * Hashes exact input bytes using SHA-256 for manifest, archive or cache identity checks.
     *
     * @param bytes Exact source bytes.
     * @return Lowercase SHA-256.
     */
    static String digest(byte[] bytes) { return hex(sha().digest(bytes)); }
    /**
     * Formats digest bytes in the lowercase representation required by the asset contract.
     *
     * @param bytes Digest bytes.
     * @return Lowercase hex.
     */
    static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }
    /**
     * Rejects noncanonical SHA-256 text before comparing integrity metadata.
     *
     * @param value Candidate lowercase SHA-256.
     * @return Unchanged valid text.
     * @throws IOException If malformed.
     */
    static String hashText(String value) throws IOException { require(value.matches("[0-9a-f]{64}"), "Invalid SHA-256."); return value; }
    /**
     * Requires an object with the exact declared fields, rejecting omissions and unknown keys.
     *
     * @param n Candidate object.
     * @param fields Exact required field set.
     * @throws IOException On unknown/missing/type failure.
     */
    static void object(JsonNode n, String... fields) throws IOException {
        require(n != null && n.isObject() && n.size() == fields.length, "Invalid object fields.");
        for (String field : fields) require(n.has(field), "Missing required field.");
    }
    /**
     * Reads a required nonblank string without coercing other JSON value types.
     *
     * @param n Containing object.
     * @param field Known string field.
     * @return Nonblank exact text.
     * @throws IOException On type/content failure.
     */
    static String text(JsonNode n, String field) throws IOException { JsonNode v = n == null ? null : n.get(field); require(v != null && v.isTextual() && !v.textValue().isBlank(), "Expected string."); return v.textValue(); }
    /**
     * Reads an integral JSON number inside the declared inclusive bounds without numeric coercion.
     *
     * @param n Number node.
     * @param min Inclusive minimum.
     * @param max Inclusive maximum.
     * @return Strict long.
     * @throws IOException On invalid type/range.
     */
    static long number(JsonNode n, long min, long max) throws IOException { require(n != null && n.isIntegralNumber() && n.canConvertToLong() && n.longValue() >= min && n.longValue() <= max, "Invalid integer."); return n.longValue(); }

    /**
     * Builds a typed failure with operator recovery guidance and no raw exception cause.
     *
     * @param reason Typed setup category.
     * @param safe Safe problem text.
     * @param recovery Concrete correction.
     * @return Redacted setup exception.
     */
    static AuthenticationFailure failure(AuthenticationFailure.Cause reason, String safe, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, reason, safe, recovery); }
    /** Rejects unsupported JVM targets before any resource or cache access.
     * @param target Normalized JVM OS/CPU target.
     * @throws AuthenticationFailure When the target has no bundled payload.
     */
    static void requireSupportedPlatform(String target) throws AuthenticationFailure {
        if (!Set.of("windows-x64", "linux-x64", "macos-x64").contains(target))
            throw failure(AuthenticationFailure.Cause.UNSUPPORTED_PLATFORM,
                    "Bundled Chromium does not support " + target + ".",
                    "Supported targets: Windows x64, Linux x64 and Intel macOS. Use a supported JVM and operating system.");
    }
    /**
     * Rejects a failed asset invariant with a safe symbolic explanation.
     *
     * @param condition Required invariant.
     * @param safe Safe symbolic detail.
     * @throws IOException If invariant fails.
     */
    static void require(boolean condition, String safe) throws IOException { if (!condition) throw new InvalidAsset(safe); }
}

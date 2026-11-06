import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/** Builds atomic byte-preserving request replacements before any Burp hook commits or records provenance. */
public final class NativeTagResolver {
    private final JourneyRegistry registry;
    private final AuthenticationCoordinator coordinator;

    /**
     * Shares the same registry/coordinator for explicit tags and ordinary automatic injection.
     * @param registry Immutable generation/alias publications.
     * @param coordinator Shared bounded acquisition and usable snapshots.
     */
    public NativeTagResolver(JourneyRegistry registry, AuthenticationCoordinator coordinator) { this.registry = registry; this.coordinator = coordinator; }

    /** One captured automatic rule and its resolved saved generation. */
    public record Automatic(JourneyRegistry.Entry entry, JourneyDefinition.Recovery recovery) {}

    /** Owns caller detachment separately from the shared authentication cycle. */
    public final class Operation implements AutoCloseable {
        private final boolean tagsOnly;
        private final CompletableFuture<Resolved> future;
        private final AuthenticationCoordinator.Ticket ticket;
        /**
         * Binds the complete request result and explicit-only policy to optional caller detachment.
         *
         * @param tagsOnly Whether any native syntax forces the whole request into explicit-only mode.
         * @param future Atomic prepared result.
         * @param ticket Optional admitted waiter.
         */
        private Operation(boolean tagsOnly, CompletableFuture<Resolved> future, AuthenticationCoordinator.Ticket ticket) {
            this.tagsOnly = tagsOnly; this.future = future; this.ticket = ticket;
            future.whenComplete((result, error) -> { if (future.isCancelled() && ticket != null) ticket.close(); });
        }
        /**
         * Returns whether automatic credentials were suppressed for this whole request.
         *
         * @return Whether automatic credentials were suppressed for this whole request.
         */
        public boolean tagsOnly() { return tagsOnly; }
        /**
         * Returns complete prepared result or safe typed failure; never a partially modified request.
         *
         * @return Complete prepared result or safe typed failure; never a partially modified request.
         */
        public CompletableFuture<Resolved> future() { return future; }
        /** Detaches this request only; shared cycles continue for other owners. */
        @Override public void close() { if (ticket != null) ticket.close(); }
    }

    /** Holds private prepared bytes and used versions until a final, immediate generation/usability check. */
    public final class Resolved {
        private final byte[] bytes;
        private final Map<String, JourneyRegistry.Entry> bindings;
        private final Map<JourneyDefinition.Identity, TokenSnapshot> tokens;
        private final boolean changed;
        private final List<Automatic> automatic;
        /**
         * Retains complete private output bytes and token-version provenance until the final commit check.
         *
         * @param bytes Complete prepared message.
         * @param bindings Captured source references.
         * @param tokens Used publications.
         * @param changed Whether the original needs replacement.
         */
        private Resolved(byte[] bytes, Map<String, JourneyRegistry.Entry> bindings, Map<JourneyDefinition.Identity, TokenSnapshot> tokens, boolean changed, List<Automatic> automatic) {
            this.bytes = bytes; this.bindings = Map.copyOf(bindings); this.tokens = Map.copyOf(tokens); this.changed = changed; this.automatic = List.copyOf(automatic);
        }
        /**
         * Returns whether an unchanged ordinary request can retain its original host object.
         *
         * @return Whether an unchanged ordinary request can retain its original host object.
         */
        public boolean changed() { return changed; }
        /**
         * Rechecks every used publication immediately before the caller constructs the outgoing request.
         * @return Caller-owned complete bytes; no partial substitutions are ever returned.
         * @throws AuthenticationFailure If configuration, invalidation or hard expiry superseded a result.
         */
        public byte[] commit() throws AuthenticationFailure {
            byte[] result = bytes.clone();
            if (!coordinator.current(tokens.values())) throw aliasFailure(String.join(", ", bindings.keySet()), AuthenticationFailure.Cause.STALE,
                    "The journey changed or its token expired while the request was being prepared.", "Resend the request to use the current saved journey and token.");
            return result;
        }
        /**
         * Produces token-free used-version provenance only for the journeys actually inserted.
         * @return Distinct generation/version/recovery rules for recording after successful commit.
         */
        public List<SessionRecovery.Used> uses() {
            Map<JourneyDefinition.Identity, SessionRecovery.Used> used = new LinkedHashMap<>();
            bindings.values().forEach(e -> used.put(e.identity(), new SessionRecovery.Used(e.identity(), tokens.get(e.identity()).version(), new JourneyDefinition.Recovery(false, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))));
            if (!automatic.isEmpty()) {
                used.clear(); var winners = new LinkedHashMap<String, Automatic>();
                for (var a : automatic) {
                    for (var mapping : a.entry().definition().injection().tokens()) switch (mapping.type()) {
                        case BEARER -> winners.put("header:authorization", a);
                        case HEADER -> winners.put("header:" + mapping.name().toLowerCase(Locale.ROOT), a);
                        case COOKIE -> winners.put("cookie:" + mapping.name(), a);
                        default -> { }
                    }
                    var source = a.entry().definition().extraction();
                    var sources = source instanceof JourneyDefinition.CombinedExtraction c ? c.tokens().stream().map(JourneyDefinition.NamedExtraction::selector).toList() : List.of(source);
                    for (var selector : sources) if (selector instanceof JourneyDefinition.CookieExtraction c) winners.put("cookie:" + c.name(), a);
                }
                winners.values().forEach(a -> used.put(a.entry().identity(), new SessionRecovery.Used(a.entry().identity(), tokens.get(a.entry().identity()).version(), a.recovery())));
            }
            return List.copyOf(used.values());
        }
        /** Retains the pre-injection template and exact saved identities, never a later alias lookup. */
        public ReplayTemplate replayTemplate(byte[] original) { return new ReplayTemplate(original, bindings, automatic); }
        /**
         * Returns safe result label excluding message bytes, credentials and source fields.
         *
         * @return Safe result label excluding message bytes, credentials and source fields.
         */
        @Override public String toString() { return "ResolvedRequest[changed=" + changed + ", journeys=" + tokens.size() + "]"; }
    }

    /** Private request-local replay input, pinned to the original saved generations and destinations. */
    public final class ReplayTemplate {
        private final byte[] original;
        private final Map<String, JourneyRegistry.Entry> bindings;
        private final List<Automatic> automatic;
        private ReplayTemplate(byte[] original, Map<String, JourneyRegistry.Entry> bindings, List<Automatic> automatic) {
            this.original = original.clone(); this.bindings = Map.copyOf(bindings); this.automatic = List.copyOf(automatic);
        }
        public int size() { return original.length; }
        public Operation prepare() throws AuthenticationFailure { return resolveInternal(original, automatic, bindings); }
        @Override public String toString() { return "ReplayTemplate[journeys=" + bindings.size() + "]"; }
    }

    /** Defines one source span and its strict decoding context. */
    private record Region(int start, int end, NativeTagParser.Tree tree, Charset charset, Kind kind) {}
    /** Names validation constraints that apply after complete rendering. */
    private enum Kind { TARGET, HEADER, BODY }
    /** Raw header offsets retain spelling, spacing and all unaffected wire bytes. */
    private record Header(String name, int start, int end, int valueStart) {}
    /** Complete HTTP boundary offsets, found before URL helpers see literal native delimiters. */
    private record Layout(int targetStart, int targetEnd, int bodyStart, int headerEnd, List<Header> headers) {}
    /** Replacement spans always address the original bytes and are applied only as one complete plan. */
    private record Edit(int start, int end, byte[] value) {}

    /**
     * Resolves explicit tags first, independently of ordinary enabled/tool/scope eligibility.
     * @param raw Stable raw HTTP message snapshot, before URL helper parsing.
     * @param automatic Explicit selected ordinary journey, or null when none is selected.
     * @param automaticEligible Result of ordinary enabled/tool/URL checks; ignored when tags are present.
     * @return Detachable request operation with a single complete result.
     * @throws AuthenticationFailure If syntax, unsupported location, bounds or aliases fail before acquisition.
     */
    public Operation resolve(byte[] raw, JourneyRegistry.Entry automatic, boolean automaticEligible) throws AuthenticationFailure {
        return resolveInternal(raw, automaticEligible && automatic != null ? List.of(new Automatic(automatic, new JourneyDefinition.Recovery(false, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))) : List.of());
    }

    /** Resolves ordered automatic rules atomically; explicit tags still suppress every automatic rule. */
    public Operation resolveAutomatic(byte[] raw, List<Automatic> automatic) throws AuthenticationFailure { return resolveInternal(raw, List.copyOf(automatic)); }

    private Operation resolveInternal(byte[] raw, List<Automatic> automatic) throws AuthenticationFailure { return resolveInternal(raw, automatic, null); }
    private Operation resolveInternal(byte[] raw, List<Automatic> automatic, Map<String, JourneyRegistry.Entry> pinned) throws AuthenticationFailure {
        boolean tagged = tagged(raw);
        if (!tagged && automatic.isEmpty())
            return new Operation(false, CompletableFuture.completedFuture(new Resolved(raw.clone(), Map.of(), Map.of(), false, List.of())), null);
        Layout layout = layout(raw);
        List<Region> regions = new ArrayList<>(); NativeTagParser.Budget budget = new NativeTagParser.Budget();
        Map<String, JourneyRegistry.Entry> bindings = new LinkedHashMap<>();
        if (tagged) {
            if (raw.length > NativeTagParser.MAX_OUTPUT_BYTES) throw NativeTagParser.syntax("The tagged message exceeds the 4 MiB expanded-message ceiling.");
            if (NativeTagParser.encodedPrefix(raw, layout.targetStart(), layout.targetEnd()))
                throw NativeTagParser.syntax("The URL contains a percent-encoded authentication tag. Enter the tag directly in the raw request editor.");
            validateLocations(raw, layout);
            addRegion(raw, layout.targetStart(), layout.targetEnd(), StandardCharsets.ISO_8859_1, Kind.TARGET, regions, budget);
            for (Header header : layout.headers()) {
                if (contains(raw, header.valueStart(), header.end())) addRegion(raw, header.valueStart(), header.end(), StandardCharsets.ISO_8859_1, Kind.HEADER, regions, budget);
            }
            if (contains(raw, layout.bodyStart(), raw.length)) {
                Charset charset = SessionRecovery.charset(header(raw, layout, "content-type"));
                String coding = header(raw, layout, "content-encoding");
                if (charset == null || (coding != null && !coding.equalsIgnoreCase("identity")) || header(raw, layout, "transfer-encoding") != null)
                    throw NativeTagParser.syntax("Authentication tags in the body require uncompressed UTF-8, ASCII or ISO-8859-1 text with a supported Content-Type.");
                addRegion(raw, layout.bodyStart(), raw.length, charset, Kind.BODY, regions, budget);
            }
            JourneyRegistry.Snapshot snapshot = registry.snapshot();
            for (String alias : budget.aliases) {
                try {
                    var entry = pinned == null ? snapshot.resolve(alias) : pinned.get(alias);
                    if (entry == null || !snapshot.isCurrent(entry.identity())) throw new IllegalStateException();
                    bindings.put(alias, entry);
                }
                catch (RuntimeException ex) { throw aliasFailure(alias, AuthenticationFailure.Cause.CONFIGURATION,
                        "The tag could not be matched to an available saved journey.", "Choose an available saved journey from Add authentication token."); }
            }
        } else automatic.forEach(a -> bindings.put(a.entry().definition().canonicalAlias(), a.entry()));
        List<Automatic> activeRules = tagged ? List.of() : automatic;
        byte[] original = raw.clone(); Map<String, JourneyRegistry.Entry> immutable = Map.copyOf(bindings);
        if (bindings.isEmpty()) return new Operation(tagged, CompletableFuture.completedFuture(new Resolved(render(original, layout, regions, Map.of(), tagged, automatic), immutable, Map.of(), true, activeRules)), null);
        AuthenticationCoordinator.Ticket ticket = tagged ? coordinator.acquire(bindings.values()) : coordinator.acquireOrdered(bindings.values());
        CompletableFuture<Resolved> future = ticket.future().handle((tokens, error) -> {
            if (error != null) {
                Throwable cause = error instanceof CompletionException && error.getCause() != null ? error.getCause() : error;
                AuthenticationFailure safe = cause instanceof AuthenticationFailure failure ? failure : new AuthenticationFailure(AuthenticationFailure.Phase.LIFECYCLE, AuthenticationFailure.Cause.UNKNOWN,
                        "Login failed.", "");
                List<String> failed = immutable.entrySet().stream().filter(e -> e.getValue().identity().equals(safe.journey())).map(Map.Entry::getKey).toList();
                String aliases = String.join(", ", failed.isEmpty() ? immutable.keySet() : failed);
                AuthenticationFailure attributed = new AuthenticationFailure(safe.phase(), safe.reason(), "Journey " + aliases + ": " + safe.problem(), safe.recovery(), safe.httpStatus(), safe.retryAfter());
                if (safe.journey() != null) attributed = attributed.forJourney(safe.journey());
                throw new CompletionException(attributed);
            }
            try {
                Map<String, String> values = new LinkedHashMap<>();
                immutable.forEach((alias, entry) -> {
                    var token = tokens.get(entry.identity());
                    if (!tagged || token.namedTokens().size() <= 1) values.put(alias, token.value());
                    token.namedTokens().forEach((name, value) -> values.put(alias + "\0" + name, value));
                    token.cookies().forEach((name, value) -> values.put(alias + "\0cookie=" + name, value));
                });
                return new Resolved(render(original, layout, regions, values, tagged, automatic), immutable, tokens, true, activeRules);
            } catch (AuthenticationFailure ex) { throw new CompletionException(ex); }
        });
        return new Operation(tagged, future, ticket);
    }

    /**
     * Recognizes literal reserved syntax anywhere and percent-encoded notation specifically in a target.
     * @param raw Raw message bytes, without decoding or materializing its body as a string.
     * @return Whether explicit-tag policy must take precedence over ordinary scope.
     */
    public static boolean tagged(byte[] raw) {
        if (contains(raw, 0, raw.length)) return true;
        int end = crlf(raw, 0); if (end < 0) return false;
        int first = index(raw, (byte) ' ', 0, end), last = lastIndex(raw, (byte) ' ', 0, end);
        return first >= 0 && last > first && NativeTagParser.encodedPrefix(raw, first + 1, last);
    }

    /**
     * Rejects markers outside supported fields before any alias is resolved or cycle is admitted.
     * @param raw Original message bytes.
     * @param layout Parsed wire boundaries.
     * @throws AuthenticationFailure On method, authority, header-name, Host or framing-header markers.
     */
    private static void validateLocations(byte[] raw, Layout layout) throws AuthenticationFailure {
        if (contains(raw, 0, layout.targetStart()) || contains(raw, layout.targetEnd(), crlf(raw, 0))) throw NativeTagParser.syntax("An authentication tag is in the HTTP method or version. Move it to a header value, URL path, query or text body.");
        String target = latin(raw, layout.targetStart(), layout.targetEnd());
        if (!target.startsWith("/")) {
            int scheme = target.indexOf("://");
            if (scheme < 0 || !(target.startsWith("http://") || target.startsWith("https://"))) throw NativeTagParser.syntax("Use authentication tags in the path or query of an HTTP(S) URL.");
            int path = target.indexOf('/', scheme + 3), query = target.indexOf('?', scheme + 3);
            int authorityEnd = path < 0 ? target.length() : path; if (query >= 0) authorityEnd = Math.min(authorityEnd, query);
            if (contains(raw, layout.targetStart(), layout.targetStart() + authorityEnd)) throw NativeTagParser.syntax("An authentication tag is in the URL scheme or host. Move it to the path, query, a header value or text body.");
        }
        for (Header header : layout.headers()) {
            if (contains(raw, header.start(), header.valueStart())) throw NativeTagParser.syntax("An authentication tag is in a header name. Move it to the header value.");
            if (List.of("host", "content-length", "transfer-encoding", "content-encoding").contains(header.name()) && contains(raw, header.valueStart(), header.end()))
                throw NativeTagParser.syntax("An authentication tag is in Host, Content-Length, Transfer-Encoding or Content-Encoding. Move it to an application header or text body.");
        }
    }

    /**
     * Validates a marked source region using the whole-request budget and strict original charset.
     * @param raw Original message bytes.
     * @param start Inclusive field offset.
     * @param end Exclusive field offset.
     * @param charset Declared supported charset.
     * @param kind Output-context constraints.
     * @param regions Destination immutable-ready region list.
     * @param budget Shared input/node/reference limits.
     * @throws AuthenticationFailure On invalid text, grammar or bounds.
     */
    private static void addRegion(byte[] raw, int start, int end, Charset charset, Kind kind, List<Region> regions, NativeTagParser.Budget budget) throws AuthenticationFailure {
        if (!contains(raw, start, end)) return;
        if (end - start > NativeTagParser.MAX_TEXT_BYTES - budget.textBytes) throw NativeTagParser.syntax("Tagged text exceeds 1 MiB.");
        try {
            String text = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw, start, end - start)).toString();
            regions.add(new Region(start, end, NativeTagParser.parse(text, end - start, budget), charset, kind));
        } catch (java.nio.charset.CharacterCodingException ex) { throw NativeTagParser.syntax("A tagged text field is invalid in its declared charset. Convert it to UTF-8 or place the tag in a header."); }
    }

    /**
     * Resolves all marked fields or one ordinary injection into a complete nonoverlapping edit list.
     * @param raw Original private bytes.
     * @param layout Original field offsets.
     * @param regions Validated explicit trees.
     * @param values Canonical aliases to deliberate token values.
     * @param tagged Whether automatic injection must be suppressed.
     * @param automatic Explicit ordinary definition when untagged.
     * @return Complete output within tagged message bounds.
     * @throws AuthenticationFailure If encoding, output context or expansion is invalid.
     */
    private static byte[] render(byte[] raw, Layout layout, List<Region> regions, Map<String, String> values, boolean tagged, List<Automatic> automatic) throws AuthenticationFailure {
        List<Edit> edits = new ArrayList<>(); Integer bodyLength = null;
        if (tagged) {
            for (Region region : regions) {
                String rendered = region.tree().render(values);
                if (region.kind() == Kind.HEADER && rendered.chars().anyMatch(Character::isISOControl)) throw NativeTagParser.syntax("An expanded header contains a control character. Use a suitable encoding wrapper.");
                if (region.kind() == Kind.TARGET) validateTarget(rendered);
                byte[] bytes = encode(rendered, region.charset()); if (region.kind() == Kind.BODY) bodyLength = bytes.length;
                edits.add(new Edit(region.start(), region.end(), bytes));
            }
            if (bodyLength != null) {
                boolean length = false;
                for (Header h : layout.headers()) if (h.name().equals("content-length")) { edits.add(new Edit(h.valueStart(), h.end(), Integer.toString(bodyLength).getBytes(StandardCharsets.US_ASCII))); length = true; }
                if (!length) edits.add(new Edit(layout.headerEnd(), layout.headerEnd(), ("Content-Length: " + bodyLength + "\r\n").getBytes(StandardCharsets.US_ASCII)));
            }
        } else ordinary(raw, layout, automatic, values, edits);
        return apply(raw, edits, tagged ? NativeTagParser.MAX_OUTPUT_BYTES : Integer.MAX_VALUE);
    }

    /**
     * Applies automatic credentials locally to this request, never a shared cookie jar.
     * @param raw Original bytes.
     * @param layout Original field positions.
     * @param automatic Selected ordinary journeys in configured order.
     * @param values Captured primary, named-token and cookie values.
     * @param edits Complete-plan destination.
     * @throws AuthenticationFailure If a value cannot safely inhabit its chosen credential form.
     */
    private static void ordinary(byte[] raw, Layout layout, List<Automatic> automatic, Map<String, String> values, List<Edit> edits) throws AuthenticationFailure {
        Map<String, String[]> headers = new LinkedHashMap<>();
        Map<String, String> cookies = new LinkedHashMap<>();
        for (var rule : automatic) {
        var entry = rule.entry();
        String alias = entry.definition().canonicalAlias(), token = values.get(alias);
        var extraction = entry.definition().extraction();
        var sources = extraction instanceof JourneyDefinition.CombinedExtraction combined ? combined.tokens().stream().map(JourneyDefinition.NamedExtraction::selector).toList() : List.of(extraction);
        for (var source : sources) if (source instanceof JourneyDefinition.CookieExtraction cookie) {
            String value = values.get(alias + "\0cookie=" + cookie.name());
            if (value == null && !(extraction instanceof JourneyDefinition.CombinedExtraction)) value = token;
            if (value == null) throw NativeTagParser.syntax("A captured cookie is missing from the authentication result. Test the login again.");
            cookies.put(cookie.name(), value);
        }
        for (var mapping : entry.definition().injection().tokens()) {
            if (mapping.type() == JourneyDefinition.InjectionType.DISABLED) continue;
            String value = mapping.tokenName() == null ? token : values.get(alias + "\0" + mapping.tokenName());
            if (value == null) throw NativeTagParser.syntax("A mapped token is missing from the authentication result. Test the login again.");
            switch (mapping.type()) {
                case BEARER -> headers.put("authorization", new String[]{"Authorization", "Bearer " + value});
                case HEADER -> headers.put(mapping.name().toLowerCase(Locale.ROOT), new String[]{mapping.name(), value});
                case COOKIE -> cookies.put(mapping.name(), value);
                default -> throw NativeTagParser.syntax("A token has an unsupported injection destination. Save its configuration again.");
            }
        }
        }
        for (var h : headers.entrySet()) headerEdits(raw, layout, h.getKey(), h.getValue()[0], h.getValue()[1], edits);
        if (cookies.isEmpty()) return;
        for (String value : cookies.values()) if (value.chars().anyMatch(c -> c < 33 || c > 126 || "\",;\\".indexOf(c) >= 0)) throw NativeTagParser.syntax("A selected cookie contains characters that cannot be sent in a Cookie header.");
        var retained = new ArrayList<String>(); var inserted = new java.util.HashSet<String>();
        for (Header h : layout.headers()) if (h.name().equals("cookie")) for (String part : latin(raw, h.valueStart(), h.end()).split(";", -1)) {
            int eq = part.indexOf('='); String name = eq < 0 ? "" : part.substring(0, eq).trim();
            if (cookies.containsKey(name)) { if (inserted.add(name)) retained.add(name + "=" + cookies.get(name)); }
            else retained.add(part);
        }
        cookies.forEach((name, value) -> { if (inserted.add(name)) retained.add((retained.isEmpty() ? "" : " ") + name + "=" + value); });
        headerEdits(raw, layout, "cookie", "Cookie", String.join(";", retained), edits);
    }

    /**
     * Replaces one credential header atomically and consolidates duplicate fields without touching unrelated bytes.
     * @param raw Original request.
     * @param layout Original field offsets.
     * @param name Lowercase lookup name.
     * @param spelling Header spelling when adding a missing field.
     * @param value Validated complete value.
     * @param edits Private replacement plan.
     * @throws AuthenticationFailure If the value contains controls or cannot be encoded.
     */
    private static void headerEdits(byte[] raw, Layout layout, String name, String spelling, String value, List<Edit> edits) throws AuthenticationFailure {
        if (value.chars().anyMatch(Character::isISOControl)) throw NativeTagParser.syntax("A selected credential contains an unsafe header character.");
        List<Header> existing = layout.headers().stream().filter(h -> h.name().equals(name)).toList();
        if (existing.isEmpty()) edits.add(new Edit(layout.headerEnd(), layout.headerEnd(), encode(spelling + ": " + value + "\r\n", StandardCharsets.ISO_8859_1)));
        else {
            edits.add(new Edit(existing.getFirst().valueStart(), existing.getFirst().end(), encode(value, StandardCharsets.ISO_8859_1)));
            for (int i = 1; i < existing.size(); i++) edits.add(new Edit(existing.get(i).start(), existing.get(i).end() + 2, new byte[0]));
        }
    }

    /**
     * Validates the expanded path/query before any host URL parser or outgoing request sees it.
     * @param target Complete rendered target.
     * @throws AuthenticationFailure On whitespace, control characters, fragments or invalid URI syntax.
     */
    private static void validateTarget(String target) throws AuthenticationFailure {
        if (target.isEmpty() || target.chars().anyMatch(c -> c <= 32 || c >= 127 || c == '#' || c == '\\')) throw NativeTagParser.syntax("The expanded request target contains unsafe characters. Wrap path/query values in url or form.");
        try { new URI(target); } catch (Exception ex) { throw NativeTagParser.syntax("The expanded request target is invalid. Use an explicit URL-component encoding wrapper."); }
    }

    /**
     * Encodes with reporting rather than silently replacing unrepresentable Unicode characters.
     * @param text Complete resolved field.
     * @param charset Original declared field charset.
     * @return Exact representable output bytes.
     * @throws AuthenticationFailure If output cannot be represented.
     */
    private static byte[] encode(String text, Charset charset) throws AuthenticationFailure {
        try { ByteBuffer buffer = charset.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(text)); byte[] bytes = new byte[buffer.remaining()]; buffer.get(bytes); return bytes; }
        catch (java.nio.charset.CharacterCodingException ex) { throw NativeTagParser.syntax("The resolved output is not representable in the field's charset. Convert the body to UTF-8 or use an ASCII-producing encoding wrapper."); }
    }

    /**
     * Constructs output once after validating every span and the total byte length.
     * @param raw Original bytes.
     * @param edits Original-offset edits; unaffected ranges are copied verbatim.
     * @param maximum Expanded message ceiling for explicit tags.
     * @return Complete new message, with no partial output exposed on failure.
     * @throws AuthenticationFailure On overlap, arithmetic overflow or the output ceiling.
     */
    private static byte[] apply(byte[] raw, List<Edit> edits, int maximum) throws AuthenticationFailure {
        edits.sort(Comparator.comparingInt(Edit::start).thenComparingInt(Edit::end)); long length = raw.length; int previous = 0;
        for (Edit edit : edits) { if (edit.start() < previous || edit.end() < edit.start()) throw NativeTagParser.syntax("Authentication tags overlap in the request. Check the tag boundaries."); previous = edit.end(); length += (long) edit.value().length - (edit.end() - edit.start()); }
        if (length < 0 || length > maximum) throw NativeTagParser.syntax("The expanded request exceeds its message-size ceiling.");
        var out = new ByteArrayOutputStream((int) length); previous = 0;
        for (Edit edit : edits) { out.write(raw, previous, edit.start() - previous); out.writeBytes(edit.value()); previous = edit.end(); }
        out.write(raw, previous, raw.length - previous); return out.toByteArray();
    }

    /**
     * Finds HTTP line/field boundaries using raw bytes; no URL helper sees unresolved template syntax.
     * @param raw Stable original request snapshot.
     * @return Immutable field offsets and lowercased header names.
     * @throws AuthenticationFailure If line framing or a marked unsupported header is invalid.
     */
    private static Layout layout(byte[] raw) throws AuthenticationFailure {
        int lineEnd = crlf(raw, 0), first = index(raw, (byte) ' ', 0, Math.max(0, lineEnd)), last = lastIndex(raw, (byte) ' ', 0, Math.max(0, lineEnd));
        if (lineEnd < 0 || first <= 0 || last <= first + 1 || !latin(raw, last + 1, lineEnd).startsWith("HTTP/")) throw NativeTagParser.syntax("The raw request line is invalid or a tag is outside the supported path/query location.");
        int at = lineEnd + 2; List<Header> headers = new ArrayList<>();
        while (at < raw.length) {
            int end = crlf(raw, at); if (end < 0 || end > NativeTagParser.MAX_TEXT_BYTES) throw NativeTagParser.syntax("The raw request headers are incomplete or oversized.");
            if (end == at) return new Layout(first + 1, last, end + 2, at, List.copyOf(headers));
            int colon = index(raw, (byte) ':', at, end);
            if (colon <= at || raw[at] == ' ' || raw[at] == '\t') throw NativeTagParser.syntax("The request contains an unnamed or folded header. Give each header a name and keep it on one line.");
            String name = latin(raw, at, colon).toLowerCase(Locale.ROOT); int value = colon + 1;
            while (value < end && (raw[value] == ' ' || raw[value] == '\t')) value++;
            headers.add(new Header(name, at, end, value)); at = end + 2;
        }
        throw NativeTagParser.syntax("The raw request has no complete header/body separator.");
    }

    /**
     * Reads one body-interpretation header, rejecting duplicate values before decoding a tagged body.
     *
     * @param raw Message bytes.
     * @param layout Header boundaries.
     * @param name Canonical header name.
     * @return Exact trimmed value, or null; duplicate interpretation headers are rejected.
     * @throws AuthenticationFailure On ambiguous duplicate values.
     */
    private static String header(byte[] raw, Layout layout, String name) throws AuthenticationFailure {
        String value = null; for (Header h : layout.headers()) if (h.name().equals(name)) { if (value != null) throw NativeTagParser.syntax("Duplicate body interpretation headers are ambiguous. Keep one declared content type/encoding."); value = latin(raw, h.valueStart(), h.end()).trim(); } return value;
    }
    /**
     * Creates an exact one-byte character view of an HTTP field without guessing a body charset.
     *
     * @param raw Message bytes.
     * @param start Inclusive offset.
     * @param end Exclusive offset.
     * @return Exact one-byte character view; no body charset is guessed.
     */
    private static String latin(byte[] raw, int start, int end) { return new String(raw, start, end - start, StandardCharsets.ISO_8859_1); }
    /**
     * Searches wire bytes for reserved native syntax without materializing an opaque body as text.
     *
     * @param raw Message bytes.
     * @param start Inclusive offset.
     * @param end Exclusive offset.
     * @return Whether reserved native-looking syntax occurs.
     */
    private static boolean contains(byte[] raw, int start, int end) { return NativeTagParser.contains(raw, start, end); }
    /**
     * Locates the next HTTP line boundary while preserving its original wire offsets.
     *
     * @param raw Message bytes.
     * @param at Search start.
     * @return First CRLF start, or -1.
     */
    private static int crlf(byte[] raw, int at) { for (int i = at; i + 1 < raw.length; i++) if (raw[i] == 13 && raw[i + 1] == 10) return i; return -1; }
    /**
     * Finds the first delimiter in a bounded source range without allocating a substring.
     *
     * @param raw Message bytes.
     * @param value Byte sought.
     * @param start Inclusive offset.
     * @param end Exclusive offset.
     * @return First match, or -1.
     */
    private static int index(byte[] raw, byte value, int start, int end) { for (int i = start; i < end; i++) if (raw[i] == value) return i; return -1; }
    /**
     * Finds the final request-line delimiter so wrapper literal spaces remain part of the target.
     *
     * @param raw Message bytes.
     * @param value Byte sought.
     * @param start Inclusive offset.
     * @param end Exclusive offset.
     * @return Last match, or -1.
     */
    private static int lastIndex(byte[] raw, byte value, int start, int end) { for (int i = end - 1; i >= start; i--) if (raw[i] == value) return i; return -1; }
    /**
     * Names validated aliases in a terminal request result without reproducing token or source text.
     *
     * @param alias Validated canonical alias.
     * @param cause Safe disposition.
     * @param problem Known issue.
     * @param recovery Concrete next action.
     * @return Actionable error without request/token data.
     */
    private static AuthenticationFailure aliasFailure(String alias, AuthenticationFailure.Cause cause, String problem, String recovery) { return new AuthenticationFailure(AuthenticationFailure.Phase.STEP, cause, "Journey alias " + alias + ": " + problem, recovery); }
}

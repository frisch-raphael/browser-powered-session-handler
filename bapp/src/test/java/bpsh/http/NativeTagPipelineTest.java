package bpsh.http;

import bpsh.Extension;
import bpsh.browser.AuthTrafficGuard;
import bpsh.config.Config;
import bpsh.config.JourneyRegistry;
import bpsh.credentials.AuthenticationResult;
import bpsh.credentials.CredentialUse;
import bpsh.diagnostics.Diagnostics;
import bpsh.model.AuthenticationFailure;
import bpsh.model.JourneyDefinition;
import bpsh.secrets.SecretStore;
import bpsh.session.AuthenticationCoordinator;
import bpsh.session.CoordinatorFixtures;
import bpsh.ui.AuthenticationTagMenu;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises complete raw messages with fake authentication, without claiming real-Burp URL handling. */
public class NativeTagPipelineTest {
    /** Shares a registry and bounded fake runner with actual parser/resolver code. */
    public static final class Fixture implements AutoCloseable {
        public final SecretStore secrets = new SecretStore();
        public final JourneyRegistry registry = new JourneyRegistry(secrets);
        public final CoordinatorFixtures.ManualRuntime clock = new CoordinatorFixtures.ManualRuntime();
        public final List<JourneyDefinition> definitions = List.of(CoordinatorFixtures.journey("employee"), CoordinatorFixtures.journey("admin"), CoordinatorFixtures.journey("url"));
        public final AuthenticationCoordinator coordinator;
        public final NativeTagResolver resolver;
        public final java.util.Map<String, String> values = new java.util.HashMap<>(Map.of("employee", "employee-token", "admin", "admin-token", "url", "url-token"));
        public int attempts;
        public String failedAlias;
        /** Publishes unique aliases and injects no network/browser implementation. */
        public Fixture() {
            CoordinatorFixtures.load(registry, definitions);
            coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                attempts++;
                if (entry.definition().canonicalAlias().equals(failedAlias)) throw CoordinatorFixtures.failure(AuthenticationFailure.Cause.AUTH_REJECTED);
                return new AuthenticationResult(entry.identity(), values.get(entry.definition().canonicalAlias()), clock.instant(), clock.nanos());
            }, entry -> null);
            resolver = new NativeTagResolver(registry, coordinator);
        }
        /** @param request Complete Latin-1 wire fixture. @return Detached complete message, after executing admitted workers. */
        public String resolve(String request) throws Exception {
            var operation = resolver.resolve(wire(request), registry.snapshot().resolve("admin"), false);
            while (!clock.workers.isEmpty()) clock.runWorker(); return new String(operation.future().join().commit(), StandardCharsets.ISO_8859_1);
        }
        /** Closes test-owned token and secret state. */
        @Override public void close() { coordinator.close(); secrets.close(); }
    }
    /** @param value Raw request fixture. @return Exact byte-preserving one-byte representation. */
    public static byte[] wire(String value) { return value.getBytes(StandardCharsets.ISO_8859_1); }
    /** @param value Header value fixture. @return Complete raw request preserving unusual casing and whitespace. */
    public static String header(String value) { return "GET /protected HTTP/1.1\r\nHost: app.example\r\nX-Retain:\t  untouched  \r\nAuthorization: " + value + "\r\n\r\n"; }
    /** @param operation Failing atomic operation. @return Safe typed cause. */
    public static AuthenticationFailure error(NativeTagResolver.Operation operation) {
        var error = assertThrows(CompletionException.class, () -> operation.future().join()); return assertInstanceOf(AuthenticationFailure.class, error.getCause());
    }

    public @Test void rawReferencesPreserveEveryOtherByteAndDoNotApplyAutomaticCredentials() throws Exception {
        try (var f = new Fixture()) {
            String raw = header("Bearer <@EMPLOYEE/>").replace("\r\n\r\n", "\r\nCookie: existing=keep\r\n\r\n");
            var operation = f.resolver.resolve(wire(raw), f.registry.snapshot().resolve("admin"), true); assertTrue(operation.tagsOnly()); f.clock.runWorker();
            var resolved = operation.future().join(); assertEquals(raw.replace("<@EMPLOYEE/>", "employee-token"), new String(resolved.commit(), StandardCharsets.ISO_8859_1));
            assertEquals(1, f.attempts); assertEquals(1, resolved.uses().size()); assertFalse(resolved.toString().contains("employee-token"));
        }
    }
    public @Test void wrappersEncodeWholeContentInsideOutAndSelfClosingWrapperNamesRemainAliases() throws Exception {
        try (var f = new Fixture()) {
            f.values.put("employee", "a b+/\"\\");
            String raw = "GET /path?token=<@url>Bearer <@employee/></@url> HTTP/1.1\r\nHost: app.example\r\n"
                    + "X-Form: <@form><@employee/></@form>\r\nX-Json: <@json><@employee/></@json>\r\n"
                    + "X-Nested: <@url><@url><@employee/></@url></@url>\r\nX-Alias: <@url/>\r\n\r\n";
            String output = f.resolve(raw);
            assertTrue(output.startsWith("GET /path?token=Bearer%20a%20b%2B%2F%22%5C HTTP/1.1\r\n"));
            assertTrue(output.contains("X-Form: a+b%2B%2F%22%5C\r\n")); assertTrue(output.contains("X-Json: a b+/\\\"\\\\\r\n"));
            assertTrue(output.contains("X-Nested: a%2520b%252B%252F%2522%255C\r\n")); assertTrue(output.contains("X-Alias: url-token\r\n")); assertEquals(2, f.attempts);
        }
    }
    public @Test void wrapperLiteralTextWorksWithoutStartingAnyAuthenticationAndTagOutputIsNeverReparsed() throws Exception {
        try (var f = new Fixture()) {
            assertTrue(f.resolve(header("<@url>ordinary text</@url>")).contains("Authorization: ordinary%20text")); assertEquals(0, f.attempts);
            f.values.put("employee", "<@admin/>");
            assertTrue(f.resolve(header("<@employee/>")).contains("Authorization: <@admin/>")); assertEquals(1, f.attempts);
        }
    }
    public @ParameterizedTest @ValueSource(strings = {"<@employee>", "<@employee />", "<@employee x=1/>", "<@BPSH:employee/>", "<@URL>hello</@URL>", "<@url>x</@form>", "</@url>", "<@employee", "<@bpsh />", "<@url><@employee/>"})
    void malformedNativeSourceFailsBeforeAnyCycleOrReplacement(String source) {
        try (var f = new Fixture()) {
            assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header(source)), null, false)); assertEquals(0, f.attempts); assertTrue(f.clock.workers.isEmpty());
        }
    }
    public @Test void unknownMixedReferenceFailsBeforeStartingTheValidJourney() {
        try (var f = new Fixture()) {
            var error = assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header("<@employee/> <@missing/>")), null, false));
            assertTrue(error.getMessage().contains("missing")); assertEquals(0, f.coordinator.capacity().waitingRequests()); assertTrue(f.clock.workers.isEmpty());
        }
    }
    public @Test void depthNodesAndReferenceCeilingsAreRequestWide() throws Exception {
        try (var f = new Fixture()) {
            String eight = "<@url>".repeat(8) + "x" + "</@url>".repeat(8); assertTrue(f.resolve(header(eight)).contains("Authorization: x"));
            assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header("<@url>" + eight + "</@url>")), null, false));
            String nodes = "<@employee/>".repeat(256); assertTrue(f.resolve(header(nodes)).contains("employee-token".repeat(256))); assertEquals(1, f.attempts);
            assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header(nodes + "<@employee/>")), null, false));
            String distinct = java.util.stream.IntStream.range(0, 17).mapToObj(i -> "<@journey" + i + "/>").collect(java.util.stream.Collectors.joining());
            assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header(distinct)), null, false));
        }
    }
    public @Test void textBodiesPreserveCharsetAndRebuildActualByteLength() throws Exception {
        for (String charset : List.of("UTF-8", "US-ASCII", "ISO-8859-1")) try (var f = new Fixture()) {
            String body = "{\"token\":\"<@employee/>\"}";
            String raw = "POST /resource HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/json; charset=" + charset + "\r\nContent-Length: " + body.length() + "\r\nX-Keep:  unchanged\r\n\r\n" + body;
            String output = f.resolve(raw); String expected = body.replace("<@employee/>", "employee-token");
            assertEquals(raw.replace("Content-Length: " + body.length(), "Content-Length: " + expected.length()).replace(body, expected), output);
        }
    }
    public @Test void utf8BodyUsesByteCountNotCharactersAndLatin1CannotSilentlyReplaceUnicode() throws Exception {
        try (var f = new Fixture()) {
            f.values.put("employee", "snow-\u96ea");
            String raw = "POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n<@employee/>";
            var operation = f.resolver.resolve(wire(raw), null, false); f.clock.runWorker(); byte[] output = operation.future().join().commit();
            assertTrue(new String(output, StandardCharsets.UTF_8).contains("Content-Length: 8\r\n")); assertTrue(new String(output, StandardCharsets.UTF_8).endsWith("snow-\u96ea"));
            var invalid = f.resolver.resolve(wire(header("<@employee/>")), null, false);
            assertEquals(AuthenticationFailure.Cause.CONFIGURATION, error(invalid).reason());
        }
    }
    public @ParameterizedTest @ValueSource(strings = {"application/octet-stream", "multipart/form-data; boundary=test", "text/plain; charset=UTF-16", "image/png"})
    void unsupportedBodyTypeReportsTheFormatRequirementWithoutAssumingARemedy(String contentType) {
        try (var f = new Fixture()) {
            var ex = assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire("POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: " + contentType + "\r\n\r\n<@employee/>"), null, false));
            assertTrue(ex.problem().contains("Content-Type")); assertEquals("", ex.recovery()); assertTrue(f.clock.workers.isEmpty());
        }
    }
    public @Test void compressedAndChunkedMarkedBodiesAndUnsupportedLocationsNeverAuthenticate() {
        try (var f = new Fixture()) {
            for (String raw : List.of("POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n\r\n<@employee/>",
                    "POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n<@employee/>",
                    "<@employee/> / HTTP/1.1\r\nHost: app.example\r\n\r\n", "GET http://<@employee/>/path HTTP/1.1\r\nHost: app.example\r\n\r\n",
                    "GET / HTTP/1.1\r\nHost: <@employee/>\r\n\r\n", "GET / HTTP/1.1\r\n<@employee/>: value\r\n\r\n"))
                assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(raw), null, false));
            assertTrue(f.clock.workers.isEmpty());
        }
    }
    public @Test void percentEncodedTargetNotationIsNotExecutedOrSilentlyLeakedAsLiteralNativeSource() {
        try (var f = new Fixture()) {
            for (String marker : List.of("%3C%40bpsh%3Aemployee%2F%3E", "<%40BPSH:employee/>", "%3c@bpsh:employee/>")) {
                byte[] raw = wire("GET /?token=" + marker + " HTTP/1.1\r\nHost: app.example\r\n\r\n");
                assertTrue(NativeTagResolver.tagged(raw)); var ex = assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(raw, null, false)); assertTrue(ex.getMessage().contains("raw"));
            }
            assertTrue(f.clock.workers.isEmpty());
        }
    }
    public @Test void invalidRawTargetAndHeaderControlsFailAtomicallyAfterAcquisition() throws Exception {
        try (var f = new Fixture()) {
            f.values.put("employee", "a b"); var invalid = f.resolver.resolve(wire("GET /?token=<@employee/> HTTP/1.1\r\nHost: app.example\r\n\r\n"), null, false);
            f.clock.runWorker(); assertEquals(AuthenticationFailure.Cause.CONFIGURATION, error(invalid).reason());
            assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire(header("<@url>text</@url>\tbad")), null, false));
        }
    }
    public @Test void oversizedTaggedTextAndExpandedMessagesFailButLargeUntaggedUploadsRemainUntouched() throws Exception {
        try (var f = new Fixture()) {
            String body = "x".repeat((1 << 20) + 1) + "<@employee/>";
            assertThrows(AuthenticationFailure.class, () -> f.resolver.resolve(wire("POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: text/plain\r\n\r\n" + body), null, false)); assertTrue(f.clock.workers.isEmpty());
            byte[] upload = wire("POST /upload HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/octet-stream\r\n\r\n" + "x".repeat(5 << 20));
            var untouched = f.resolver.resolve(upload, null, false); assertFalse(untouched.tagsOnly()); assertFalse(untouched.future().join().changed()); assertArrayEquals(upload, untouched.future().join().commit());
            f.values.put("employee", "a".repeat(65_536)); var expanded = f.resolver.resolve(wire(header("<@employee/>".repeat(65))), null, false); f.clock.runWorker();
            assertEquals(AuthenticationFailure.Cause.CONFIGURATION, error(expanded).reason());
        }
    }
    public @Test void lateGenerationAndVersionChangesPreventCommitAndReservationsAlwaysRelease() throws Exception {
        try (var f = new Fixture()) {
            var operation = f.resolver.resolve(wire(header("<@employee/> <@admin/>")), null, false); assertEquals(1, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); f.clock.runWorker(); var result = operation.future().join(); assertEquals(0, f.coordinator.capacity().waitingRequests());
            var used = result.uses().stream().filter(u -> u.identity().equals(f.registry.snapshot().resolve("employee").identity())).findFirst().orElseThrow();
            f.coordinator.invalidateVersion(used.identity(), used.version()); assertThrows(AuthenticationFailure.class, result::commit);
            var next = f.resolver.resolve(wire(header("<@employee/>")), null, false); next.close();
            assertEquals(AuthenticationFailure.Cause.CANCELLED, error(next).reason()); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    public @Test void ordinaryCookieInjectionReplacesNamedCookieOnceWithoutChangingOthersOrSharedState() throws Exception {
        try (var f = new Fixture()) {
            var old = f.definitions.getFirst(); var cookie = new JourneyDefinition(old.id(), old.displayName(), old.alias(), old.authenticationUrl(), false, old.steps(), old.browser(), old.extraction(),
                    JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.COOKIE, "session"))), old.cache(), null);
            CoordinatorFixtures.load(f.registry, List.of(cookie));
            String raw = "POST /upload HTTP/1.1\r\nHost: app.example\r\nCookie: other=a; session=old; keep=b; session=duplicate\r\nX-Keep: unchanged\r\n\r\nopaque body";
            var operation = f.resolver.resolve(wire(raw), f.registry.snapshot().resolve("employee"), true); f.clock.runWorker();
            assertFalse(operation.tagsOnly()); assertEquals(raw.replace(" session=old", "session=employee-token").replace("; session=duplicate", ""), new String(operation.future().join().commit(), StandardCharsets.ISO_8859_1));
        }
    }
    public @Test void failedMixedJourneyResolutionNeverReturnsPartialBytesAndReleasesAllReservations() throws Exception {
        try (var f = new Fixture()) {
            f.failedAlias = "admin"; byte[] original = wire(header("<@employee/> <@admin/>")); byte[] preserved = original.clone();
            var operation = f.resolver.resolve(original, f.registry.snapshot().resolve("employee"), true);
            f.clock.runWorker(); f.clock.runWorker(); var failure = error(operation);
            assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, failure.reason()); assertTrue(failure.getMessage().contains("Journey admin:"));
            assertEquals(f.registry.snapshot().resolve("admin").identity(), failure.journey()); assertFalse(failure.getMessage().contains("employee"));
            assertArrayEquals(preserved, original); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    public @Test void finiteAdmissionFailureLeavesBothOrdinaryAndTaggedSourceBytesUntouched() throws Exception {
        try (var f = new Fixture()) {
            f.coordinator.updateControls(CoordinatorFixtures.limits(1, null));
            var first = f.resolver.resolve(wire(header("<@employee/>")), null, false);
            for (boolean tagged : List.of(true, false)) {
                byte[] raw = wire(header(tagged ? "<@admin/>" : "existing")), original = raw.clone();
                var operation = f.resolver.resolve(raw, f.registry.snapshot().resolve("admin"), true);
                assertEquals(tagged, operation.tagsOnly()); assertEquals(AuthenticationFailure.Cause.CAPACITY, error(operation).reason()); assertArrayEquals(original, raw);
            }
            first.close(); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }

    /** Runs the actual production hooks against a small host factory double, never a Burp process. */
    public @org.junit.jupiter.api.Nested class ProductionHooks {
        /** Replaces only the SDK test JVM's factory and restores it after every hook test. */
        public final class Host implements AutoCloseable {
            public final burp.api.montoya.internal.MontoyaObjectFactory previous = burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;
            public final java.util.concurrent.atomic.AtomicReference<Config.Controls> controls = new java.util.concurrent.atomic.AtomicReference<>(Config.Controls.defaults());
            public final java.util.concurrent.atomic.AtomicInteger largeReads = new java.util.concurrent.atomic.AtomicInteger(), urls = new java.util.concurrent.atomic.AtomicInteger(), bodyAccesses = new java.util.concurrent.atomic.AtomicInteger();
            public final List<String> logs = new java.util.concurrent.CopyOnWriteArrayList<>();
            public final AuthTrafficGuard guard = new AuthTrafficGuard(); public final Diagnostics diagnostics = new Diagnostics(logs::add);
            public final SessionRecovery recovery; public final HttpSessionHandler handler;
            public boolean supportsDrop = true;
            /** @param fixture Shared deterministic coordinator and saved aliases. */
            public Host(Fixture fixture) { this(fixture, null); }
            public Host(Fixture fixture, HttpSessionHandler.ReplayTransport transport) {
                recovery = new SessionRecovery(fixture.coordinator, fixture.clock::nanos);
                burp.api.montoya.internal.ObjectFactoryLocator.FACTORY = stub(burp.api.montoya.internal.MontoyaObjectFactory.class, (method, args) -> factory(method, args));
                handler = new HttpSessionHandler(fixture.registry, fixture.resolver, guard, recovery, diagnostics, controls, transport);
            }
            /** @param type SDK interface. @param call Observed public API behavior. @return Small test-only dynamic implementation. */
            public <T> T stub(Class<T> type, java.util.function.BiFunction<java.lang.reflect.Method, Object[], Object> call) {
                return type.cast(java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, args) -> {
                    if (method.getName().equals("toString")) return "Montoya test double";
                    if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
                    if (method.getName().equals("equals")) return proxy == args[0];
                    return call.apply(method, args == null ? new Object[0] : args);
                }));
            }
            /** @param method SDK factory signature. @param a Factory arguments. @return Pure in-memory host object, with no network or installed app access. */
            public Object factory(java.lang.reflect.Method method, Object[] a) {
                var result = method.getReturnType(); String name = method.getName();
                if (result == burp.api.montoya.core.ByteArray.class) return bytes((byte[]) a[0]);
                if (result == burp.api.montoya.core.Annotations.class) return annotations(a.length > 0 && a[0] instanceof String s ? s : "", null);
                if (result == burp.api.montoya.http.message.requests.HttpRequest.class) {
                    Object raw = a[a.length - 1]; return request(raw instanceof String s ? s : new String(((burp.api.montoya.core.ByteArray) raw).getBytes(), StandardCharsets.ISO_8859_1), 99, false);
                }
                if (result == burp.api.montoya.http.handler.RequestToBeSentAction.class) {
                    if (!supportsDrop) throw new UnsupportedOperationException("Controlled unsupported host factory");
                    boolean full = a.length == 4; var action = full ? a[0] : burp.api.montoya.http.handler.RequestAction.CONTINUE;
                    Object request = full ? a[1] : a[0], notes = full ? a[3] : a.length > 1 ? a[1] : annotations("", null);
                    return stub(burp.api.montoya.http.handler.RequestToBeSentAction.class, (m, x) -> switch (m.getName()) { case "action" -> action; case "request" -> request; case "annotations" -> notes; default -> null; });
                }
                if (result == burp.api.montoya.http.handler.ResponseReceivedAction.class) return stub(burp.api.montoya.http.handler.ResponseReceivedAction.class, (m, x) -> m.getName().equals("response") ? a[0] : m.getName().equals("annotations") && a.length > 1 ? a[1] : null);
                if (result == burp.api.montoya.proxy.http.ProxyRequestReceivedAction.class || result == burp.api.montoya.proxy.http.ProxyResponseReceivedAction.class) {
                    Object action = a.length == 3 ? a[2] : java.lang.Enum.valueOf(burp.api.montoya.proxy.MessageReceivedAction.class, name.contains("DoNotIntercept") ? "DO_NOT_INTERCEPT" : "CONTINUE");
                    return stub(result, (m, x) -> switch (m.getName()) { case "action" -> action; case "request", "response" -> a[0]; case "annotations" -> a.length > 1 ? a[1] : annotations("", null); default -> null; });
                }
                throw new AssertionError("Unexpected SDK factory boundary: " + name);
            }
            /** @param value Exact wire bytes. @return Byte-array view whose large materialization is counted. */
            public burp.api.montoya.core.ByteArray bytes(byte[] value) {
                return stub(burp.api.montoya.core.ByteArray.class, (method, a) -> switch (method.getName()) {
                    case "length" -> value.length; case "getByte" -> value[(int) a[0]];
                    case "getBytes" -> { if (value.length > 65_536) largeReads.incrementAndGet(); yield value.clone(); }
                    case "subArray" -> bytes(Arrays.copyOfRange(value, (int) a[0], (int) a[1]));
                    case "indexOf" -> {
                        byte[] needle = a[0] instanceof String s ? wire(s) : ((burp.api.montoya.core.ByteArray) a[0]).getBytes();
                        boolean sensitive = a.length == 1 || (boolean) a[1]; int start = a.length > 2 ? (int) a[2] : 0, end = a.length > 3 ? (int) a[3] : value.length, found = -1;
                        outer: for (int i = start; i + needle.length <= end; i++) {
                            for (int j = 0; j < needle.length; j++) if ((sensitive ? value[i + j] : Character.toLowerCase((char) (value[i + j] & 255))) != (sensitive ? needle[j] : Character.toLowerCase((char) (needle[j] & 255)))) continue outer;
                            found = i; break;
                        }
                        yield found;
                    }
                    default -> throw new AssertionError("Unexpected byte access: " + method.getName());
                });
            }
            /** @param notes Existing/new notes. @param color Optional existing highlight. @return Annotation value preserving unrelated user notes. */
            public burp.api.montoya.core.Annotations annotations(String notes, burp.api.montoya.core.HighlightColor color) {
                var current = new java.util.concurrent.atomic.AtomicReference<>(notes);
                return stub(burp.api.montoya.core.Annotations.class, (m, a) -> switch (m.getName()) {
                    case "notes" -> current.get(); case "withNotes" -> annotations((String) a[0], color); case "withHighlightColor" -> annotations(current.get(), (burp.api.montoya.core.HighlightColor) a[0]);
                    case "setNotes" -> { current.set((String) a[0]); yield null; } case "highlightColor" -> color; default -> null;
                });
            }
            /** @param raw Complete raw request. @param id Host correlation ID. @param inScope Ordinary scope status. @return Global/Proxy-compatible request double. */
            public burp.api.montoya.http.handler.HttpRequestToBeSent request(String raw, int id, boolean inScope) {
                byte[] wire = wire(raw); int end = raw.indexOf("\r\n\r\n");
                var headers = new ArrayList<burp.api.montoya.http.message.HttpHeader>();
                for (String line : raw.substring(raw.indexOf("\r\n") + 2, end).split("\r\n")) {
                    int colon = line.indexOf(':'); if (colon < 0) continue; String name = line.substring(0, colon), value = line.substring(colon + 1).stripLeading();
                    headers.add(stub(burp.api.montoya.http.message.HttpHeader.class, (m, a) -> m.getName().equals("name") ? name : value));
                }
                var notes = annotations("existing user note", null);
                Object request = java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{burp.api.montoya.http.handler.HttpRequestToBeSent.class, burp.api.montoya.proxy.http.InterceptedRequest.class}, (proxy, m, args) -> {
                    Object[] a = args == null ? new Object[0] : args;
                    return switch (m.getName()) {
                        case "messageId" -> id; case "headers" -> headers; case "toByteArray" -> bytes(wire); case "annotations" -> notes; case "isInScope" -> inScope;
                        case "httpService" -> null; case "toolSource" -> stub(burp.api.montoya.core.ToolSource.class, (method, x) -> ToolTypeForTest());
                        case "headerValue" -> headers.stream().filter(h -> h.name().equalsIgnoreCase((String) a[0])).map(h -> h.value()).findFirst().orElse(null);
                        case "url" -> { urls.incrementAndGet(); if (raw.contains("<@bpsh")) throw new AssertionError("URL helpers must not receive literal native syntax"); yield "https://app.example/protected"; }
                        case "hasHeader" -> headers.stream().anyMatch(h -> h.name().equalsIgnoreCase((String) a[0]));
                        case "withAddedHeader" -> request(raw.substring(0, end) + "\r\n" + a[0] + ": " + a[1] + raw.substring(end), id, inScope);
                        case "withUpdatedHeader" -> {
                            String changed = raw.replaceAll("(?im)^" + java.util.regex.Pattern.quote((String) a[0]) + ":[^\\r\\n]*", a[0] + ": " + a[1]); yield request(changed, id, inScope);
                        }
                        case "toString" -> "Request test double";
                        default -> throw new AssertionError("Unexpected request boundary: " + m.getName());
                    };
                });
                return (burp.api.montoya.http.handler.HttpRequestToBeSent) request;
            }
            /** @return A tool which ordinary policy may exclude but explicit native tags still support. */
            private burp.api.montoya.core.ToolType ToolTypeForTest() { return burp.api.montoya.core.ToolType.EXTENSIONS; }
            /** @param id Correlated message ID. @param status Actual status. @param type MIME value. @param body Exact body bytes. @return Global/Proxy-compatible response. */
            public burp.api.montoya.http.handler.HttpResponseReceived response(int id, short status, String type, byte[] body) {
                return (burp.api.montoya.http.handler.HttpResponseReceived) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{burp.api.montoya.http.handler.HttpResponseReceived.class, burp.api.montoya.proxy.http.InterceptedResponse.class}, (proxy, m, a) -> switch (m.getName()) {
                    case "messageId" -> id; case "statusCode" -> status; case "toByteArray" -> bytes(body); case "bodyOffset" -> 0;
                    case "body" -> { bodyAccesses.incrementAndGet(); yield bytes(body); } case "annotations" -> annotations("", null);
                    case "headerValue" -> ((String) a[0]).equalsIgnoreCase("Content-Type") ? type : null;
                    case "bodyToString" -> throw new AssertionError("Response body must not be materialized as text before guards");
                    case "toString" -> "Response test double"; default -> null;
                });
            }
            /** Restores the SDK test factory and closes only this test's hook services. */
            @Override public void close() { handler.close(); recovery.close(); guard.close(); diagnostics.close(); burp.api.montoya.internal.ObjectFactoryLocator.FACTORY = previous; }
        }

        /** @param f Deterministic acquisition fixture. @param action Blocking host callback. @return Completed action after one admitted worker executes. */
        public <T> T callback(Fixture f, java.util.concurrent.Callable<T> action) throws Exception {
            var thread = java.util.concurrent.Executors.newSingleThreadExecutor();
            try {
                var result = thread.submit(action); long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
                while (!result.isDone() && deadline - System.nanoTime() > 0) { if (!f.clock.workers.isEmpty()) f.clock.runWorker(); else Thread.sleep(1); }
                return result.get(5, java.util.concurrent.TimeUnit.SECONDS);
            } finally { thread.shutdownNow(); }
        }
        public @Test void explicitGlobalHookResolvesOutOfScopeWithAutomaticDisabledBeforeAnyUrlHelper() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                String raw = header("Bearer <@employee/>"); var request = host.request(raw, 10, false);
                var result = callback(f, () -> host.handler.handleHttpRequestToBeSent(request));
                assertEquals(burp.api.montoya.http.handler.RequestAction.CONTINUE, result.action());
                assertArrayEquals(wire(raw.replace("<@employee/>", "employee-token")), result.request().toByteArray().getBytes()); assertEquals(0, host.urls.get());
            }
        }
        public @Test void requestContextMenuInsertsLiteralTagsAndRejectsStaleEditorOrJourney() {
            try (var f = new Fixture(); var host = new Host(f)) {
                String raw = header("Existing"); int caret = raw.indexOf("Existing");
                var current = new java.util.concurrent.atomic.AtomicReference<burp.api.montoya.http.message.requests.HttpRequest>(host.request(raw, 8, false));
                var writes = new java.util.concurrent.atomic.AtomicInteger(); var reports = new ArrayList<String>();
                var pair = host.stub(burp.api.montoya.http.message.HttpRequestResponse.class, (m, a) -> m.getName().equals("request") ? current.get() : null);
                var editor = host.stub(burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class, (m, a) -> switch (m.getName()) {
                    case "selectionContext" -> burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
                    case "selectionOffsets" -> java.util.Optional.empty(); case "caretPosition" -> caret; case "requestResponse" -> pair;
                    case "setRequest" -> { current.set((burp.api.montoya.http.message.requests.HttpRequest) a[0]); writes.incrementAndGet(); yield null; }
                    default -> null;
                });
                var event = host.stub(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (m, a) -> m.getName().equals("messageEditorRequestResponse") ? java.util.Optional.of(editor) : null);
                var provider = new AuthenticationTagMenu(f.registry, reports::add);
                var root = (javax.swing.JMenu) provider.provideMenuItems(event).getFirst();
                var employee = java.util.stream.IntStream.range(0, root.getItemCount()).mapToObj(root::getItem).filter(item -> item.getText().equals("employee")).map(javax.swing.JMenu.class::cast).findFirst().orElseThrow();
                employee.getItem(1).doClick();
                assertEquals(raw.substring(0, caret) + "<@url><@employee/></@url>" + raw.substring(caret), new String(current.get().toByteArray().getBytes(), StandardCharsets.ISO_8859_1));
                assertEquals(1, writes.get()); assertTrue(f.clock.workers.isEmpty());
                employee.getItem(0).doClick(); assertEquals(1, writes.get()); assertTrue(reports.getLast().contains("request changed"));
                CoordinatorFixtures.load(f.registry, List.of()); employee.getItem(0).doClick(); assertEquals(1, writes.get()); assertTrue(reports.getLast().contains("journey changed"));
            }
        }
        public @Test void orderedAutomaticRulesRespectActivationToolsScopesOrderAndUsedExpiration() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                var employee = f.registry.snapshot().resolve("employee"); var admin = f.registry.snapshot().resolve("admin"); var disabled = f.registry.snapshot().resolve("url");
                var first = new Config.AutomaticRule(true, new Config.JourneySelection(employee.identity().scope(), employee.identity().journeyId()), Config.UrlMode.BURP_SCOPE, null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null));
                var second = new Config.AutomaticRule(true, new Config.JourneySelection(admin.identity().scope(), admin.identity().journeyId()), Config.UrlMode.SINGLE_URL, java.net.URI.create("https://app.example/"), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 403, null));
                var off = new Config.AutomaticRule(false, new Config.JourneySelection(disabled.identity().scope(), disabled.identity().journeyId()), Config.UrlMode.ALL_REQUESTS, null, first.recovery());
                var defaults = Config.Controls.defaults();
                host.controls.set(new Config.Controls(true, List.of(first, off, second), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                var sent = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(header("stale"), 501, true)));
                assertTrue(new String(sent.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1).contains("Bearer admin-token")); assertEquals(2, f.attempts);
                host.handler.handleHttpResponseReceived(host.response(501, (short) 401, null, new byte[0])); assertNotNull(f.coordinator.peek(admin.identity())); assertNotNull(f.coordinator.peek(employee.identity()));
                host.controls.set(new Config.Controls(true, List.of(second, first), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                sent = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(header("stale"), 502, true)));
                assertTrue(new String(sent.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1).contains("Bearer employee-token")); assertEquals(2, f.attempts);
                sent = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(header("stale"), 503, false)));
                assertTrue(new String(sent.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1).contains("Bearer admin-token"));
                host.handler.handleHttpResponseReceived(host.response(503, (short) 403, null, new byte[0])); assertNull(f.coordinator.peek(admin.identity())); assertNotNull(f.coordinator.peek(employee.identity()));
                host.controls.set(new Config.Controls(true, List.of(first, second), List.of(burp.api.montoya.core.ToolType.REPEATER), 60_000, 60_000, 300_000, null, null));
                var excluded = host.request(header("stale"), 504, true); assertSame(excluded, host.handler.handleHttpRequestToBeSent(excluded).request()); assertEquals(2, f.attempts);
                host.controls.set(new Config.Controls(false, List.of(first, second), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                assertSame(excluded, host.handler.handleHttpRequestToBeSent(excluded).request());
                var missing = new Config.AutomaticRule(true, new Config.JourneySelection(JourneyDefinition.Scope.PROJECT, java.util.UUID.randomUUID()), Config.UrlMode.ALL_REQUESTS, null, first.recovery());
                host.controls.set(new Config.Controls(true, List.of(first, missing), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                var rejected = host.handler.handleHttpRequestToBeSent(excluded); assertSame(excluded, rejected.request()); assertTrue(rejected.annotations().notes().contains("unavailable")); assertEquals(1, f.clock.workers.size(), "the prior observed loss owns the only recovery; missing identities start no extra work");
            }
        }
        public @Test void actualHookDropsTaggedFailureAndPreservesOrdinaryFailureBytesWithWarning() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                f.failedAlias = "employee"; var tagged = host.request(header("<@employee/>"), 1, false);
                var stopped = callback(f, () -> host.handler.handleHttpRequestToBeSent(tagged)); assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, stopped.action());
                assertTrue(stopped.annotations().notes().contains("not sent")); assertTrue(stopped.annotations().notes().contains("employee")); assertTrue(stopped.annotations().notes().contains("existing user note"));
                var d = Config.Controls.defaults(); var entry = f.registry.snapshot().resolve("employee");
                host.controls.set(new Config.Controls(true, List.of(new Config.AutomaticRule(true, new Config.JourneySelection(entry.identity().scope(), entry.identity().journeyId()), Config.UrlMode.ALL_REQUESTS, null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), d.tools(), 60_000, 60_000, 300_000, null, null));
                var ordinary = host.request(header("Existing"), 2, true); var unchanged = host.handler.handleHttpRequestToBeSent(ordinary);
                assertSame(ordinary, unchanged.request()); assertTrue(unchanged.annotations().notes().contains("unchanged request was sent")); assertFalse(host.logs.isEmpty());
            }
        }
        public @Test void proxyOwnedCarrierIsRetainedUntilGlobalSendAndResponseLedgersRemainIndependent() throws Exception {
            try (var f = new Fixture(); var host = new Host(f); var lease = host.guard.begin()) {
                var entry = f.registry.snapshot().resolve("employee"); var defaults = Config.Controls.defaults();
                var rule = new Config.AutomaticRule(true, new Config.JourneySelection(entry.identity().scope(), entry.identity().journeyId()),
                        Config.UrlMode.ALL_REQUESTS, null, new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null));
                host.controls.set(new Config.Controls(true, List.of(rule), defaults.tools(), 60_000, 60_000, 300_000, null, null));
                String raw = header("existing").replace("\r\n\r\n", "\r\nUser-Agent: " + lease.decorate("Actual full agent") + "\r\n\r\n"); var request = host.request(raw, 77, false);
                var proxy = host.handler.handleRequestReceived((burp.api.montoya.proxy.http.InterceptedRequest) request);
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.DO_NOT_INTERCEPT, proxy.action());
                var global = callback(f, () -> host.handler.handleHttpRequestToBeSent(request));
                assertEquals("Actual full agent", global.request().headerValue("User-Agent")); assertTrue(f.clock.workers.isEmpty());
                var response = host.response(77, (short) 401, "application/octet-stream", new byte[0]);
                assertSame(response, host.handler.handleHttpResponseReceived(response).response());
                assertEquals(0, f.attempts, "Owned login traffic must not authenticate itself even when its URL and 401 match automatic handling.");
                assertTrue(f.clock.workers.isEmpty()); assertEquals(0, f.coordinator.capacity().waitingRequests());
                var proxyResponse = host.handler.handleResponseReceived((burp.api.montoya.proxy.http.InterceptedResponse) response);
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.DO_NOT_INTERCEPT, proxyResponse.action());
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.CONTINUE, host.handler.handleResponseReceived((burp.api.montoya.proxy.http.InterceptedResponse) response).action());
            }
        }
        public @Test void staleAndNestedOwnedRequestsStopWithoutAcquisitionWhileNormalProxyTrafficKeepsUserRules() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                String marked; try (var lease = host.guard.begin()) { marked = lease.decorate("Agent"); }
                var stale = host.request(header("existing").replace("\r\n\r\n", "\r\nUser-Agent: " + marked + "\r\n\r\n"), 1, false);
                assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, host.handler.handleHttpRequestToBeSent(stale).action());
                try (var lease = host.guard.begin()) {
                    var nested = host.request(header("<@employee/>").replace("\r\n\r\n", "\r\nUser-Agent: " + lease.decorate("Agent") + "\r\n\r\n"), 2, false);
                    assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, host.handler.handleHttpRequestToBeSent(nested).action());
                }
                var normal = host.request(header("existing"), 3, false);
                assertEquals(burp.api.montoya.proxy.MessageReceivedAction.CONTINUE, host.handler.handleRequestReceived((burp.api.montoya.proxy.http.InterceptedRequest) normal).action()); assertTrue(f.clock.workers.isEmpty());
            }
        }
        public @ParameterizedTest @org.junit.jupiter.params.provider.CsvSource({"false,true", "true,true", "false,false", "true,false"})
        void actualReplaySendTraversesTheHooksOnceAndRejectedReplacementPausesBothRequestPolicies(boolean reject, boolean hasAgent) throws Exception {
            try (var f = new Fixture()) {
                var hostRef = new java.util.concurrent.atomic.AtomicReference<Host>();
                var deliveryFailure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
                var delivered = new java.util.concurrent.CountDownLatch(1); var sends = new java.util.concurrent.atomic.AtomicInteger();
                try (var host = new Host(f, (marked, timeout) -> {
                    try {
                        assertEquals(60_000, timeout); var h = hostRef.get(); sends.incrementAndGet();
                        String raw = new String(marked.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
                        assertTrue(raw.contains("BPSHAuth/"));
                        var outgoing = h.handler.handleHttpRequestToBeSent(h.request(raw, 900, true));
                        assertEquals(burp.api.montoya.http.handler.RequestAction.CONTINUE, outgoing.action());
                        String wire = new String(outgoing.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
                        assertFalse(wire.contains("BPSHAuth/")); assertTrue(wire.contains("Bearer replacement-token"));
                        assertTrue(wire.endsWith("body=data")); assertTrue(wire.contains("Cookie: unrelated=keep")); assertEquals(hasAgent, wire.contains("User-Agent: application-agent")); assertEquals(hasAgent, wire.contains("User-Agent:"));
                        assertTrue(outgoing.annotations().notes().contains("request 50"));
                        var response = h.response(900, (short) (reject ? 401 : 200), null, new byte[0]);
                        var returned = h.handler.handleHttpResponseReceived(response);
                        assertSame(response, returned.response());
                        assertTrue(returned.annotations().notes().contains("request 50"), "The response callback must restore correlation even with fresh host annotations.");
                    } catch (Throwable failure) { deliveryFailure.set(failure); }
                    finally { delivered.countDown(); }
                })) {
                    hostRef.set(host); var entry = f.registry.snapshot().resolve("employee");
                    var rule = new Config.AutomaticRule(true, new Config.JourneySelection(entry.identity().scope(), entry.identity().journeyId()), Config.UrlMode.ALL_REQUESTS, null,
                            new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null));
                    host.controls.set(new Config.Controls(true, List.of(rule), Config.Controls.defaults().tools(), 60_000, 60_000, 300_000, null, null));
                    f.coordinator.acquire(List.of(entry)); f.clock.runWorker();
                    String raw = "POST /protected HTTP/1.1\r\nHost: app.example\r\n" + (hasAgent ? "User-Agent: application-agent\r\n" : "") + "Authorization: Bearer stale\r\nCookie: unrelated=keep\r\nContent-Length: 9\r\n\r\nbody=data";
                    host.handler.handleHttpRequestToBeSent(host.request(raw, 50, true));
                    var original = host.response(50, (short) 401, null, new byte[0]);
                    var originalOutcome = host.handler.handleHttpResponseReceived(original); assertSame(original, originalOutcome.response());
                    String persistedOriginalNotes = originalOutcome.annotations().notes();
                    assertTrue(persistedOriginalNotes.contains("request 50"), "Original correlation must exist before the host copies the callback result.");
                    assertEquals(0, sends.get()); f.values.put("employee", "replacement-token"); f.clock.runWorker();
                    assertTrue(delivered.await(5, java.util.concurrent.TimeUnit.SECONDS)); assertNull(deliveryFailure.get());
                    assertEquals(1, sends.get()); assertEquals(2, f.attempts); assertTrue(originalOutcome.annotations().notes().contains("request 900"));
                    host.handler.handleHttpResponseReceived(original); assertEquals(1, sends.get());
                    if (reject) {
                        assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(entry.identity()).phase());
                        f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty());
                        var ordinary = host.request(raw, 51, true); var forwarded = host.handler.handleHttpRequestToBeSent(ordinary);
                        assertSame(ordinary, forwarded.request()); assertTrue(forwarded.annotations().notes().contains("paused"));
                        var tagged = host.handler.handleHttpRequestToBeSent(host.request(raw.replace("Bearer stale", "Bearer <@employee/>"), 52, true));
                        assertEquals(burp.api.montoya.http.handler.RequestAction.DROP, tagged.action()); assertTrue(f.clock.workers.isEmpty());
                        var healthy = callback(f, () -> host.handler.handleHttpRequestToBeSent(host.request(raw.replace("Bearer stale", "Bearer <@admin/>"), 53, true)));
                        assertEquals(burp.api.montoya.http.handler.RequestAction.CONTINUE, healthy.action());
                    } else assertTrue(f.coordinator.status(entry.identity()).acceptedUse());
                }
            }
        }

        public @Test void actualHostByteScanningSkipsLargeUntaggedUploadsAndStatusRecoveryNeverReadsLargeBodies() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                var upload = host.request(header("existing") + "x".repeat(5 << 20), 1, false);
                assertSame(upload, host.handler.handleHttpRequestToBeSent(upload).request()); assertEquals(0, host.largeReads.get());
                f.coordinator.acquire(List.of(f.registry.snapshot().resolve("employee"))); f.clock.runWorker(); var token = f.coordinator.peek(f.registry.snapshot().resolve("employee").identity());
                host.controls.set(new Config.Controls(true, List.of(), Config.Controls.defaults().tools(), 60_000, 60_000, 300_000, null, null));
                host.recovery.record(2, List.of(new CredentialUse(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null))), false);
                host.handler.handleHttpResponseReceived(host.response(2, (short) 401, "application/octet-stream", new byte[5 << 20])); assertNull(f.coordinator.peek(token.identity())); assertEquals(0, host.largeReads.get()); assertEquals(0, host.bodyAccesses.get());
            }
        }
        public @Test void unsupportedHostReportsMinimumRequirementsBeforeRegisteringAnyAuthenticationHook() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                host.supportsDrop = false; var tabs = new java.util.concurrent.atomic.AtomicInteger();
                var logger = host.stub(burp.api.montoya.logging.Logging.class, (m, a) -> { if (a.length > 0 && a[0] instanceof String text) host.logs.add(text); return null; });
                var ui = host.stub(burp.api.montoya.ui.UserInterface.class, (m, a) -> { if (m.getName().equals("registerSuiteTab")) tabs.incrementAndGet(); else throw new AssertionError("Unexpected unsupported-host UI action"); return null; });
                var extension = host.stub(burp.api.montoya.extension.Extension.class, (m, a) -> { assertEquals("setName", m.getName()); return null; });
                var api = host.stub(burp.api.montoya.MontoyaApi.class, (m, a) -> switch (m.getName()) { case "extension" -> extension; case "logging" -> logger; case "userInterface" -> ui; default -> throw new AssertionError("Unsupported host must not register or compose native authentication services"); });
                new Extension().initialize(api); javax.swing.SwingUtilities.invokeAndWait(() -> {});
                assertEquals(1, tabs.get()); assertTrue(host.logs.stream().anyMatch(s -> s.contains("no authentication hooks were registered"))); assertTrue(f.clock.workers.isEmpty());
            }
        }
        public @Test void attributedOversizedRegexBodyIsSkippedBeforeFetchingHostBodyBytes() throws Exception {
            try (var f = new Fixture(); var host = new Host(f)) {
                var entry = f.registry.snapshot().resolve("employee"); f.coordinator.acquire(List.of(entry)); f.clock.runWorker(); var token = f.coordinator.peek(entry.identity());
                host.recovery.record(1, List.of(new CredentialUse(token.identity(), token.version(), new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.REGEX, null, "sign in"))), false);
                host.handler.handleHttpResponseReceived(host.response(1, (short) 200, "text/html", new byte[65_537]));
                assertNotNull(f.coordinator.peek(token.identity())); assertEquals(0, host.largeReads.get()); assertEquals(0, host.bodyAccesses.get());
            }
        }
    }
}

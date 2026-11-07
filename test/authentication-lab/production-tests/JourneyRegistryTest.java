import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class JourneyRegistryTest {
    static final UUID JOURNEY = UUID.fromString("22222222-2222-4222-8222-222222222222");
    static final UUID STEP = UUID.fromString("33333333-3333-4333-8333-333333333333");
    static final ObjectMapper JSON = new ObjectMapper();
    static String fixture(ConfigManager.DocumentKind kind, boolean remembered, boolean secret) {
        return """
            {"schemaVersion":1,"kind":"%s","revision":"11111111-1111-4111-8111-111111111111",
             "journeys":[{"id":"22222222-2222-4222-8222-222222222222","displayName":"Employee","alias":"employee",
               "authenticationUrl":"https://login.example/login","rememberSecrets":%s,
               "steps":[{"id":"33333333-3333-4333-8333-333333333333","type":"secure_input","selector":"#password"}],
               "browser":{},"extraction":{"type":"json_path","responseOrigin":"https://login.example",
               "pathSubstring":"/token","jsonPath":"data.tokens[0].value"},"injection":{"type":"per_token","tokens":[{"type":"bearer"}]},
               "cache":{}%s}],"retiredAliases":[]%s}
            """.formatted(kind.wire(), remembered, secret ? ",\"secrets\":{\"stepValues\":{\"" + STEP + "\":\"EXAMPLE_SECRET\"}}" : "",
                kind == ConfigManager.DocumentKind.PROJECT ? ",\"controls\":{}" : "");
    }
    static ConfigManager.NativeDocument document(ConfigManager.DocumentKind kind) {
        return ConfigManager.parseNative(fixture(kind, false, false), kind);
    }
    static JourneyDefinition changed(JourneyDefinition j, String alias, String display) {
        return new JourneyDefinition(j.id(), display, alias, j.authenticationUrl(), j.rememberSecrets(), j.steps(), j.browser(),
                j.extraction(), j.injection(), j.cache(), j.mtls());
    }
    static ConfigManager.NativeDocument definitions(ConfigManager.NativeDocument d, List<JourneyDefinition> journeys) {
        return new ConfigManager.NativeDocument(d.kind(), d.revision(), journeys, d.retiredAliases(), d.controls(), Map.of());
    }
    static String edit(String json, String pointer, String field, Object value) throws Exception {
        JsonNode root = JSON.readTree(json); ObjectNode target = (ObjectNode) root.at(pointer);
        target.set(field, JSON.valueToTree(value)); return JSON.writeValueAsString(root);
    }

    @Test void nativeDefaultsAndAllEnvelopeRoundTrips() throws Exception {
        long began=System.nanoTime();boolean definitionsMatch=true,revisionsMatch=true,controlsMatch=true;var kinds=new ArrayList<String>();
        for (ConfigManager.DocumentKind kind : ConfigManager.DocumentKind.values()) {
            try (var d = document(kind); var roundTrip = ConfigManager.parseNative(ConfigManager.nativeToJson(d), kind)) {
                assertEquals(d.journeys(), roundTrip.journeys()); assertEquals(d.revision(), roundTrip.revision());
                kinds.add(kind.name());definitionsMatch&=d.journeys().equals(roundTrip.journeys());revisionsMatch&=d.revision().equals(roundTrip.revision());controlsMatch&=java.util.Objects.equals(d.controls(),roundTrip.controls());
                var j = d.journeys().getFirst(); assertEquals(1800, j.cache().maxAgeSeconds()); assertFalse(j.browser().headless());
                assertEquals(30_000, j.browser().navigationTimeoutMs()); assertEquals(3000, j.browser().tokenWaitTimeoutMs());
                assertNull(j.mtls());
                if (kind == ConfigManager.DocumentKind.PROJECT) {
                    assertNull(d.controls().maxWaitingRequestsGlobal()); assertNull(d.controls().maxWaitingRequestsPerJourney());
                    assertEquals(Config.Controls.defaults(), d.controls());
                } else assertNull(d.controls());
            }
        }
        var observed=Map.<String,Object>of("kinds",kinds,"definitionsMatch",definitionsMatch,"revisionsMatch",revisionsMatch,"controlsMatch",controlsMatch);
        for(String variant:List.of("project-roundtrip","export-roundtrip"))configurationObservation("CORE.storage."+variant,observed,began);
    }
    @ParameterizedTest @ValueSource(strings = {
        "{\"type\":\"click\",\"selector\":\"#submit\"}", "{\"type\":\"input\",\"selector\":\"#name\",\"value\":\"\"}",
        "{\"type\":\"secure_input\",\"selector\":\"#pin\"}", "{\"type\":\"wait_load_state\"}",
        "{\"type\":\"wait_load_state\",\"state\":\"networkidle\"}", "{\"type\":\"wait_url\",\"urlPattern\":\"**/home\"}",
        "{\"type\":\"wait_selector\",\"selector\":\"#done\"}", "{\"type\":\"wait_time\",\"durationMs\":0}",
        "{\"type\":\"wait_selector\",\"selector\":\"#spinner\",\"state\":\"hidden\"}",
        "{\"type\":\"wait_selector\",\"selector\":\"#done\",\"state\":\"attached\"}",
        "{\"type\":\"wait_selector\",\"selector\":\"#spinner\",\"state\":\"detached\"}",
        "{\"type\":\"wait_url\",\"urlPattern\":\"https://app.example/home\",\"match\":\"exact\"}",
        "{\"type\":\"wait_url\",\"urlPattern\":\"**/home\",\"match\":\"glob\"}",
        "{\"type\":\"wait_time\",\"durationMs\":300000}" })
    void everyStepModeRoundTrips(String stepJson) throws Exception {
        ObjectNode step = (ObjectNode) JSON.readTree(stepJson); step.put("id", STEP.toString());
        String json = edit(fixture(ConfigManager.DocumentKind.EXPORT, false, false), "/journeys/0", "steps", List.of(step));
        try (var d = ConfigManager.parseNative(json, ConfigManager.DocumentKind.EXPORT);
             var next = ConfigManager.parseNative(ConfigManager.nativeToJson(d), ConfigManager.DocumentKind.EXPORT)) {
            assertEquals(d.journeys().getFirst().steps(), next.journeys().getFirst().steps());
        }
    }
    @Test void cookieRegexMtlsAndProxyRoundTrip() throws Exception {
        ObjectNode root = (ObjectNode) JSON.readTree(fixture(ConfigManager.DocumentKind.LIBRARY, true, false));
        ObjectNode j = (ObjectNode) root.at("/journeys/0");
        j.set("extraction", JSON.readTree("""
            {"type":"cookie","originUrl":"https://app.example/path","name":"SESSION","domain":null,"path":"/"}
            """));
        j.set("injection", JSON.readTree("{\"type\":\"per_token\",\"tokens\":[]}"));
        ((ObjectNode) j.get("browser")).set("proxy", JSON.readTree("{\"url\":\"http://LOCALHOST:80/\"}"));
        j.set("mtls", JSON.readTree("""
            {"modulePath":"C:\\Windows\\vendor.dll","certificateSha256":"%s",
             "origins":["https://APP.example:443/"],"trustedCaBundlePath":"/opt/ca.pem"}
            """.formatted("a".repeat(64)).replace("C:\\Windows\\vendor.dll", "C:/Windows/vendor.dll")));
        j.set("secrets", JSON.readTree("{\"mtlsPin\":\"example-pin\"}"));
        try (var d = ConfigManager.parseNative(root.toString(), ConfigManager.DocumentKind.LIBRARY);
             var next = ConfigManager.parseNative(ConfigManager.nativeToJson(d), ConfigManager.DocumentKind.LIBRARY)) {
            assertEquals(d.journeys(), next.journeys()); assertEquals(URI.create("https://app.example"), next.journeys().getFirst().mtls().origins().getFirst());
            assertEquals(new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX, 0), next.journeys().getFirst().mtls().slot());
            assertArrayEquals("example-pin".toCharArray(), next.secrets().get(JOURNEY).pin());
            assertEquals(URI.create("http://localhost"), next.journeys().getFirst().browser().proxy().url());
        }
    }
    @ParameterizedTest @ValueSource(strings = {"$", "data..token", "data[*]", "data[01]", "data.01", "data[2147483648]", "data.[0]", "[0].", "data['key']"})
    void rejectsUnsupportedJsonPaths(String path) { assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.validateJsonPath(path)); }
    @ParameterizedTest @ValueSource(strings = {"access_token", "data.tokens[0].value", "data.tokens.0.value", "[0].token", "0", "data[2147483647]"})
    void acceptsOnlyTheSpecifiedPathGrammar(String path) { assertDoesNotThrow(() -> ConfigManager.validateJsonPath(path)); }
    @Test void longJsonPathsDoNotUseRecursiveRegexMatching() {
        assertDoesNotThrow(() -> ConfigManager.validateJsonPath("data.".repeat(10_000) + "value"));
    }

    @ParameterizedTest @ValueSource(strings = {
        "{\"type\":\"secure_input\",\"selector\":\"#pin\",\"value\":\"DO_NOT_LEAK\"}",
        "{\"type\":\"wait_time\",\"durationMs\":0.5}", "{\"type\":\"wait_time\",\"durationMs\":\"100\"}",
        "{\"type\":\"wait_time\",\"durationMs\":-1}", "{\"type\":\"click\",\"selector\":\"\"}",
        "{\"type\":\"input\",\"selector\":\"#name\",\"value\":null}", "{\"type\":\"wait_load_state\",\"state\":null}",
        "{\"type\":\"wait_url\",\"value\":\"**/done\"}" })
    void rejectsInvalidStepShapesWithoutLeakingValues(String stepJson) throws Exception {
        ObjectNode step = (ObjectNode) JSON.readTree(stepJson); step.put("id", STEP.toString());
        String json = edit(fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "steps", List.of(step));
        var ex = assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(json, ConfigManager.DocumentKind.PROJECT));
        assertFalse(ex.getMessage().contains("DO_NOT_LEAK")); assertNull(ex.getCause());
    }
    @Test void strictParsingRejectsDuplicateUnknownVersionTypeAndWrongKind() throws Exception {
        String json = fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        List<String> invalid = List.of(json.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"),
                json + " {}", edit(json, "", "DO_NOT_LEAK", "DO_NOT_LEAK"), edit(json, "", "schemaVersion", 2),
                edit(json, "", "schemaVersion", "1"), edit(json, "/controls", "enabled", 1),
                edit(json, "/journeys/0", "rememberSecrets", null), edit(json, "", "revision", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
                edit(json, "/journeys/0/cache", "pattern", "DO_NOT_LEAK"));
        for (String bad : invalid) {
            var ex = assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(bad, ConfigManager.DocumentKind.PROJECT), bad);
            assertFalse(ex.getMessage().contains("DO_NOT_LEAK"));
        }
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(json, ConfigManager.DocumentKind.LIBRARY));
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(edit(json, "/controls", "tools", List.of("PROXY", "PROXY")), ConfigManager.DocumentKind.PROJECT));
    }
    @Test void deadlinesAndIndependentUnlimitedLimits() throws Exception {
        String base = fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        String valid = edit(edit(base, "/controls", "maxWaitingRequestsGlobal", 1), "/controls", "maxWaitingRequestsPerJourney", Integer.MAX_VALUE);
        try (var d = ConfigManager.parseNative(valid, ConfigManager.DocumentKind.PROJECT)) {
            assertEquals(1, d.controls().maxWaitingRequestsGlobal()); assertEquals(Integer.MAX_VALUE, d.controls().maxWaitingRequestsPerJourney());
        }
        for (var field : List.of("maxWaitingRequestsGlobal", "maxWaitingRequestsPerJourney"))
            for (Object value : List.of(0, -1, 2147483648L, 1.5, "1")) {
                String bad = edit(base, "/controls", field, value);
                assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(bad, ConfigManager.DocumentKind.PROJECT));
            }
        for (var field : List.of("requestWaitTimeoutMs", "attemptTimeoutMs", "cycleTimeoutMs")) {
            String bad = edit(base, "/controls", field, 999);
            assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(bad, ConfigManager.DocumentKind.PROJECT));
        }
        String invalidCycle = edit(base, "/controls", "cycleTimeoutMs", 1000);
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(invalidCycle, ConfigManager.DocumentKind.PROJECT));
        String shortCaller = edit(base, "/controls", "requestWaitTimeoutMs", 1000);
        assertDoesNotThrow(() -> { try (var ignored = ConfigManager.parseNative(shortCaller, ConfigManager.DocumentKind.PROJECT)) {} });
    }
    @Test void secretPolicyIsIndependentForManagedAndExportDocuments() {
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(fixture(ConfigManager.DocumentKind.PROJECT, false, true), ConfigManager.DocumentKind.PROJECT));
        try (var source = ConfigManager.parseNative(fixture(ConfigManager.DocumentKind.EXPORT, false, true), ConfigManager.DocumentKind.EXPORT)) {
            assertFalse(ConfigManager.nativeToJson(source).contains("EXAMPLE_SECRET"));
            assertTrue(ConfigManager.nativeToJson(source, true).contains("EXAMPLE_SECRET"));
            var managed = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.LIBRARY, UUID.randomUUID(), source.journeys(), List.of(), null, source.secrets());
            assertFalse(ConfigManager.nativeToJson(managed).contains("EXAMPLE_SECRET"));
        }
        try (var remembered = ConfigManager.parseNative(fixture(ConfigManager.DocumentKind.PROJECT, true, true), ConfigManager.DocumentKind.PROJECT)) {
            assertTrue(ConfigManager.nativeToJson(remembered).contains("EXAMPLE_SECRET"));
            assertFalse(ConfigManager.nativeToJson(remembered.redacted()).contains("EXAMPLE_SECRET"));
            assertFalse(remembered.toString().contains("EXAMPLE_SECRET")); assertFalse(remembered.secrets().toString().contains("EXAMPLE_SECRET"));
        }
    }
    @Test void danglingSecretsAndUnrelatedPinsAreRejected() throws Exception {
        String base = fixture(ConfigManager.DocumentKind.EXPORT, false, true);
        for (Map<String, Object> value : List.of(Map.<String, Object>of("stepValues", Map.of(UUID.randomUUID().toString(), "EXAMPLE_SECRET")),
                Map.<String, Object>of("mtlsPin", "EXAMPLE_SECRET"), Map.<String, Object>of("proxyPassword", "EXAMPLE_SECRET"))) {
            String bad = edit(base, "/journeys/0", "secrets", value);
            assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(bad, ConfigManager.DocumentKind.EXPORT));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"https://proxy.example:8080", "socks5://proxy.example:1080",
            "http://proxy.example/path", "http://proxy.example?key=value", "http://proxy.example#fragment", "http://proxy.example:0", "http://proxy.example:65536"})
    void rejectsUnsupportedProxyModesRatherThanFallingBackToDirect(String url) throws Exception {
        String json = edit(fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0/browser", "proxy", Map.of("url", url));
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(json, ConfigManager.DocumentKind.PROJECT));
    }
    @Test void proxyCredentialsAreRejectedWithUrlOnlyGuidanceAndNeverEchoed() throws Exception {
        String base = fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        String withUsername = edit(base, "/journeys/0/browser", "proxy", Map.of("url", "http://localhost:8080", "username", "DO_NOT_ECHO"));
        var usernameError = assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(withUsername, ConfigManager.DocumentKind.PROJECT));
        assertTrue(usernameError.getMessage().contains("proxy URL only")); assertFalse(usernameError.getMessage().contains("DO_NOT_ECHO"));
        String withPassword = edit(base, "/journeys/0", "secrets", Map.of("proxyPassword", "DO_NOT_ECHO"));
        var passwordError = assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(withPassword, ConfigManager.DocumentKind.PROJECT));
        assertTrue(passwordError.getMessage().contains("requires no authentication")); assertFalse(passwordError.getMessage().contains("DO_NOT_ECHO"));
    }
    @Test void mtlsSelectorsAndIntegerSlotBoundaries() throws Exception {
        String base = fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        Map<String, Object> mtls = new HashMap<>(Map.of("modulePath", "/opt/vendor.so", "certificateSha256", "a".repeat(64), "origins", List.of("https://app.example")));
        mtls.put("slot", Map.of("kind", "id", "value", Long.MAX_VALUE));
        try (var d = ConfigManager.parseNative(edit(base, "/journeys/0", "mtls", mtls), ConfigManager.DocumentKind.PROJECT)) {
            assertEquals(Long.MAX_VALUE, d.journeys().getFirst().mtls().slot().value());
        }
        List<Map<String, Object>> invalidFields = List.of(Map.of("modulePath", "relative.dll"), Map.of("certificateSha256", "A".repeat(64)),
                Map.of("origins", List.of("http://app.example")), Map.of("origins", List.of("https://*.example")),
                Map.of("origins", List.of("https://app.example/path")), Map.of("origins", List.of("https://app.example", "https://APP.example:443/")),
                Map.of("slot", Map.of("kind", "index", "value", 2147483648L)), Map.of("slot", Map.of("kind", "id", "value", -1)),
                Map.of("slot", Map.of("kind", "id", "value", new java.math.BigInteger("9223372036854775808"))));
        for (var fields : invalidFields) {
            Map<String, Object> invalid = new HashMap<>(mtls); invalid.putAll(fields);
            String json = edit(base, "/journeys/0", "mtls", invalid);
            assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(json, ConfigManager.DocumentKind.PROJECT));
        }
    }
    @ParameterizedTest @org.junit.jupiter.params.provider.CsvSource({
            "https://LOGIN.example:443/login?next=home, https://login.example",
            "https://LOGIN.example:8443/login, https://login.example:8443",
            "https://[::1]:8443/login, https://[::1]:8443"})
    void mtlsAutomaticallyIncludesTheExactHttpsLoginServer(String loginUrl, String expected) throws Exception {
        String base = edit(fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "authenticationUrl", loginUrl);
        var mtls = Map.of("modulePath", "/opt/vendor.so", "certificateSha256", "a".repeat(64), "origins", List.of());
        try (var parsed = ConfigManager.parseNative(edit(base, "/journeys/0", "mtls", mtls), ConfigManager.DocumentKind.PROJECT);
             var reloaded = ConfigManager.parseNative(ConfigManager.nativeToJson(parsed), ConfigManager.DocumentKind.PROJECT)) {
            assertEquals(List.of(URI.create(expected)), parsed.journeys().getFirst().mtls().origins());
            assertEquals(parsed.journeys(), reloaded.journeys());
        }
        var explicit = Map.of("modulePath", "/opt/vendor.so", "certificateSha256", "a".repeat(64), "origins", List.of(expected, "https://identity.example"));
        try (var parsed = ConfigManager.parseNative(edit(base, "/journeys/0", "mtls", explicit), ConfigManager.DocumentKind.PROJECT)) {
            assertEquals(List.of(URI.create(expected), URI.create("https://identity.example")), parsed.journeys().getFirst().mtls().origins());
            assertFalse(parsed.journeys().getFirst().mtls().origins().contains(URI.create("https://unrelated.example")));
        }
    }
    @Test void mtlsHttpLoginRequiresAnExplicitHttpsAuthenticationServer() throws Exception {
        String base = edit(fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "authenticationUrl", "http://login.example/start");
        var empty = Map.of("modulePath", "/opt/vendor.so", "certificateSha256", "a".repeat(64), "origins", List.of());
        var failure = assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(edit(base, "/journeys/0", "mtls", empty), ConfigManager.DocumentKind.PROJECT));
        assertTrue(failure.getMessage().contains("use an HTTPS Login URL or add an HTTPS authentication server"));
        var additional = Map.of("modulePath", "/opt/vendor.so", "certificateSha256", "a".repeat(64), "origins", List.of("https://identity.example:8443"));
        try (var parsed = ConfigManager.parseNative(edit(base, "/journeys/0", "mtls", additional), ConfigManager.DocumentKind.PROJECT)) {
            assertEquals(List.of(URI.create("https://identity.example:8443")), parsed.journeys().getFirst().mtls().origins());
        }
    }
    @Test void strictEnvelopeRetirementAndStepIdentityRules() throws Exception {
        String base = fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        ObjectNode root = (ObjectNode) JSON.readTree(base);
        var journeys = (com.fasterxml.jackson.databind.node.ArrayNode) root.get("journeys"); journeys.add(journeys.get(0).deepCopy());
        String duplicateJourney = root.toString();
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(duplicateJourney, ConfigManager.DocumentKind.PROJECT));
        root = (ObjectNode) JSON.readTree(base); var steps = (com.fasterxml.jackson.databind.node.ArrayNode) root.at("/journeys/0/steps"); steps.add(steps.get(0).deepCopy());
        String duplicateStep = root.toString(); assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(duplicateStep, ConfigManager.DocumentKind.PROJECT));
        Map<String, Object> retired = Map.of("alias", "former", "formerJourneyId", JOURNEY.toString(), "retiredAt", "2026-11-03T12:00:00Z");
        String tombstone = edit(base, "", "retiredAliases", List.of(retired));
        try (var d = ConfigManager.parseNative(tombstone, ConfigManager.DocumentKind.PROJECT)) {
            assertEquals(1, d.retiredAliases().size());
            try (var rewritten = ConfigManager.parseNative(ConfigManager.nativeToJson(d), ConfigManager.DocumentKind.PROJECT)) { assertTrue(rewritten.retiredAliases().isEmpty()); }
        }
        for (String bad : List.of(edit(base, "", "retiredAliases", List.of(retired, retired)),
                edit(fixture(ConfigManager.DocumentKind.EXPORT, false, false), "", "retiredAliases", List.of(retired)),
                edit(fixture(ConfigManager.DocumentKind.LIBRARY, false, false), "", "controls", Map.of()))) {
            ConfigManager.DocumentKind kind = ConfigManager.DocumentKind.valueOf(JSON.readTree(bad).get("kind").textValue().toUpperCase());
            assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(bad, kind));
        }
        Map<String, Object> notUtc = new HashMap<>(retired); notUtc.put("retiredAt", "2026-11-03T12:00:00+01:00");
        String badTime = edit(base, "", "retiredAliases", List.of(notUtc));
        assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(badTime, ConfigManager.DocumentKind.PROJECT));
    }
    @Test void rejectsUnsupportedOrExcessiveRegexWithSafeErrors() throws Exception {
        String base = fixture(ConfigManager.DocumentKind.PROJECT, false, false);
        for (String pattern : List.of("(?=secret)", "(secret)\\1", "x".repeat(4097), "Ã©".repeat(2049), "(abcdefghijk){1000}", "[")) {
            String bad = edit(base, "/controls", "rules", List.of(Map.of("journey", Map.of("scope", "project", "id", JOURNEY.toString()), "urlMode", "all_requests", "recovery", Map.of("mode", "regex", "pattern", pattern))));
            var ex = assertThrows(ConfigManager.NativeFormatException.class, () -> ConfigManager.parseNative(bad, ConfigManager.DocumentKind.PROJECT));
            assertFalse(ex.getMessage().contains("secret")); assertNull(ex.getCause());
        }
    }
    @Test void approvedNativeExamplesRemainReadable() throws Exception {
        String design = java.nio.file.Files.readString(java.nio.file.Path.of("../docs/designs/bapp-owned-authentication.md"));
        var blocks = java.util.regex.Pattern.compile("```json\\R(.*?)\\R\\s*```", java.util.regex.Pattern.DOTALL).matcher(design);
        int examples = 0;
        while (blocks.find()) {
            JsonNode example = JSON.readTree(blocks.group(1)); if (!example.has("schemaVersion")) continue;
            ConfigManager.DocumentKind kind = ConfigManager.DocumentKind.valueOf(example.get("kind").textValue().toUpperCase());
            try (var parsed = ConfigManager.parseNative(blocks.group(1), kind)) { assertEquals(1, parsed.journeys().size()); examples++; }
        }
        assertEquals(3, examples);
    }
    @Test void ownedSecretBuffersAreIndependentAndClosedSnapshotsRejectAccess() {
        char[] original = "example".toCharArray(); var values = new SecretStore.Values(original, Map.of(STEP, original)); original[0] = 'X';
        try (SecretStore store = new SecretStore()) {
            var key = new SecretStore.Key(JourneyDefinition.Scope.PROJECT, JOURNEY); store.put(key, values); values.close();
            try (var copy = store.snapshot(key)) { char[] got = copy.stepValue(STEP); got[0] = 'Y'; assertArrayEquals("example".toCharArray(), copy.stepValue(STEP)); }
            store.removeStep(key, STEP); try (var copy = store.snapshot(key)) { assertNull(copy.stepValue(STEP)); assertArrayEquals("example".toCharArray(), copy.pin()); }
        }
        assertThrows(IllegalStateException.class, values::pin);
    }

    @Test void crossScopeCaseCollisionsArePreservedAndBlockedWithNoWinner() throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;
        try (SecretStore secrets = new SecretStore(); var project = document(ConfigManager.DocumentKind.PROJECT); var library = document(ConfigManager.DocumentKind.LIBRARY)) {
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, project);
            var old = registry.snapshot().resolve("EMPLOYEE").identity();
            var conflict = definitions(library, List.of(changed(library.journeys().getFirst(), "EMPLOYEE", "Library")));
            assertTrue(registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, conflict).contains(old));
            assertEquals(2, registry.snapshot().entries().size()); assertFalse(registry.snapshot().isCurrent(old));
            int entriesDuringConflict=registry.snapshot().entries().size();
            boolean resolutionBlocked=assertThrows(IllegalStateException.class, () -> registry.snapshot().resolve("employee"))!=null;
            assertThrows(IllegalStateException.class, () -> registry.snapshot().resolve(old.key()));
            registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, definitions(library, List.of()));
            assertNotEquals(old, registry.snapshot().resolve("employee").identity()); assertFalse(registry.snapshot().isCurrent(old));
            observed=Map.of("entriesDuringConflict",entriesDuringConflict,"oldRetired",!registry.snapshot().isCurrent(old),"resolutionBlocked",resolutionBlocked,"restoredNewGeneration",registry.snapshot().resolve("employee").identity().generation()>old.generation());
        }
        configurationObservation("CORE.registry.alias-conflict",observed,began);
    }
    @Test void withinScopeConflictsCanBeSavedAndRemainBlockedUntilRepaired() {
        try (SecretStore secrets = new SecretStore(); var d = document(ConfigManager.DocumentKind.PROJECT)) {
            var j = d.journeys().getFirst(); var other = changed(j.withIdentity(UUID.randomUUID(), j.steps(), false), "EMPLOYEE", "Other");
            var conflict = definitions(d, List.of(j, other));
            try (var saved = ConfigManager.parseNative(ConfigManager.nativeToJson(conflict), ConfigManager.DocumentKind.PROJECT)) { assertEquals(2, saved.journeys().size()); }
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, conflict);
            assertEquals(2, registry.snapshot().entries().size()); assertThrows(IllegalStateException.class, () -> registry.snapshot().resolve("employee"));
            try (var repaired = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(changed(j, "first", j.displayName()), other),
                    d.controls())) {
                registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, repaired);
                assertEquals(other.id(), registry.snapshot().resolve("employee").definition().id());
                assertEquals(j.id(), registry.snapshot().resolve("first").definition().id());
            }
        }
    }
    @Test void authenticationEditsRejectOldIdentitiesAndRevisionOnlyReloadsKeepThem() {
        try (SecretStore secrets = new SecretStore(); var d = document(ConfigManager.DocumentKind.PROJECT)) {
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, d);
            var old = registry.snapshot().resolve("employee").identity();
            try (var same = d.withRevision(UUID.randomUUID())) {
                assertTrue(registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, same).isEmpty());
                assertTrue(registry.snapshot().isCurrent(old));
            }
            var j = d.journeys().getFirst();
            var changedUrl = new JourneyDefinition(j.id(), j.displayName(), j.alias(), URI.create("https://other.example/login"), j.rememberSecrets(),
                    j.steps(), j.browser(), j.extraction(), j.injection(), j.cache(), j.mtls());
            assertTrue(registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, definitions(d, List.of(changedUrl))).contains(old));
            assertFalse(registry.snapshot().isCurrent(old)); assertEquals(old.generation() + 1, registry.snapshot().resolve("employee").identity().generation());
        }
    }
    @Test void generationsTrackAuthAndSecretChangesButKeepDisplayAndAliasCaseEdits() throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;
        try (SecretStore secrets = new SecretStore(); var doc = document(ConfigManager.DocumentKind.PROJECT)) {
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, doc);
            var first = registry.snapshot().resolve("employee").identity(); var j = doc.journeys().getFirst();
            registry.replaceLoaded(JourneyDefinition.Scope.PROJECT,definitions(doc,List.of(changed(j,"employee","Renamed display"))));assertEquals(first,registry.snapshot().resolve("employee").identity());boolean displayRetains=first.equals(registry.snapshot().resolve("employee").identity());
            registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, definitions(doc, List.of(changed(j, "EMPLOYEE", "Renamed display"))));
            assertEquals(first, registry.snapshot().resolve("employee").identity());
            boolean caseRetains=first.equals(registry.snapshot().resolve("employee").identity()),secretRetires=false,reloadRetires=false;
            try (var values = new SecretStore.Values(null, Map.of(STEP, "example".toCharArray()))) {
                assertTrue(registry.secretChanged(first.key(), values).contains(first));
                var next = registry.snapshot().resolve("employee").identity(); assertEquals(2, next.generation());
                secretRetires=!first.equals(next);
                assertTrue(registry.secretChanged(first.key(), values).isEmpty());
                registry.disableScope(JourneyDefinition.Scope.PROJECT); assertFalse(registry.snapshot().isCurrent(next));
                registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, doc); assertTrue(registry.snapshot().resolve("employee").identity().generation() > next.generation());
                reloadRetires=registry.snapshot().resolve("employee").identity().generation()>next.generation();
            }
            var latest = registry.snapshot().resolve("employee").identity();
            registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, definitions(doc, List.of()));
            registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, doc);
            assertFalse(registry.snapshot().isCurrent(latest));
            observed=Map.of("displayRetainsIdentity",displayRetains,"caseRetainsIdentity",caseRetains,"secretRetires",secretRetires,"reloadRetires",reloadRetires,"deleteRetires",!registry.snapshot().isCurrent(latest));
        }
        for(String variant:List.of("display-rename","case-only-rename"))configurationObservation("CORE.registry."+variant,observed,began);
    }
    @Test void renamedAliasesAreReusableAcrossScopesWhileActiveDuplicatesBlockExecution() throws Exception {
        long began=System.nanoTime();Map<String,Object> observed;
        try (SecretStore secrets = new SecretStore(); var doc = document(ConfigManager.DocumentKind.PROJECT)) {
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, doc);
            var j = doc.journeys().getFirst(); var renamed = changed(j, "staff", "Staff");
            try (var edit = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(renamed), doc.controls())) {
                assertTrue(edit.retiredAliases().isEmpty()); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, edit);
            }
            boolean oldUnavailable=assertThrows(IllegalStateException.class, () -> registry.snapshot().resolve("employee"))!=null,replacementSelected=false,originalPreserved=false,collisionBlocked=false,deletedUnavailable=false,replacementHasNewId=false;
            var reused = j.withIdentity(UUID.randomUUID(), j.steps(), false);
            try (var edited = registry.prepareEdit(JourneyDefinition.Scope.LIBRARY, List.of(reused), null)) {
                registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, edited); assertEquals(reused.id(), registry.snapshot().resolve("employee").definition().id());
                assertEquals(j.id(), registry.snapshot().resolve("staff").definition().id());
                replacementSelected=reused.id().equals(registry.snapshot().resolve("employee").definition().id());originalPreserved=j.id().equals(registry.snapshot().resolve("staff").definition().id());
            }
            try (var collision = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(j), doc.controls())) {
                registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, collision);
                collisionBlocked=assertThrows(IllegalStateException.class, () -> registry.snapshot().resolve("employee"))!=null;
            }
            try (var deleted = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(), doc.controls())) {
                registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, deleted); assertTrue(deleted.retiredAliases().isEmpty());
                deletedUnavailable=assertThrows(IllegalStateException.class, () -> registry.snapshot().resolve("staff"))!=null;
            }
            try (var reusedStaff = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(renamed.withIdentity(UUID.randomUUID(), j.steps(), false)), doc.controls())) {
                registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, reusedStaff); assertNotEquals(j.id(), registry.snapshot().resolve("staff").definition().id());
                replacementHasNewId=!j.id().equals(registry.snapshot().resolve("staff").definition().id());
            }
            observed=Map.of("oldAliasUnavailable",oldUnavailable,"replacementSelected",replacementSelected,"originalAliasPreserved",originalPreserved,"collisionBlocked",collisionBlocked,"deletedUnavailable",deletedUnavailable,"replacementHasNewId",replacementHasNewId);
        }
        for(String variant:List.of("retired-alias","explicit-reassignment"))configurationObservation("CORE.registry."+variant,observed,began);
    }
    static void configurationObservation(String id,Map<String,Object> observed,long began) throws Exception {
        AuthLabSupport.component(id,observed,Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
    }
    @Test void legacyRetirementRecordsDoNotBlockAnActiveAliasInEitherScope() {
        try (SecretStore secrets = new SecretStore(); var project = document(ConfigManager.DocumentKind.PROJECT)) {
            var registry = new JourneyRegistry(secrets);
            var legacy = new ConfigManager.RetiredAlias("employee", UUID.randomUUID(), Instant.now());
            try (var library = new ConfigManager.NativeDocument(ConfigManager.DocumentKind.LIBRARY, UUID.randomUUID(), List.of(), List.of(legacy), null, Map.of())) { registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, library); }
            registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, project);
            var previous = registry.snapshot().resolve("employee").identity();
            assertEquals(JOURNEY, previous.journeyId());
            try (var deleted = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(), project.controls())) { registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, deleted); }
            var replacement = project.journeys().getFirst().withIdentity(UUID.randomUUID(), List.of(), false);
            try (var edited = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(replacement), project.controls())) { registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, edited); }
            assertEquals(replacement.id(), registry.snapshot().resolve("employee").definition().id()); assertFalse(registry.snapshot().isCurrent(previous));
        }
    }
    @Test void reorderPreservesSecureStepAssociationAndRetypingDropsIt() {
        try (SecretStore secrets = new SecretStore(); var doc = ConfigManager.parseNative(fixture(ConfigManager.DocumentKind.PROJECT, true, true), ConfigManager.DocumentKind.PROJECT)) {
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, doc);
            JourneyDefinition j = doc.journeys().getFirst();
            var click = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.CLICK, "#go", null, null, null, null);
            var moved = j.withIdentity(j.id(), List.of(click, j.steps().getFirst()), true);
            try (var edit = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(moved), doc.controls())) {
                assertArrayEquals("EXAMPLE_SECRET".toCharArray(), edit.secrets().get(JOURNEY).stepValue(STEP));
                registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, edit);
            }
            var ordinary = new AuthStep.Definition(STEP, AuthStep.Type.INPUT, "#password", "", null, null, null);
            try (var edit = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, List.of(j.withIdentity(j.id(), List.of(ordinary), true)), doc.controls())) {
                assertNull(edit.secrets().get(JOURNEY).stepValue(STEP)); assertFalse(ConfigManager.nativeToJson(edit).contains("EXAMPLE_SECRET"));
            }
        }
    }
    @Test void importAllocatesAndRemapsIdentitiesKeepsSecretsSessionOnlyAndValidatesWholePreview() {
        try (SecretStore secrets = new SecretStore(); var doc = document(ConfigManager.DocumentKind.PROJECT)) {
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, doc);
            String export = fixture(ConfigManager.DocumentKind.EXPORT, false, true);
            assertThrows(IllegalArgumentException.class, () -> JourneyTransfer.previewImport(export, JourneyDefinition.Scope.PROJECT, registry, Map.of()));
            assertEquals(1, registry.snapshot().entries().size());
            try (var preview = JourneyTransfer.previewImport(export, JourneyDefinition.Scope.PROJECT, registry, Map.of("employee", "second"))) {
                JourneyDefinition imported = preview.journeys().get(1); assertNotEquals(JOURNEY, imported.id()); assertFalse(imported.rememberSecrets());
                UUID newStep = imported.steps().getFirst().id(); assertNotEquals(STEP, newStep);
                assertArrayEquals("EXAMPLE_SECRET".toCharArray(), preview.secrets().get(imported.id()).stepValue(newStep));
                assertFalse(ConfigManager.nativeToJson(preview).contains("EXAMPLE_SECRET"));
                assertEquals(1, registry.snapshot().entries().size()); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, preview);
                var entry = registry.snapshot().resolve("second");
                assertFalse(JourneyTransfer.exportJourneys(List.of(entry), secrets, false).contains("EXAMPLE_SECRET"));
                assertTrue(JourneyTransfer.exportJourneys(List.of(entry), secrets, true).contains("EXAMPLE_SECRET"));
            }
            assertThrows(ConfigManager.NativeFormatException.class, () -> JourneyTransfer.previewImport(fixture(ConfigManager.DocumentKind.PROJECT, false, false), JourneyDefinition.Scope.PROJECT, registry, Map.of()));
        }
    }
    @Test void nativeProjectStorageNeverReadsOrOverwritesLegacyKeyAndRejectsStaleSaves() {
        Map<String, String> values = new HashMap<>(); values.put("bpsh_config", "legacy-unmodified");
        PersistedObject storage = (PersistedObject) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{PersistedObject.class}, (p, m, args) -> {
            if (m.getName().equals("getString")) return values.get((String) args[0]);
            if (m.getName().equals("setString")) { values.put((String) args[0], (String) args[1]); return null; }
            throw new UnsupportedOperationException();
        });
        ConfigManager manager = new ConfigManager(storage); assertTrue(manager.loadNativeProject().isEmpty());
        try (var d = document(ConfigManager.DocumentKind.PROJECT); var saved = manager.saveNativeProject(d, null)) {
            assertNotEquals(d.revision(), saved.revision());
            assertThrows(ConfigManager.NativeFormatException.class, () -> manager.saveNativeProject(d, null));
            try (var loaded = manager.loadNativeProject().orElseThrow()) { assertEquals(saved.revision(), loaded.revision()); }
        }
        assertEquals("legacy-unmodified", values.get("bpsh_config"));
    }
    @Test void explicitSecretExportReportsMissingValuesInsteadOfCallingItComplete() {
        try (SecretStore secrets = new SecretStore(); var d = document(ConfigManager.DocumentKind.PROJECT)) {
            JourneyRegistry registry = new JourneyRegistry(secrets); registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, d);
            var entry = registry.snapshot().resolve("employee");
            assertDoesNotThrow(() -> JourneyTransfer.exportJourneys(List.of(entry), secrets, false));
            var ex = assertThrows(ConfigManager.NativeFormatException.class, () -> JourneyTransfer.exportJourneys(List.of(entry), secrets, true));
            assertTrue(ex.getMessage().contains("enter it in the journey configuration"));
            assertTrue(ex.getMessage().contains("export without Include secrets"));
        }
    }

    /** Exercises isolated Swing components and temporary native stores, not an installed Burp window. */
    @org.junit.jupiter.api.Nested class NativeUi {
        @org.junit.jupiter.api.io.TempDir java.nio.file.Path root;
        /** Reflects only our own controller's private test seams, never another app or host JVM. */
        @SuppressWarnings("unchecked") <T> T member(Object object, String name) throws Exception {
            var field = object.getClass().getDeclaredField(name); field.setAccessible(true); return (T) field.get(object);
        }
        /** @param target Own component/controller. @param name Private action. @param types Exact parameter types. @param values Captured arguments. */
        Object call(Object target, String name, Class<?>[] types, Object... values) throws Exception { var method = target.getClass().getDeclaredMethod(name, types); method.setAccessible(true); return method.invoke(target, values); }
        /** @param task Local component operation. */
        void edt(Checked task) throws Exception {
            var error = new java.util.concurrent.atomic.AtomicReference<Throwable>(); javax.swing.SwingUtilities.invokeAndWait(() -> { try { task.run(); } catch (Throwable ex) { error.set(ex); } });
            if (error.get() != null) throw new AssertionError("Local Swing operation failed", error.get());
        }
        /** Allows checked assertions inside EDT test operations. */
        interface Checked { /** @throws Exception Propagated to the test thread. */ void run() throws Exception; }
        /** @param ready Observable local background completion. */
        void await(java.util.function.BooleanSupplier ready) throws Exception { long end = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(8); while (!ready.getAsBoolean() && end - System.nanoTime() > 0) { edt(() -> {}); Thread.sleep(5); } assertTrue(ready.getAsBoolean(), "local background action must terminate"); }

        /** Owns private test storage and a Swing editor without browser/native execution. */
        final class Editor implements AutoCloseable {
            final Map<String, String> disk = new java.util.concurrent.ConcurrentHashMap<>();
            final SecretStore secrets = new SecretStore(); final JourneyRegistry registry = new JourneyRegistry(secrets);
            final CoordinatorFixtures.ManualRuntime clock = new CoordinatorFixtures.ManualRuntime();
            final AuthenticationCoordinator coordinator;
            final UserLibraryStore library = new UserLibraryStore(root.resolve("library.json")); final Pkcs11IdentityManager identities;
            final java.util.List<String> diagnosticMessages = new java.util.concurrent.CopyOnWriteArrayList<>();
            final Diagnostics diagnostics = new Diagnostics(diagnosticMessages::add); final UiController ui;
            final java.util.concurrent.atomic.AtomicReference<Config.Controls> controls = new java.util.concurrent.atomic.AtomicReference<>(Config.Controls.defaults());
            java.awt.Component component;
            /** @param stored Optional native project JSON; old data is also seeded to verify preservation. */
            Editor(String stored) throws Exception { this(stored, Config.Controls.defaults(), null, null); }
            Editor(String stored, AuthenticationCoordinator.Attempt attempt) throws Exception { this(stored, Config.Controls.defaults(), attempt, null); }
            Editor(String stored, AuthenticationCoordinator.Attempt attempt, Pkcs11IdentityManager.NativeAccess nativeAccess) throws Exception { this(stored, Config.Controls.defaults(), attempt, nativeAccess); }
            Editor(String stored, Config.Controls selectedControls, AuthenticationCoordinator.Attempt attempt) throws Exception { this(stored, selectedControls, attempt, null); }
            /** Shares the discovery boundary while preserving the diagnostic owner's selected controls. */
            Editor(String stored, Config.Controls selectedControls, AuthenticationCoordinator.Attempt attempt, Pkcs11IdentityManager.NativeAccess nativeAccess) throws Exception {
                identities = nativeAccess == null ? new Pkcs11IdentityManager() : new Pkcs11IdentityManager(nativeAccess);
                coordinator = new AuthenticationCoordinator(registry, selectedControls, clock,
                        attempt == null ? (entry, recovery, deadline, cancel) -> { throw new AssertionError("Opening/saving an editor must not log in"); } : attempt, entry -> null);
                controls.set(selectedControls);
                if (stored != null) disk.put(ConfigManager.NATIVE_PROJECT_KEY, stored); disk.put("bpsh_config", "untouched old data"); disk.put("bpsh_project_v1", "untouched preceding native format");
                var storage = (PersistedObject) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{PersistedObject.class}, (p, method, args) -> {
                    assertFalse(javax.swing.SwingUtilities.isEventDispatchThread(), "project persistence must stay off the EDT");
                    if (method.getName().equals("getString")) return disk.get(args[0]); if (method.getName().equals("setString")) { disk.put((String) args[0], (String) args[1]); return null; } return null;
                });
                ui = new UiController(null, new ConfigManager(storage), library, secrets, registry, coordinator, identities, controls, diagnostics);
                edt(() -> component = ui.buildUi()); ui.start(); await(() -> { try { return (boolean) member(ui, "initialized"); } catch (Exception e) { return false; } }); edt(() -> {});
            }
            /** @return Our own named text fields, never installed-app automation. */
            Map<String, javax.swing.JTextField> fields() throws Exception { return member(ui, "fields"); }
            /** @return Our own flag controls. */
            Map<String, javax.swing.JCheckBox> checks() throws Exception { return member(ui, "checks"); }
            /** @return Whether the visible editor's latest version is committed, independent of UI feedback. */
            boolean saved() throws Exception {
                var result = new java.util.concurrent.atomic.AtomicBoolean();
                edt(() -> result.set(!(boolean) member(ui, "dirty") && !(boolean) member(ui, "journeySaveInFlight")
                        && member(ui, "editingIdentity") != null)); return result.get();
            }
            /** @return Safe visible status, read on its owning EDT. */
            String status() throws Exception { var text = new java.util.concurrent.atomic.AtomicReference<String>(); edt(() -> text.set(((SessionStatusBar) member(ui, "status")).getText())); return text.get(); }
            /** Flushes/wipes the local UI, timers and native state. */
            @Override public void close() throws Exception { ui.shutdown(); ui.awaitSaves(5000); coordinator.close(); identities.close(); diagnostics.close(); secrets.close(); edt(() -> {}); }
        }

        @Test void openingSavingAndShutdownKeepPersistenceOffEdtAndSessionSecretsOutOfStorage() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                var key = new SecretStore.Key(JourneyDefinition.Scope.PROJECT, JOURNEY); edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
                await(() -> { try { return editor.registry.snapshot().entries().containsKey(key) && ((java.util.List<?>) member((StepsPanel) member(editor.ui, "steps"), "rows")).size() == 1; } catch (Exception e) { return false; } });
                edt(() -> {
                    StepsPanel panel = member(editor.ui, "steps"); List<?> rows = member(panel, "rows"); Object row = rows.getFirst();
                    ((javax.swing.JPasswordField) member(row, "secret")).setText("fixture-session-only");
                    call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
                });
                await(() -> { try (var values = editor.secrets.snapshot(key)) { return values.stepValue(STEP) != null; } });
                assertFalse(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY).contains("fixture-session-only")); assertEquals("untouched old data", editor.disk.get("bpsh_config")); assertEquals("untouched preceding native format", editor.disk.get("bpsh_project_v1"));
                try (var stored = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) { assertTrue(stored.secrets().isEmpty()); assertEquals(STEP, stored.journeys().getFirst().steps().getFirst().id()); }
                editor.ui.shutdown(); edt(() -> { assertFalse(((javax.swing.Timer) member(editor.ui, "statusTimer")).isRunning()); });
            }
        }
        @Test void stableRowsRetainIdsOnReorderAndDropSecureValuesOnRetype() throws Exception {
            var first = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.SECURE_INPUT, "#password", null, null, null, null);
            var second = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.WAIT_TIME, null, null, null, null, 1000);
            try (var values = new SecretStore.Values(null, Map.of(first.id(), "fixture-only".toCharArray()))) {
                edt(() -> {
                    var panel = new StepsPanel(); panel.setSteps(List.of(first, second), values); List<?> rows = member(panel, "rows"); Object secure = rows.getFirst();
                    call(secure, "move", new Class<?>[]{String.class}, "Down");
                    try (var capture = panel.snapshot()) { assertEquals(List.of(second.id(), first.id()), capture.definitions().stream().map(AuthStep.Definition::id).toList()); assertTrue(capture.secrets.containsKey(first.id())); }
                    ((javax.swing.JComboBox<?>) member(secure, "type")).setSelectedItem(AuthStep.Type.INPUT);
                    try (var capture = panel.snapshot()) { assertTrue(capture.secrets.isEmpty()); }
                    assertEquals(0, ((javax.swing.JPasswordField) member(secure, "secret")).getPassword().length);
                });
            }
            try (var snapshot = new StepsPanel.Snapshot(List.of(new StepsPanel.Input(UUID.randomUUID(), AuthStep.Type.WAIT_TIME, null, "1.5s", null)), new HashMap<>())) { assertEquals(1500, snapshot.definitions().getFirst().durationMs()); }
        }
        @Test void externalLibraryChangeCannotBeOverwrittenByAnOlderVisibleDraft() throws Exception {
            long began=System.nanoTime();Map<String,Object> observed;
            try (var editor = new Editor(null)) {
                edt(() -> { ((javax.swing.JComboBox<?>) member(editor.ui, "destination")).setSelectedItem(JourneyDefinition.Scope.LIBRARY); call(editor.ui, "newJourney", new Class<?>[]{}); });
                await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
                long before = member(editor.ui, "editingScopeEpoch");
                var key = (SecretStore.Key) member(editor.ui, "editing");
                edt(() -> editor.fields().get("name").setText("Local edit"));
                try (var external = new UserLibraryStore(editor.library.path()); var existing = external.load(); var empty = ConfigManager.NativeDocument.empty(ConfigManager.DocumentKind.LIBRARY);
                     var document = new ConfigManager.NativeDocument(empty.kind(), empty.revision(), List.of(CoordinatorFixtures.journey("external")), List.of(), null, Map.of());
                     var written = external.save(document, existing.version())) {}
                await(() -> { try { return ((Map<JourneyDefinition.Scope, Long>) member(editor.ui, "visibleEpochs")).get(JourneyDefinition.Scope.LIBRARY) > before; } catch (Exception e) { return false; } });
                edt(() -> call(editor.ui, "save", new Class<?>[]{boolean.class}, false));
                await(() -> { try { return editor.coordinator.events().snapshot(key).stream().anyMatch(event -> event.level() == JourneyEventLog.Level.ERROR && event.message().contains("Storage changed")); } catch (Exception e) { return false; } });
                try (var actualStore=new UserLibraryStore(editor.library.path());var loaded=actualStore.load()) {
                    assertEquals("external", loaded.document().journeys().getFirst().alias()); assertEquals(1, loaded.document().journeys().size());
                    observed=Map.of("alias",loaded.document().journeys().getFirst().alias(),"journeys",loaded.document().journeys().size(),"draftRejected",editor.coordinator.events().snapshot(key).stream().anyMatch(event->event.level()==JourneyEventLog.Level.ERROR&&event.message().contains("Storage changed")),"epochAdvanced",((Map<JourneyDefinition.Scope,Long>)member(editor.ui,"visibleEpochs")).get(JourneyDefinition.Scope.LIBRARY)>before);
                }
            }
            configurationObservation("CORE.registry.library-change",observed,began);
        }
        @Test void malformedNativeProjectStaysPreservedAndVisibleInsteadOfFallingBackToOldData() throws Exception {
            long began=System.nanoTime();Map<String,Object> observed;
            try (var editor = new Editor("{invalid-native")) {
                assertTrue(editor.registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.PROJECT));
                assertEquals("{invalid-native", editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY)); assertEquals("untouched old data", editor.disk.get("bpsh_config")); assertEquals("untouched preceding native format", editor.disk.get("bpsh_project_v1"));
                assertTrue(editor.status().contains("journey storage is unavailable")); assertTrue(editor.clock.workers.isEmpty());
                observed=Map.of("projectUnavailable",editor.registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.PROJECT),"nativePreserved",editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY).equals("{invalid-native"),"legacyPreserved",editor.disk.get("bpsh_config").equals("untouched old data"),"priorNativePreserved",editor.disk.get("bpsh_project_v1").equals("untouched preceding native format"),"statusVisible",editor.status().contains("journey storage is unavailable"),"pendingWorkers",editor.clock.workers.size());
            }
            configurationObservation("CORE.storage.mixed-version",observed,began);
        }
        @Test void offscreenLayoutArtifactIsExplicitlySeparateFromThePendingManualBurpCheck() throws Exception {
            try (var editor = new Editor(null)) {
                edt(() -> {
                    call(editor.ui, "newJourney", new Class<?>[]{}); var component = editor.component; component.setSize(1280, 820); layout(component);
                    var image = new java.awt.image.BufferedImage(1280, 820, java.awt.image.BufferedImage.TYPE_INT_RGB); var graphics = image.createGraphics(); component.printAll(graphics); graphics.dispose();
                    var output = java.nio.file.Path.of("build", "ui-previews"); java.nio.file.Files.createDirectories(output); javax.imageio.ImageIO.write(image, "png", output.resolve("p4-native-editor.png").toFile());
                });
            }
        }
        @Test void selectionLoadingDisablesOldJourneyFieldsAndIgnoresObsoleteSelectionCompletions() throws Exception {
            String json;
            try (var original = document(ConfigManager.DocumentKind.PROJECT)) {
                var first = original.journeys().getFirst(); var second = changed(first.withIdentity(UUID.randomUUID(), List.of(), false), "second", "Second");
                try (var project = new ConfigManager.NativeDocument(original.kind(), original.revision(), List.of(first, second), original.retiredAliases(), original.controls(), Map.of())) { json = ConfigManager.nativeToJson(project); }
            }
            try (var editor = new Editor(json)) {
                var started = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
                java.util.concurrent.ThreadPoolExecutor io = member(editor.ui, "io");
                io.execute(() -> { started.countDown(); try { release.await(5, java.util.concurrent.TimeUnit.SECONDS); } catch (InterruptedException ex) { Thread.currentThread().interrupt(); } });
                assertTrue(started.await(5, java.util.concurrent.TimeUnit.SECONDS));
                var first = editor.registry.snapshot().resolve("employee").identity().key(); var second = editor.registry.snapshot().resolve("second").identity().key();
                edt(() -> {
                    call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, first); call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, second);
                    assertTrue((boolean) member(editor.ui, "editorLoading")); assertFalse(editor.fields().get("name").isEnabled());
                    editor.fields().get("control.request").setText("60001");
                });
                release.countDown(); await(() -> { try { return !(boolean) member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
                edt(() -> { assertEquals("second", member(editor.ui, "draftAlias")); assertEquals(second, member(editor.ui, "editing")); assertTrue(editor.fields().get("name").isEnabled()); assertEquals("60001", editor.fields().get("control.request").getText()); });
            }
        }
        @Test void savingAnAliasFromLegacyRetirementNeedsNoAcknowledgement() throws Exception {
            String json;
            try (var original = document(ConfigManager.DocumentKind.PROJECT)) {
                var journey = changed(original.journeys().getFirst(), "current", "Employee");
                try (var stored = new ConfigManager.NativeDocument(original.kind(), original.revision(), List.of(journey), List.of(), original.controls(), Map.of())) {
                    json = edit(ConfigManager.nativeToJson(stored), "", "retiredAliases", List.of(Map.of("alias", "employee", "formerJourneyId", UUID.randomUUID().toString(), "retiredAt", Instant.now().toString())));
                }
            }
            try (var editor = new Editor(json)) {
                var key = editor.registry.snapshot().resolve("current").identity().key();
                edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
                await(() -> { try { return !(boolean) member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
                edt(() -> { assertFalse(editor.checks().containsKey("reassign")); editor.fields().get("name").setText("Employee"); call(editor.ui, "save", new Class<?>[]{boolean.class}, false); });
                await(() -> { try { return editor.saved(); } catch (Exception e) { return false; } });
                String previous = editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY);
                edt(() -> call(editor.ui, "save", new Class<?>[]{boolean.class}, false));
                assertEquals(previous, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), "flushing an unchanged journey does not write again");
                assertEquals(key, editor.registry.snapshot().resolve("employee").identity().key());
            }
        }
        @Test void dirtyDraftCannotTestAnAliasThatAlreadyBelongsToAnotherSavedJourney() throws Exception {
            String stored;
            try (var original = ConfigManager.parseNative(fixture(ConfigManager.DocumentKind.PROJECT, false, false), ConfigManager.DocumentKind.PROJECT)) {
                var first = original.journeys().getFirst(); var second = changed(first.withIdentity(UUID.randomUUID(), List.of(), false), "different", "Other account");
                try (var document = new ConfigManager.NativeDocument(original.kind(), original.revision(), List.of(first, second), original.retiredAliases(), original.controls(), Map.of())) { stored = ConfigManager.nativeToJson(document); }
            }
            try (var editor = new Editor(stored)) {
                var key = editor.registry.snapshot().resolve("employee").identity().key();
                edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
                await(() -> { try { return !(boolean) member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
                edt(() -> {
                    assertTrue((boolean) call(editor.ui, "canUseSavedJourney", new Class<?>[]{}));
                    editor.fields().get("name").setText("Different");
                    assertFalse((boolean) call(editor.ui, "canUseSavedJourney", new Class<?>[]{}));
                    call(editor.ui, "authenticate", new Class<?>[]{boolean.class}, false);
                });
                await(() -> { try { return editor.status().contains("already uses this generated tag"); } catch (Exception error) { return false; } });
                assertTrue(editor.clock.workers.isEmpty()); assertNotEquals(stored, editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY));
                assertEquals("different", editor.registry.snapshot().entries().get(key).definition().alias());
                assertThrows(IllegalStateException.class, () -> editor.registry.snapshot().resolve("different"));
            }
        }
        @Test void navigationAutomaticallySavesTheLatestEditsWithoutADialog() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                var key = editor.registry.snapshot().resolve("employee").identity().key();
                edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
                await(() -> { try { return !(boolean) member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
                var navigated = new java.util.concurrent.atomic.AtomicBoolean();
                edt(() -> {
                    editor.fields().get("name").setText("Autosaved before leaving");
                    call(editor.ui, "leaveDraft", new Class<?>[]{Runnable.class}, (Runnable) () -> navigated.set(true));
                    assertFalse(navigated.get());
                });
                await(navigated::get);
                assertEquals("Autosaved before leaving", editor.registry.snapshot().entries().get(key).definition().displayName());
                assertTrue(editor.saved());
            }
        }
        /** Creates a replacement draft inside a navigation callback while preserving assertion failures. */
        void callUncheckedCreate(UiController ui) { try { call(ui, "createJourney", new Class<?>[]{}); } catch (Exception ex) { throw new AssertionError(ex); } }

        @Test void replacedStorageDisablesSavedActionsUntilTheVisibleJourneyIsReloaded() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                var approved = editor.registry.snapshot().resolve("employee"); var key = approved.identity().key();
                edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
                await(() -> { try { return !(boolean) member(editor.ui, "editorLoading"); } catch (Exception ex) { return false; } });
                edt(() -> assertTrue((boolean) call(editor.ui, "canUseSavedJourney", new Class<?>[]{})));
                String replacement = fixture(ConfigManager.DocumentKind.PROJECT, false, false).replace("employee", "replacement-account");
                try (var document = ConfigManager.parseNative(replacement, ConfigManager.DocumentKind.PROJECT)) { editor.registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, document); }
                edt(() -> {
                    call(editor.ui, "bump", new Class<?>[]{JourneyDefinition.Scope.class}, JourneyDefinition.Scope.PROJECT);
                    call(editor.ui, "refreshJourneyUi", new Class<?>[]{});
                    assertEquals("employee", member(editor.ui, "draftAlias"));
                    assertFalse((boolean) call(editor.ui, "canUseSavedJourney", new Class<?>[]{}));
                    assertFalse(((javax.swing.JButton) member(editor.ui, "testButton")).isEnabled());
                    assertTrue(((javax.swing.JLabel) member(editor.ui, "draftState")).getText().contains("reload journey"));
                    var failure = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> call(editor.ui, "checkCurrent", new Class<?>[]{JourneyRegistry.Entry.class}, approved));
                    assertTrue(failure.getCause().getMessage().contains("Reload"));
                    call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key);
                });
                await(() -> { try { return !(boolean) member(editor.ui, "editorLoading"); } catch (Exception ex) { return false; } });
                edt(() -> { assertEquals("replacement-account", member(editor.ui, "draftAlias")); assertTrue((boolean) call(editor.ui, "canUseSavedJourney", new Class<?>[]{})); });
            }
        }
        @Test void saveBeforeNavigationCommitsTheCapturedDraftBeforeChangingJourney() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                var key = editor.registry.snapshot().resolve("employee").identity().key();
                edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key));
                await(() -> { try { return !(boolean) member(editor.ui, "editorLoading"); } catch (Exception e) { return false; } });
                var navigated = new java.util.concurrent.atomic.AtomicBoolean();
                edt(() -> {
                    editor.fields().get("name").setText("Saved before leaving");
                    call(editor.ui, "leaveDraft", new Class<?>[]{Runnable.class}, (Runnable) () -> { assertEquals("Saved before leaving", editor.registry.snapshot().entries().get(key).definition().displayName()); navigated.set(true); });
                });
                await(navigated::get);
                try (var persisted = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) { assertEquals("Saved before leaving", persisted.journeys().getFirst().displayName()); }
            }
        }
        @Test void applyingOneRequestSettingsCategoryDoesNotApplyDraftChangesFromTheOther() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                edt(() -> { editor.fields().get("control.request").setText("invalid pending budget"); editor.checks().get("enabled").setSelected(true); call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, false); });
                await(() -> editor.controls.get().enabled()); assertEquals(60_000, editor.controls.get().requestWaitTimeoutMs());
                edt(() -> { editor.checks().get("enabled").setSelected(false); editor.fields().get("control.request").setText("120"); call(editor.ui, "saveControls", new Class<?>[]{boolean.class}, true); });
                await(() -> editor.controls.get().requestWaitTimeoutMs() == 120000); assertTrue(editor.controls.get().enabled());
            }
        }
        @Test void waitingSettingsSaveValidSecondsAutomaticallyAndKeepLastGoodValuesOnInvalidInput() throws Exception {
            try (var editor = new Editor(null)) {
                edt(() -> editor.fields().get("control.request").setText("61.5"));
                await(() -> editor.controls.get().requestWaitTimeoutMs() == 61_500);
                edt(() -> { editor.fields().get("control.request").setText("invalid"); ((javax.swing.Timer) member(editor.ui, "settingsDebounce")).getActionListeners()[0].actionPerformed(null); });
                await(() -> { try { return !editor.status().contains("Saving settings"); } catch (Exception ex) { return false; } });
                assertEquals(61_500, editor.controls.get().requestWaitTimeoutMs());
                editor.ui.shutdown(); edt(() -> assertFalse(((javax.swing.Timer) member(editor.ui, "settingsDebounce")).isRunning()));
            }
        }
        @Test void automaticInjectionEditsSaveWithoutApplyAndInvalidPrefixRetainsLastValidRules() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                var key = editor.registry.snapshot().resolve("employee").identity().key();
                edt(() -> {
                    editor.checks().get("enabled").doClick();
                    var rules = (AutomaticRulesPanel) member(editor.ui, "automaticRules");
                    ((javax.swing.JButton) member(rules, "add")).doClick();
                    rules.urlMode.setSelectedItem(Config.UrlMode.SINGLE_URL);
                    ((AutomaticRulesPanel) member(editor.ui, "automaticRules")).prefix.setText("https://app.example/protected");
                    Map<burp.api.montoya.core.ToolType, javax.swing.JCheckBox> tools = member(editor.ui, "tools"); tools.values().iterator().next().doClick();
                });
                await(() -> !editor.controls.get().rules().isEmpty() && URI.create("https://app.example/protected").equals(editor.controls.get().rules().getFirst().urlPrefix()));
                var applied = editor.controls.get(); assertTrue(applied.enabled()); assertEquals(key.journeyId(), applied.rules().getFirst().journey().id());
                assertEquals(Config.Controls.defaults().tools().size() - 1, applied.tools().size()); assertEquals(60_000, applied.requestWaitTimeoutMs());
                edt(() -> ((AutomaticRulesPanel) member(editor.ui, "automaticRules")).prefix.setText("not a url"));
                await(() -> { try { return editor.diagnosticMessages.stream().anyMatch(m -> m.contains("URL prefix")); } catch (Exception ex) { return false; } });
                assertEquals(applied, editor.controls.get());
                edt(() -> editor.checks().get("enabled").doClick());
                await(() -> !editor.controls.get().enabled()); assertEquals(applied.rules(), editor.controls.get().rules());
                try (var saved = ConfigManager.parseNative(editor.disk.get(ConfigManager.NATIVE_PROJECT_KEY), ConfigManager.DocumentKind.PROJECT)) { assertFalse(saved.controls().enabled()); assertEquals(60_000, saved.controls().requestWaitTimeoutMs()); }
                edt(() -> {
                    editor.checks().get("enabled").setSelected(true); call(editor.ui, "refreshModes", new Class<?>[]{});
                    ((javax.swing.JTabbedPane) member(editor.ui, "mainTabs")).setSelectedIndex(1);
                    assertFalse(((SessionStatusBar) member(editor.ui, "status")).isShowing());
                    editor.component.setSize(1280, 820); layout(editor.component);
                    var image = new java.awt.image.BufferedImage(1280, 820, java.awt.image.BufferedImage.TYPE_INT_RGB); var graphics = image.createGraphics(); editor.component.printAll(graphics); graphics.dispose();
                    var output = java.nio.file.Path.of("build", "ui-previews"); java.nio.file.Files.createDirectories(output); javax.imageio.ImageIO.write(image, "png", output.resolve("automatic-injection.png").toFile());
                });
                editor.ui.shutdown(); edt(() -> assertFalse(((javax.swing.Timer) member(editor.ui, "automaticDebounce")).isRunning()));
            }
        }
        @Test void conditionalRuleFieldsHideTheirLabelsWhenTheirModeChanges() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                edt(() -> {
                    var rules = (AutomaticRulesPanel) member(editor.ui, "automaticRules");
                    ((javax.swing.JButton) member(rules, "add")).doClick();
                    rules.urlMode.setSelectedItem(Config.UrlMode.SINGLE_URL); rules.prefix.setText("https://app.example/"); assertTrue(rules.prefix.isVisible());
                    rules.urlMode.setSelectedItem(Config.UrlMode.ALL_REQUESTS); assertFalse(rules.prefix.isVisible());
                    assertFalse(((javax.swing.JLabel) rules.prefix.getClientProperty("ruleLabel")).isVisible());
                    rules.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.BOTH);
                    assertTrue(rules.pattern.isVisible()); assertTrue(rules.failureStatus.isVisible());
                    rules.recoveryMode.setSelectedItem(JourneyDefinition.RecoveryMode.STATUS_CODE); assertFalse(rules.pattern.isVisible());
                });
            }
        }
        @Test void perTokenDestinationsStayWithTheirSourceAndIrrelevantFieldsAreCleared() throws Exception {
            try (var editor = new Editor(null)) {
                edt(() -> {
                    call(editor.ui, "newJourney", new Class<?>[]{}); editor.fields().get("url").setText("https://login.example/login");
                    CredentialsPanel sources = member(editor.ui, "credentials");
                    sources.setDefinition(new JourneyDefinition.CombinedExtraction(List.of(new JourneyDefinition.NamedExtraction("first", CombinedCredentialsTest.JSON), new JourneyDefinition.NamedExtraction("second", CombinedCredentialsTest.JSON))));
                    assertFalse(editor.fields().containsKey("authorizationToken"));
                    List<?> rows = member(sources, "rows");
                    var secondInjection = (javax.swing.JComboBox<String>) member(rows.get(1), "injection"); secondInjection.setSelectedItem("Header");
                    javax.swing.JTextField secondDestination = member(rows.get(1), "destination"); secondDestination.setText("X-CSRF-Token");
                    assertEquals("header", sources.snapshot().get(1).injection());
                    assertEquals("X-CSRF-Token", sources.snapshot().get(1).destination());
                    ((javax.swing.JButton) member(rows.getFirst(), "remove")).doClick();
                    assertEquals("header", sources.snapshot().getFirst().injection());
                    assertEquals("X-CSRF-Token", sources.snapshot().getFirst().destination());
                    assertFalse(CredentialsPanel.injectionNode(sources.snapshot()).path("tokens").get(0).has("tokenName"));
                    Object row = rows.getFirst(); javax.swing.JTextField origin = member(row, "origin"), selector = member(row, "selector");
                    assertTrue(origin.getToolTipText().contains("response")); assertFalse(origin.getToolTipText().contains("cookie"));
                    ((javax.swing.JComboBox<?>) member(row, "type")).setSelectedIndex(1);
                    assertTrue(origin.getToolTipText().contains("cookie")); assertFalse(origin.getToolTipText().contains("response"));
                    assertTrue(selector.getToolTipText().contains("cookie with the same name")); assertFalse(selector.getToolTipText().contains("array"));
                    assertEquals("", origin.getText()); assertEquals("", selector.getText());
                    assertTrue(CredentialsPanel.injectionNode(sources.snapshot()).path("tokens").isEmpty());
                    ((javax.swing.JComboBox<?>) member(row, "type")).setSelectedIndex(2);
                    javax.swing.JTextField start = member(row, "startRegex"), end = member(row, "endRegex");
                    assertTrue(((javax.swing.JPanel) member(row, "startLine")).isVisible());
                    assertFalse(((javax.swing.JPanel) member(row, "selectorLine")).isVisible());
                    start.setText("start"); end.setText("end");
                    origin.setText("https://login.example"); ((javax.swing.JTextField) member(row, "path")).setText("/page");
                    ((javax.swing.JComboBox<?>) member(row, "type")).setSelectedIndex(0);
                    assertEquals("", start.getText()); assertEquals("", end.getText());
                    assertEquals("https://login.example", origin.getText()); assertEquals("/page", sources.snapshot().getFirst().path());
                    var destinationMode = (javax.swing.JComboBox<String>) member(row, "injection"); destinationMode.setSelectedItem("Header");
                    ((javax.swing.JTextField) member(row, "destination")).setText("X-Token"); destinationMode.setSelectedItem("Cookie");
                    assertEquals("", sources.snapshot().getFirst().destination());
                });
            }
        }
        @Test void editorSavesRegexWithItsHeaderDestinationAndRendersBothWindowSizes() throws Exception {
            try (var editor = new Editor(fixture(ConfigManager.DocumentKind.PROJECT, false, false))) {
                edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, new SecretStore.Key(JourneyDefinition.Scope.PROJECT, JOURNEY)));
                await(() -> { try { return !((CredentialsPanel) member(editor.ui, "credentials")).snapshot().isEmpty(); } catch (Exception ex) { return false; } });
                edt(() -> {
                    CredentialsPanel sources = member(editor.ui, "credentials");
                    sources.setDefinition(RegexInjectionTest.REGEX, JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.HEADER, "X-CSRF-Token"))));
                    call(editor.ui, "edited", new Class<?>[]{});
                    call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
                });
                await(() -> editor.registry.snapshot().resolve("employee").definition().extraction() instanceof JourneyDefinition.RegexExtraction);
                var saved = editor.registry.snapshot().resolve("employee").definition();
                assertEquals(RegexInjectionTest.REGEX, saved.extraction());
                assertEquals("X-CSRF-Token", saved.injection().tokens().getFirst().name());
                edt(() -> {
                    CredentialsPanel sources = member(editor.ui, "credentials"); sources.setDefinition(RegexInjectionTest.sources(), RegexInjectionTest.mappings());
                    ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).setSelectedIndex(2);
                    var output = java.nio.file.Path.of("build", "ui-previews"); java.nio.file.Files.createDirectories(output);
                    for (int width : List.of(1280, 900)) {
                        editor.component.setSize(width, 820); layout(editor.component);
                        var image = new java.awt.image.BufferedImage(width, 820, java.awt.image.BufferedImage.TYPE_INT_RGB); var graphics = image.createGraphics(); editor.component.printAll(graphics); graphics.dispose();
                        javax.imageio.ImageIO.write(image, "png", output.resolve("regex-injection-" + width + ".png").toFile());
                        java.awt.Container parent = sources.getParent(); while (!(parent instanceof javax.swing.JScrollPane)) parent = parent.getParent();
                        var scroll = (javax.swing.JScrollPane) parent; scroll.getVerticalScrollBar().setValue(scroll.getVerticalScrollBar().getMaximum()); layout(editor.component);
                        graphics = image.createGraphics(); editor.component.printAll(graphics); graphics.dispose();
                        javax.imageio.ImageIO.write(image, "png", output.resolve("regex-injection-bottom-" + width + ".png").toFile());
                        scroll.getVerticalScrollBar().setValue(0);
                    }
                });
            }
        }
        @Test void wizardStepFollowsEachJourneyAcrossCollectionsAndMainTabs() throws Exception {
            String stored;
            try (var original = document(ConfigManager.DocumentKind.PROJECT)) {
                var first = original.journeys().getFirst();
                var other = changed(first.withIdentity(UUID.randomUUID(), List.of(), false), "other-account", "Other account");
                try (var project = definitions(original, List.of(first, other))) { stored = ConfigManager.nativeToJson(project); }
            }
            try (var editor = new Editor(stored)) {
                var first = editor.registry.snapshot().resolve("employee").identity().key();
                var other = editor.registry.snapshot().resolve("other-account").identity().key();
                SecretStore.Key libraryKey;
                try (var original = document(ConfigManager.DocumentKind.LIBRARY)) {
                    var libraryJourney = changed(original.journeys().getFirst(), "library-employee", "Library employee");
                    try (var library = definitions(original, List.of(libraryJourney))) { editor.registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, library); }
                    libraryKey = new SecretStore.Key(JourneyDefinition.Scope.LIBRARY, libraryJourney.id());
                }
                assertEquals(first.journeyId(), libraryKey.journeyId(), "scope must isolate page memory even when UUIDs match");
                openJourneyPage(editor, first); edt(() -> ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).setSelectedIndex(1));
                openJourneyPage(editor, other); edt(() -> { var wizard = (javax.swing.JTabbedPane) member(editor.ui, "wizard"); assertEquals(0, wizard.getSelectedIndex()); wizard.setSelectedIndex(2); });
                openJourneyPage(editor, first); edt(() -> {
                    var wizard = (javax.swing.JTabbedPane) member(editor.ui, "wizard"); assertEquals(1, wizard.getSelectedIndex());
                    var tabs = (javax.swing.JTabbedPane) member(editor.ui, "mainTabs"); tabs.setSelectedIndex(1); tabs.setSelectedIndex(2); tabs.setSelectedIndex(0);
                    assertEquals(1, wizard.getSelectedIndex());
                    ((javax.swing.JTabbedPane) member(editor.ui, "journeyScopes")).setSelectedIndex(1);
                });
                openJourneyPage(editor, libraryKey); edt(() -> { var wizard = (javax.swing.JTabbedPane) member(editor.ui, "wizard"); assertEquals(0, wizard.getSelectedIndex()); wizard.setSelectedIndex(4); });
                edt(() -> ((javax.swing.JTabbedPane) member(editor.ui, "journeyScopes")).setSelectedIndex(0)); awaitJourneyPage(editor, first);
                edt(() -> { assertEquals(1, ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).getSelectedIndex()); ((javax.swing.JTabbedPane) member(editor.ui, "journeyScopes")).setSelectedIndex(1); }); awaitJourneyPage(editor, libraryKey);
                edt(() -> { assertEquals(4, ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).getSelectedIndex()); call(editor.ui, "newJourney", new Class<?>[]{}); });
                await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
                edt(() -> assertEquals(0, ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).getSelectedIndex()));
                openJourneyPage(editor, libraryKey); edt(() -> assertEquals(4, ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).getSelectedIndex()));
                edt(() -> ((javax.swing.JTabbedPane) member(editor.ui, "journeyScopes")).setSelectedIndex(0)); awaitJourneyPage(editor, first);
                openJourneyPage(editor, other); edt(() -> assertEquals(2, ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).getSelectedIndex()));
            }
        }
        @Test void rememberedCertificatePageFallsBackWhenItIsNoLongerAvailable() throws Exception {
            String stored = edit(fixture(ConfigManager.DocumentKind.PROJECT, false, false), "/journeys/0", "mtls", Map.of(
                    "modulePath", "C:/owned-test/middleware.dll", "slot", Map.of("kind", "index", "value", 0),
                    "certificateSha256", "a".repeat(64), "origins", List.of("https://login.example")));
            try (var editor = new Editor(stored)) {
                var key = editor.registry.snapshot().resolve("employee").identity().key(); openJourneyPage(editor, key);
                edt(() -> ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).setSelectedIndex(3));
                try (var replacement = document(ConfigManager.DocumentKind.PROJECT)) { editor.registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, replacement); }
                edt(() -> call(editor.ui, "bump", new Class<?>[]{JourneyDefinition.Scope.class}, JourneyDefinition.Scope.PROJECT));
                openJourneyPage(editor, key);
                edt(() -> { var wizard = (javax.swing.JTabbedPane) member(editor.ui, "wizard"); assertFalse(wizard.isEnabledAt(3)); assertEquals(2, wizard.getSelectedIndex()); });
                openJourneyPage(editor, key); edt(() -> assertEquals(2, ((javax.swing.JTabbedPane) member(editor.ui, "wizard")).getSelectedIndex()));
            }
        }
        /** @param editor Owned local Swing editor. @param key Saved journey to open without driving an installed application. */
        private void openJourneyPage(Editor editor, SecretStore.Key key) throws Exception { edt(() -> call(editor.ui, "open", new Class<?>[]{SecretStore.Key.class}, key)); awaitJourneyPage(editor, key); }
        /** @param editor Owned local editor. @param key Exact expected scope/UUID after asynchronous loading. */
        private void awaitJourneyPage(Editor editor, SecretStore.Key key) throws Exception { await(() -> { try { return key.equals(member(editor.ui, "editing")) && !(boolean) member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } }); }

        @Test void wizardSkipsDisabledCertificateStepAndRendersEachPageWithoutProxyCredentialControls() throws Exception {
            try (var editor = new Editor(null)) {
                edt(() -> {
                    call(editor.ui, "newJourney", new Class<?>[]{}); editor.fields().get("url").setText("http://127.0.0.1:1/login");
                    var wizard = (javax.swing.JTabbedPane) member(editor.ui, "wizard"); wizard.setSelectedIndex(2);
                    call(editor.ui, "moveWizard", new Class<?>[]{int.class}, 1); assertEquals(4, wizard.getSelectedIndex());
                    assertFalse(editor.fields().containsKey("proxyUser")); assertFalse(editor.fields().containsKey("proxyPassword"));
                    assertEquals("Remember secrets", editor.checks().get("remember").getText()); editor.checks().get("mtls").doClick();
                    try (var empty = SecretStore.Values.empty()) {
                        ((StepsPanel) member(editor.ui, "steps")).setSteps(List.of(
                                new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.INPUT, "#username", "demo-user", null, null, null),
                                new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.SECURE_INPUT, "#password", null, null, null, null),
                                new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.WAIT_TIME, null, null, null, null, 1500)), empty);
                    }
                    var output = java.nio.file.Path.of("build", "ui-previews"); java.nio.file.Files.createDirectories(output);
                    for (int page = 0; page < wizard.getTabCount(); page++) {
                        wizard.setSelectedIndex(page); editor.component.setSize(1280, 820); layout(editor.component);
                        var image = new java.awt.image.BufferedImage(1280, 820, java.awt.image.BufferedImage.TYPE_INT_RGB); var graphics = image.createGraphics(); editor.component.printAll(graphics); graphics.dispose();
                        javax.imageio.ImageIO.write(image, "png", output.resolve("wizard-page-" + (page + 1) + ".png").toFile());
                    }
                    CredentialsPanel sources = member(editor.ui, "credentials"); sources.setDefinition(CombinedCredentialsTest.SOURCES); wizard.setSelectedIndex(2);
                    editor.component.setSize(1280, 820); layout(editor.component);
                    var combinedImage = new java.awt.image.BufferedImage(1280, 820, java.awt.image.BufferedImage.TYPE_INT_RGB); var combinedGraphics = combinedImage.createGraphics(); editor.component.printAll(combinedGraphics); combinedGraphics.dispose();
                    javax.imageio.ImageIO.write(combinedImage, "png", output.resolve("wizard-multiple-credentials.png").toFile());
                });
            }
        }
        /** @param component Our own isolated Swing tree, laid out recursively for a test artifact only. */
        void layout(java.awt.Component component) { if (component instanceof java.awt.Container parent) { parent.doLayout(); for (var child : parent.getComponents()) layout(child); } }
    }
}

package bpsh.journey.editing;

import bpsh.journey.AuthStep;
import bpsh.journey.BrowserSetup;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyDraft;
import java.net.URI;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the distinction between recording admission and executable journey compilation. */
class BrowserSetupCompilerTest {
    private static JourneyDraft draft(Map<String, String> overrides, boolean mtls, boolean unfinished) {
        var text = new LinkedHashMap<String, String>();
        for (String field : List.of("name", "alias", "url", "navTimeout", "tokenWait", "proxy", "maxAge", "skew", "module", "slot", "origins", "ca")) text.put(field, "");
        text.putAll(Map.of("name", "Setup fixture", "alias", "setup", "url", "https://example.test/login",
                "navTimeout", "5", "tokenWait", "3", "maxAge", "1800", "skew", "10", "slot", "0"));
        if (mtls) {
            text.put("module", Path.of("build", "not-a-device.so").toAbsolutePath().toString());
            text.put("origins", "https://identity.test");
        }
        text.putAll(overrides);
        var steps = unfinished ? List.of(new JourneyDraft.StepInput(UUID.randomUUID(), AuthStep.Type.WAIT_TIME, "", "unfinished", ""))
                : List.<JourneyDraft.StepInput>of();
        var credentials = List.of(new JourneyDraft.CredentialInput("access", "json_path",
                unfinished ? "" : "https://example.test", "/token", unfinished ? "" : "access_token", "", "", "", "", "bearer", ""));
        return new JourneyDraft(text, Map.of("headless", true, "remember", false, "mtls", mtls),
                JourneyDefinition.SlotKind.INDEX, "12".repeat(32), steps, credentials);
    }

    @Test void recordingAdmissionIgnoresUnfinishedStepsCaptureNamesAndCache() {
        var raw = draft(Map.of("name", "", "alias", "not an alias", "tokenWait", "unfinished", "maxAge", "unfinished", "skew", "unfinished"), false, true);
        var setup = BrowserSetupCompiler.compile(raw);
        assertEquals(URI.create("https://example.test/login"), setup.authenticationUrl());
        assertEquals(5000, setup.browser().navigationTimeoutMs());
        assertEquals(3000, setup.browser().tokenWaitTimeoutMs());
        assertTrue(setup.browser().headless()); assertNull(setup.mtls());
        assertThrows(ConfigurationException.class, () -> JourneyDraftCompiler.compile(raw, UUID.randomUUID()));
    }

    @Test void setupAndFullJourneyShareProxyAndCertificateValidationWithoutLoadingADevice() {
        var raw = draft(Map.of("proxy", "http://127.0.0.1:8080"), true, false);
        assertEquals(BrowserSetup.from(JourneyDraftCompiler.compile(raw, UUID.randomUUID())), BrowserSetupCompiler.compile(raw));
        assertTrue(BrowserSetupCompiler.compile(raw).mtls().origins().contains(URI.create("https://example.test")));
        var badSlot = draft(Map.of("slot", "-1"), true, false);
        assertThrows(ConfigurationException.class, () -> BrowserSetupCompiler.compile(badSlot));
        assertThrows(ConfigurationException.class, () -> JourneyDraftCompiler.compile(badSlot, UUID.randomUUID()));
    }

    @Test void unfinishedJourneyDoesNotBypassUnsafeSetupValidation() {
        var proxy = draft(Map.of("proxy", "http://user:CANARY_PROXY_PASSWORD@localhost:8080"), false, true);
        var failure = assertThrows(ConfigurationException.class, () -> BrowserSetupCompiler.compile(proxy));
        assertTrue(failure.getMessage().contains("browser.proxy"));
        assertFalse(failure.getMessage().contains("CANARY_PROXY_PASSWORD"));
        assertThrows(ConfigurationException.class, () -> BrowserSetupCompiler.compile(draft(Map.of("url", "file:///private"), false, true)));
        assertThrows(ConfigurationException.class, () -> BrowserSetupCompiler.compile(draft(Map.of("navTimeout", "0.0001"), false, true)));
    }

    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings = {"access", ""})
    void aSingleCredentialKeepsItsOptionalNameAndMatchingInjectionWhenCompiled(String name) {
        var raw = draft(Map.of(), false, false); var input = raw.credentials().getFirst();
        var credential = new JourneyDraft.CredentialInput(name, input.type(), input.origin(), input.path(), input.selector(), input.domain(),
                input.cookiePath(), input.startRegex(), input.endRegex(), input.injection(), input.destination());
        var changed = new JourneyDraft(raw.text(), raw.flags(), raw.slotKind(), raw.certificateSha256(), raw.steps(), List.of(credential));
        var compiled = JourneyDraftCompiler.compile(changed, UUID.randomUUID());
        if (name.isEmpty()) {
            assertInstanceOf(JourneyDefinition.JsonExtraction.class, compiled.extraction());
            assertNull(compiled.injection().tokens().getFirst().tokenName());
        } else {
            var selected = assertInstanceOf(JourneyDefinition.CombinedExtraction.class, compiled.extraction()).tokens().getFirst();
            assertEquals(name, selected.name()); assertInstanceOf(JourneyDefinition.JsonExtraction.class, selected.selector());
            assertEquals(name, compiled.injection().tokens().getFirst().tokenName());
        }
    }
}

package bpsh.journey.editing;

import bpsh.burp.ui.JourneyRegistryTest;
import bpsh.journey.*;
import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;
import java.net.URI;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class JourneyDuplicationTest {
    @ParameterizedTest @EnumSource(JourneyDefinition.Scope.class)
    void copiesSettingsAndSecretsWithIndependentIdentitiesAndSessionOnlyPersistence(JourneyDefinition.Scope scope) {
        var kind = scope == JourneyDefinition.Scope.PROJECT ? JourneyDocument.DocumentKind.PROJECT : JourneyDocument.DocumentKind.LIBRARY;
        try (var secrets = new SecretStore(); var source = JourneyRegistryTest.document(kind)) {
            var original = source.journeys().getFirst();
            var click = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.CLICK, "#open", null, null, null, null);
            var popup = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.EXPECT_POPUP, null, null, null, null, null, new AuthStep.Popup("login", click.id()));
            var mtls = new JourneyDefinition.Mtls(java.nio.file.Path.of("build", "fixtures", "test-module").toAbsolutePath().toString(), new JourneyDefinition.Slot(JourneyDefinition.SlotKind.INDEX, 0), "a".repeat(64), List.of(URI.create("https://login.example")), null);
            var http = new HttpAuthentication(HttpAuthentication.Protocol.BASIC, "fixture-user", "", "", Set.of(URI.create("https://login.example")));
            var configured = new JourneyDefinition(original.id(), original.displayName(), original.alias(), original.authenticationUrl(), true,
                    List.of(popup, click, original.steps().getFirst()), original.browser(), original.extraction(), original.injection(), original.cache(), mtls, http, null);
            try (var values = new SecretStore.Values("fixture-pin".toCharArray(), Map.of(JourneyRegistryTest.STEP, "fixture-secret".toCharArray()), "fixture-http".toCharArray());
                 var loaded = new JourneyDocument(kind, source.revision(), List.of(configured), List.of(), source.controls(), Map.of(original.id(), values))) {
                var workspace = new JourneyWorkspace(secrets); workspace.replaceLoaded(scope, loaded);
                var key = new JourneyKey(scope, original.id()); var identity = workspace.snapshot().entries().get(key).identity();
                try (var preview = workspace.prepareDuplicate(key)) {
                    var copy = preview.journeys().getLast();
                    assertEquals(1, workspace.snapshot().entries().size(), "preview must not publish before storage commits");
                    assertEquals("Employee copy", copy.displayName()); assertEquals("employee-copy", copy.alias());
                    assertNotEquals(original.id(), copy.id()); assertFalse(copy.rememberSecrets());
                    assertEquals(configured.browser(), copy.browser()); assertEquals(configured.mtls(), copy.mtls());
                    assertEquals(configured.httpAuthentication(), copy.httpAuthentication()); assertEquals(configured.extraction(), copy.extraction());
                    assertEquals(configured.injection(), copy.injection()); assertEquals(configured.cache(), copy.cache());
                    for (int i = 0; i < configured.steps().size(); i++) assertNotEquals(configured.steps().get(i).id(), copy.steps().get(i).id());
                    assertEquals(copy.steps().get(1).id(), ((AuthStep.Popup) copy.steps().getFirst().operation()).triggerStepId());
                    var copiedValues = preview.secrets().get(copy.id()); var step = copy.steps().getLast().id();
                    assertArrayEquals("fixture-secret".toCharArray(), copiedValues.stepValue(step));
                    assertArrayEquals("fixture-pin".toCharArray(), copiedValues.pin()); assertArrayEquals("fixture-http".toCharArray(), copiedValues.httpPassword());
                    try (var disk = JourneyJson.read(JourneyJson.write(preview), kind)) {
                        assertFalse(disk.secrets().containsKey(copy.id()), "remembered source values must not make the copy persistent");
                    }
                    workspace.replaceLoaded(scope, preview); secrets.remove(key);
                    try (var retained = secrets.snapshot(new JourneyKey(scope, copy.id()))) { assertArrayEquals("fixture-secret".toCharArray(), retained.stepValue(step)); }
                    assertEquals(identity, workspace.snapshot().entries().get(key).identity(), "copying must preserve the source generation");
                }
            }
        }
    }

    @Test void unfinishedDraftsRetainLiteralInputAndRemapPopupTriggers() {
        try (var secrets = new SecretStore()) {
            UUID id = UUID.randomUUID(), trigger = UUID.randomUUID();
            var draft = JourneyDraft.capture(Map.of("name", "Unfinished", "alias", "unfinished", "url", "bad url", "navTimeout", "unfinished number"),
                    Map.of("remember", true), JourneyDefinition.SlotKind.INDEX, "", List.of(
                            new JourneyDraft.StepInput(UUID.randomUUID(), AuthStep.Type.EXPECT_POPUP, "", "", "", JourneyDraft.DurationUnit.SECONDS, new JourneyDraft.Popup("partial", trigger.toString())),
                            new JourneyDraft.StepInput(trigger, AuthStep.Type.CLICK, "unfinished selector", "", "")), List.of());
            try (var source = new JourneyDocument(JourneyDocument.DocumentKind.PROJECT, UUID.randomUUID(), List.of(draft.definition(id, "Unfinished", "unfinished", true)), List.of(), bpsh.request.RequestSettings.Controls.defaults(), Map.of())) {
                var workspace = new JourneyWorkspace(secrets); workspace.replaceLoaded(JourneyDefinition.Scope.PROJECT, source);
                try (var preview = workspace.prepareDuplicate(new JourneyKey(JourneyDefinition.Scope.PROJECT, id));
                     var disk = JourneyJson.read(JourneyJson.write(preview), preview.kind())) {
                    var copy = disk.journeys().getLast(); var raw = copy.draft();
                    assertEquals("Unfinished copy", raw.text().get("name")); assertEquals(copy.alias(), raw.text().get("alias"));
                    assertEquals("bad url", raw.text().get("url")); assertEquals("unfinished number", raw.text().get("navTimeout")); assertFalse(raw.flags().get("remember"));
                    assertEquals(raw.steps().get(1).id().toString(), ((JourneyDraft.Popup) raw.steps().getFirst().operation()).triggerStepId());
                    assertEquals(draft, workspace.snapshot().resolve("unfinished").definition().draft());
                }
            }
        }
    }

    @Test void namesAvoidAliasesAcrossCollectionsAndKeepSuffixWithinLimits() {
        try (var secrets = new SecretStore(); var source = JourneyRegistryTest.document(JourneyDocument.DocumentKind.PROJECT)) {
            var workspace = new JourneyWorkspace(secrets); var original = source.journeys().getFirst();
            var longName = "A".repeat(128); var named = JourneyRegistryTest.changed(original, "a".repeat(64), longName);
            try (var loaded = JourneyRegistryTest.definitions(source, List.of(named));
                 var library = new JourneyDocument(JourneyDocument.DocumentKind.LIBRARY, UUID.randomUUID(),
                         List.of(JourneyRegistryTest.changed(original.withIdentity(UUID.randomUUID(), original.steps(), false), "a".repeat(59) + "-copy", "Other")), List.of(), null, Map.of())) {
                workspace.replaceLoaded(JourneyDefinition.Scope.PROJECT, loaded); workspace.replaceLoaded(JourneyDefinition.Scope.LIBRARY, library);
                var key = new JourneyKey(JourneyDefinition.Scope.PROJECT, original.id());
                try (var preview = workspace.prepareDuplicate(key)) {
                    var copy = preview.journeys().getLast(); assertTrue(copy.displayName().endsWith(" copy 2")); assertTrue(copy.alias().endsWith("-copy-2")); assertEquals(64, copy.alias().length());
                    workspace.replaceLoaded(JourneyDefinition.Scope.PROJECT, preview);
                }
                try (var preview = workspace.prepareDuplicate(key)) { assertTrue(preview.journeys().getLast().displayName().endsWith(" copy 3")); }
            }
        }
    }

    @Test void missingOrUnavailableSourcesCannotProduceAPreview() {
        try (var secrets = new SecretStore(); var source = JourneyRegistryTest.document(JourneyDocument.DocumentKind.PROJECT)) {
            var workspace = new JourneyWorkspace(secrets); var key = new JourneyKey(JourneyDefinition.Scope.PROJECT, JourneyRegistryTest.JOURNEY);
            assertThrows(IllegalStateException.class, () -> workspace.prepareDuplicate(key));
            workspace.replaceLoaded(key.scope(), source); workspace.disableScope(key.scope());
            assertThrows(IllegalStateException.class, () -> workspace.prepareDuplicate(key)); assertEquals(1, workspace.snapshot().entries().size());
        }
    }
}

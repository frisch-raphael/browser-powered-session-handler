package bpsh.ui;

import bpsh.credentials.CombinedCredentialsTest;
import bpsh.http.NativeTagPipelineTest;
import bpsh.model.JourneyDefinition;
import bpsh.session.CoordinatorFixtures;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the request menu through SDK boundary doubles; these are not installed-Burp UI tests. */
class UxRequestMenuTest {
    /** @return Every named-token/encoding choice, with caret insertion and selection replacement. */
    static Stream<Arguments> choices() {
        return Stream.of("access", "session").flatMap(token -> java.util.stream.IntStream.range(0, 4).boxed()
                .flatMap(format -> Stream.of(false, true).map(selection -> Arguments.of(token, format, selection))));
    }
    /** @return Invalid editor offset shapes and a read-only editor failure. */
    static Stream<Arguments> rejectedEdits() { return Stream.of(Arguments.of(-1, 0, false), Arguments.of(20, 19, false), Arguments.of(0, 10000, false), Arguments.of(10000, 10000, false), Arguments.of(0, 0, true)); }

    @ParameterizedTest @MethodSource("rejectedEdits")
    void invalidOffsetsAndReadOnlyEditorsProduceActionableErrorsWithoutAcquisition(int start, int end, boolean readOnly) throws Exception {
        var hooks = new NativeTagPipelineTest().new ProductionHooks();
        try (var fixture = new NativeTagPipelineTest.Fixture(); var host = hooks.new Host(fixture)) {
            var request = host.request(NativeTagPipelineTest.header("existing"), 1, false); var reports = new ArrayList<String>();
            var pair = host.stub(burp.api.montoya.http.message.HttpRequestResponse.class, (m, a) -> m.getName().equals("request") ? request : null);
            var range = host.stub(burp.api.montoya.core.Range.class, (m, a) -> m.getName().equals("startIndexInclusive") ? start : end);
            var writes = new java.util.concurrent.atomic.AtomicInteger();
            var editor = host.stub(burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class, (m, a) -> switch (m.getName()) {
                case "selectionContext" -> burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
                case "selectionOffsets" -> Optional.of(range); case "caretPosition" -> start; case "requestResponse" -> pair;
                case "setRequest" -> { writes.incrementAndGet(); if (readOnly) throw new IllegalStateException("sensitive host detail"); yield null; }
                default -> null;
            });
            var event = host.stub(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (m, a) -> m.getName().equals("messageEditorRequestResponse") ? Optional.of(editor) : null);
            var root = (JMenu) new AuthenticationTagMenu(fixture.registry, reports::add).provideMenuItems(event).getFirst();
            SwingUtilities.invokeAndWait(() -> ((JMenu) root.getItem(0)).getItem(0).doClick());
            assertEquals(readOnly ? 1 : 0, writes.get()); assertEquals(1, reports.size());
            assertTrue(reports.getFirst().contains(readOnly ? "editable request in Repeater" : "Place the cursor again")); assertFalse(reports.getFirst().contains("sensitive host detail")); assertTrue(fixture.clock.workers.isEmpty());
        }
    }

    @ParameterizedTest @MethodSource("choices")
    void namedCredentialMenuInsertsOnlyChosenLiteralReference(String token, int format, boolean selection) throws Exception {
        var hooks = new NativeTagPipelineTest().new ProductionHooks();
        try (var fixture = new NativeTagPipelineTest.Fixture(); var host = hooks.new Host(fixture)) {
            var original = fixture.definitions.getFirst();
            var journey = new JourneyDefinition(original.id(), original.displayName(), original.alias(), original.authenticationUrl(), false,
                    original.steps(), original.browser(), CombinedCredentialsTest.SOURCES, CombinedCredentialsTest.INJECTION, original.cache(), null);
            CoordinatorFixtures.load(fixture.registry, List.of(journey));
            String wire = NativeTagPipelineTest.header("Bearer selected-text"); int start = wire.indexOf("selected-text"); int end = selection ? start + "selected-text".length() : start;
            var current = new AtomicReference<burp.api.montoya.http.message.requests.HttpRequest>(host.request(wire, 1, false));
            var pair = host.stub(burp.api.montoya.http.message.HttpRequestResponse.class, (m, a) -> m.getName().equals("request") ? current.get() : null);
            var range = host.stub(burp.api.montoya.core.Range.class, (m, a) -> m.getName().equals("startIndexInclusive") ? start : end);
            var editor = host.stub(burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class, (m, a) -> switch (m.getName()) {
                case "selectionContext" -> burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
                case "selectionOffsets" -> selection ? Optional.of(range) : Optional.empty(); case "caretPosition" -> start; case "requestResponse" -> pair;
                case "setRequest" -> { current.set((burp.api.montoya.http.message.requests.HttpRequest) a[0]); yield null; }
                default -> null;
            });
            var event = host.stub(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (m, a) -> m.getName().equals("messageEditorRequestResponse") ? Optional.of(editor) : null);
            var reports = new ArrayList<String>(); var root = (JMenu) new AuthenticationTagMenu(fixture.registry, reports::add).provideMenuItems(event).getFirst();
            var alias = (JMenu) root.getItem(0); assertEquals("employee", alias.getText()); assertEquals(2, alias.getItemCount());
            JMenu names = (JMenu) alias.getItem(token.equals("access") ? 0 : 1); assertEquals(token, names.getText()); assertEquals(4, names.getItemCount());
            SwingUtilities.invokeAndWait(() -> names.getItem(format).doClick());
            String raw = "<@employee token=\"" + token + "\"/>";
            String expected = switch (format) { case 1 -> "<@url>" + raw + "</@url>"; case 2 -> "<@form>" + raw + "</@form>"; case 3 -> "<@json>" + raw + "</@json>"; default -> raw; };
            assertEquals(wire.substring(0, start) + expected + wire.substring(end), new String(current.get().toByteArray().getBytes(), StandardCharsets.ISO_8859_1));
            assertTrue(reports.isEmpty()); assertTrue(fixture.clock.workers.isEmpty()); assertEquals(0, fixture.attempts);
        }
    }

    @Test void responseAndListContextsHaveNoInsertionActionAndEmptyRegistryHasAnHonestMenu() {
        var hooks = new NativeTagPipelineTest().new ProductionHooks();
        try (var fixture = new NativeTagPipelineTest.Fixture(); var host = hooks.new Host(fixture)) {
            var menu = new AuthenticationTagMenu(fixture.registry, message -> fail(message));
            var list = host.stub(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (m, a) -> m.getName().equals("messageEditorRequestResponse") ? Optional.empty() : null);
            assertTrue(menu.provideMenuItems(list).isEmpty());
            var response = host.stub(burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class, (m, a) -> m.getName().equals("selectionContext") ? burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext.RESPONSE : null);
            var responseEvent = host.stub(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (m, a) -> m.getName().equals("messageEditorRequestResponse") ? Optional.of(response) : null);
            assertTrue(menu.provideMenuItems(responseEvent).isEmpty());
            CoordinatorFixtures.load(fixture.registry, List.of());
            var request = host.request(NativeTagPipelineTest.header("existing"), 1, false);
            var pair = host.stub(burp.api.montoya.http.message.HttpRequestResponse.class, (m, a) -> m.getName().equals("request") ? request : null);
            var editor = host.stub(burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.class, (m, a) -> switch (m.getName()) {
                case "selectionContext" -> burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
                case "selectionOffsets" -> Optional.empty(); case "caretPosition" -> 0; case "requestResponse" -> pair; default -> null;
            });
            var event = host.stub(burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, (m, a) -> m.getName().equals("messageEditorRequestResponse") ? Optional.of(editor) : null);
            var root = (JMenu) menu.provideMenuItems(event).getFirst(); assertEquals(1, root.getItemCount()); assertEquals("Save a journey first", root.getItem(0).getText()); assertFalse(root.getItem(0).isEnabled());
        }
    }
}

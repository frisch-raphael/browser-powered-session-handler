package bpsh.burp.ui;

import bpsh.journey.JourneyCatalog;
import bpsh.journey.JourneyDefinition;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.*;

/** Inserts literal saved references at the request selection without acquiring or exposing credentials. */
public final class AuthenticationTagMenu implements ContextMenuItemsProvider {
    static final List<String> FORMATS = List.of("Raw", "URL component", "Form value", "JSON string content");
    private final JourneyCatalog registry;
    private final Consumer<String> report;
    /** @param registry Current saved identities. @param report Safe insertion-error sink. */
    public AuthenticationTagMenu(JourneyCatalog registry, Consumer<String> report) { this.registry = registry; this.report = report; }
    /**
     * Builds aliases and explicit named-token choices from one current registry publication.
     * @param event Request editor invocation; response and list-only invocations have no insertion menu.
     * @return Native menu hierarchy, or no contribution outside a request editor.
     */
    @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
        var selected = event.messageEditorRequestResponse();
        if (selected.isEmpty() || selected.get().selectionContext() != MessageEditorHttpRequestResponse.SelectionContext.REQUEST) return List.of();
        var editor = selected.get(); byte[] original = editor.requestResponse().request().toByteArray().getBytes();
        int start = editor.selectionOffsets().map(r -> r.startIndexInclusive()).orElse(editor.caretPosition());
        int end = editor.selectionOffsets().map(r -> r.endIndexExclusive()).orElse(start);
        var root = new JMenu("Add authentication"); var snapshot = registry.snapshot();
        snapshot.entries().values().stream().filter(e -> snapshot.isCurrent(e.identity())).sorted(java.util.Comparator.comparing(e -> e.definition().canonicalAlias())).forEach(entry -> {
            var journey = new JMenu(entry.definition().alias()); root.add(journey);
            if (entry.definition().transportAuthenticationEnabled()) {
                var http = new JMenuItem(entry.definition().httpAuthenticationEnabled() ? "Authenticate HTTP as this user" : "Use this client certificate"); journey.add(http);
                http.addActionListener(action -> {
                    if (!registry.snapshot().isCurrent(entry.identity())) { report.accept("The journey changed. Reopen the authentication menu."); return; }
                    var request = editor.requestResponse().request();
                    if (!Arrays.equals(original, request.toByteArray().getBytes())) { report.accept("The request changed. Reopen the authentication menu."); return; }
                    try { editor.setRequest(request.withRemovedHeader("BPSP-HTTP-AUTHENT").withAddedHeader("BPSP-HTTP-AUTHENT", "<@" + entry.definition().alias() + "/>")); }
                    catch (RuntimeException failure) { report.accept("Open an editable request in Repeater to add HTTP authentication."); }
                });
                if (!hasCredentialCapture(entry.definition())) return;
                journey.addSeparator();
            }
            if (!hasCredentialCapture(entry.definition())) return;
            if (entry.definition().extraction() instanceof JourneyDefinition.CombinedExtraction combined && combined.tokens().size() > 1) {
                for (var token : combined.tokens()) { var item = new JMenu(token.name()); journey.add(item); formats(item, entry, token.name(), editor, original, start, end); }
            } else formats(journey, entry, null, editor, original, start, end);
        });
        if (root.getItemCount() == 0) { var empty = new JMenuItem("Save a journey first"); empty.setEnabled(false); root.add(empty); }
        return List.of(root);
    }
    /**
     * Offers explicit encodings without guessing the credential's destination syntax.
     * @param parent Alias/token submenu.
     * @param entry Captured saved identity.
     * @param token Optional user-defined token name.
     * @param editor Invoking request editor.
     * @param original Captured exact request bytes.
     * @param start Selection/caret start.
     * @param end Selection/caret end.
     */
    private void formats(JMenu parent, JourneyCatalog.Entry entry, String token, MessageEditorHttpRequestResponse editor, byte[] original, int start, int end) {
        for (String format : FORMATS) {
            var item = new JMenuItem(format); parent.add(item);
            item.addActionListener(e -> insert(entry, token, format, editor, original, start, end));
        }
    }
    /**
     * Rechecks both the saved identity and editor bytes before replacing the user's selected range.
     * @param entry Saved definition approved in the open menu.
     * @param token Optional exact token name.
     * @param format Explicit encoding choice.
     * @param editor Target request editor.
     * @param original Original request bytes.
     * @param start Inclusive selected offset.
     * @param end Exclusive selected offset.
     */
    private void insert(JourneyCatalog.Entry entry, String token, String format, MessageEditorHttpRequestResponse editor, byte[] original, int start, int end) {
        if (!registry.snapshot().isCurrent(entry.identity())) { report.accept("The journey changed. Reopen Add authentication and select it again."); return; }
        var request = editor.requestResponse().request();
        if (!Arrays.equals(original, request.toByteArray().getBytes()) || start < 0 || end < start || end > original.length) { report.accept("The request changed. Place the cursor again and reopen Add authentication."); return; }
        byte[] replacement = tag(entry.definition().alias(), token, format).getBytes(StandardCharsets.US_ASCII);
        byte[] result = new byte[original.length - (end - start) + replacement.length];
        System.arraycopy(original, 0, result, 0, start); System.arraycopy(replacement, 0, result, start, replacement.length); System.arraycopy(original, end, result, start + replacement.length, original.length - end);
        try { editor.setRequest(HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(result))); }
        catch (RuntimeException ex) { report.accept("This request editor could not be updated. Open an editable request in Repeater and insert the tag there."); }
    }
    /**
     * Builds only literal source notation, without evaluating or reading any cached credential.
     * @param alias Validated journey alias.
     * @param token Optional validated token name.
     * @param format Explicit encoding label.
     * @return Literal raw reference or one encoding wrapper.
     */
    static String tag(String alias, String token, String format) {
        String raw = "<@" + alias + (token == null ? "" : " token=\"" + token + "\"") + "/>";
        String wrapper = switch (format) { case "URL component" -> "url"; case "Form value" -> "form"; case "JSON string content" -> "json"; default -> null; };
        return wrapper == null ? raw : "<@" + wrapper + ">" + raw + "</@" + wrapper + ">";
    }
    /** @return Whether this saved definition has outputs for credential-reference choices. */
    static boolean hasCredentialCapture(JourneyDefinition definition) {
        return definition.extraction() != null && (!(definition.extraction() instanceof JourneyDefinition.CombinedExtraction combined) || !combined.tokens().isEmpty());
    }
    /** @return Literal custom request header selecting a saved HTTP authentication identity, without credentials. */
    static String httpHeader(String alias) { return "BPSP-HTTP-AUTHENT: " + tag(alias, null, "Raw"); }
}

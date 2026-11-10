package bpsh.burp.ui;

import bpsh.journey.HttpAuthentication;
import bpsh.journey.JourneyCatalog;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import bpsh.journey.persistence.JourneyDocument;
import bpsh.journey.persistence.JourneyJson;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.http.*;
import bpsh.journey.SecretStore;
import java.util.concurrent.CompletableFuture;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises HTTP identity editing, inline failures and request-header actions with isolated native components. */
class HttpAuthenticationUiTest {
    @org.junit.jupiter.api.io.TempDir Path root;

    private JourneyRegistryTest.NativeUi harness() {
        var h = new JourneyRegistryTest().new NativeUi(); h.root = root; return h;
    }
    private static String project(boolean capture) throws Exception {
        try (var source = JourneyRegistryTest.document(JourneyDocument.DocumentKind.PROJECT)) {
            var base = source.journeys().getFirst();
            var http = new HttpAuthentication(HttpAuthentication.Protocol.BASIC, "fixture-user", "", "", java.util.Set.of(URI.create("https://login.example")));
            var journey = new JourneyDefinition(base.id(), base.displayName(), base.alias(), base.authenticationUrl(), false,
                    capture ? base.steps() : List.of(), base.browser(), capture ? base.extraction() : null,
                    capture ? base.injection() : JourneyDefinition.Injection.perToken(List.of()), base.cache(), base.mtls(), http, null);
            try (var document = new JourneyDocument(source.kind(), source.revision(), List.of(journey), List.of(), source.controls(), Map.of())) {
                return JourneyJson.write(document);
            }
        }
    }
    private static void open(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor, JourneyKey key) throws Exception {
        h.edt(() -> h.call(editor.ui, "open", new Class<?>[]{JourneyKey.class}, key));
        h.await(() -> { try { return !(boolean) h.member(editor.ui, "editorLoading"); } catch (Exception error) { return false; } });
    }
    private static List<String> clipboard(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor) throws Exception {
        var copied = new ArrayList<String>();
        h.edt(() -> {
            var dialogs = new JourneyDialogs() {
                public Path file(java.awt.Component parent, boolean save) { throw new AssertionError("Unexpected file chooser"); }
                public boolean confirm(java.awt.Component parent, Object content, String title) { throw new AssertionError("Unexpected confirmation"); }
                public void inform(java.awt.Component parent, String text) { fail(text); }
                public void copyText(String text) { copied.add(text); }
            };
            var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true); field.set(editor.ui, dialogs);
        });
        return copied;
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void httpOnlyCopiesTheHeaderDirectlyAndMixedJourneysRetainCredentialFormats(boolean capture) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(project(capture))) {
            var entry = editor.registry.snapshot().resolve("employee"); open(h, editor, entry.identity().key());
            var copied = clipboard(h, editor);
            h.edt(() -> {
                JButton button = h.member(editor.ui, "copyReferenceButton");
                var menu = (JPopupMenu) h.call(editor.ui, "referenceMenu", new Class<?>[]{JourneyCatalog.Entry.class}, entry);
                assertEquals("HTTP authentication header", ((JMenuItem) menu.getComponent(0)).getText());
                if (!capture) {
                    assertEquals("Copy HTTP authentication header", button.getText());
                    assertFalse(button.getToolTipText().contains("valid token"));
                    assertEquals(1, menu.getComponentCount(), "HTTP-only journeys have no captured-value formats");
                    button.doClick(0);
                    assertEquals(List.of("BPSP-HTTP-AUTHENT: <@employee/>"), copied);
                } else {
                    assertEquals("Copy BPSH tag", button.getText());
                    assertEquals(6, menu.getComponentCount());
                    ((JMenuItem) menu.getComponent(0)).doClick(0);
                    ((JMenuItem) menu.getComponent(2)).doClick(0);
                    ((JMenuItem) menu.getComponent(5)).doClick(0);
                    assertEquals(List.of("BPSP-HTTP-AUTHENT: <@employee/>", "<@employee/>", "<@json><@employee/></@json>"), copied);
                }
                assertTrue(editor.clock.workers.isEmpty()); assertNull(editor.coordinator.peek(entry.identity()));
            });
        }
    }

    @Test void renamingUpdatesTheHeaderExampleAndSavedCopyWithoutInventingCaptures() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(project(false))) {
            var entry = editor.registry.snapshot().resolve("employee"); var key = entry.identity().key(); open(h, editor, key);
            var copied = clipboard(h, editor); var obsolete = new java.util.concurrent.atomic.AtomicReference<JMenuItem>();
            h.edt(() -> {
                HttpAuthenticationPanel panel = h.member(editor.ui, "httpAuthentication"); JTextArea help = h.member(panel, "help");
                assertTrue(help.getText().contains("BPSP-HTTP-AUTHENT: <@employee/>"));
                assertTrue(help.getText().contains("custom header")); assertTrue(help.getText().contains("for that request"));
                assertTrue(help.getText().contains("removes the custom header before sending"));
                var menu = (JPopupMenu) h.call(editor.ui, "referenceMenu", new Class<?>[]{JourneyCatalog.Entry.class}, entry);
                obsolete.set((JMenuItem) menu.getComponent(0));
                editor.fields().get("name").setText("Finance login");
                assertTrue(help.getText().contains("BPSP-HTTP-AUTHENT: <@finance-login/>"));
                assertFalse(help.getText().contains("journey-alias"));
                h.call(editor.ui, "save", new Class<?>[]{boolean.class}, false);
            });
            h.await(() -> { try { return editor.saved(); } catch (Exception error) { return false; } });
            h.edt(() -> {
                assertTrue(editor.registry.snapshot().resolve(key).definition().httpOnly());
                assertTrue(((CredentialsPanel) h.member(editor.ui, "credentials")).snapshot().isEmpty());
                obsolete.get().doClick(0); assertTrue(copied.isEmpty(), "An obsolete menu must not copy an old journey name");
                ((JButton) h.member(editor.ui, "copyReferenceButton")).doClick(0);
                assertEquals(List.of("BPSP-HTTP-AUTHENT: <@finance-login/>"), copied);
                assertTrue(editor.clock.workers.isEmpty());
            });
        }
    }

    @Test void allowedOriginFormattingAndScopeAreTooltipsOnTheFieldAndItsLabel() throws Exception {
        var h = harness(); h.edt(() -> {
            var panel = new HttpAuthenticationPanel(() -> {});
            Map<String, JTextField> fields = h.member(panel, "fields"); var origins = fields.get("httpOrigins");
            assertTrue(origins.getToolTipText().contains("separated by commas"));
            assertTrue(origins.getToolTipText().contains("https://login.example:8443"));
            assertTrue(origins.getAccessibleContext().getAccessibleDescription().contains("No paths"));
            assertFalse(origins.getAccessibleContext().getAccessibleDescription().contains("<html>"));
            JLabel label = java.util.Arrays.stream(panel.getComponents()).filter(c -> c instanceof JLabel title && title.getLabelFor() == origins).map(JLabel.class::cast).findFirst().orElseThrow();
            assertEquals(origins.getToolTipText(), label.getToolTipText());
            assertEquals(origins.getAccessibleContext().getAccessibleDescription(), label.getAccessibleContext().getAccessibleDescription());
            JTextArea help = h.member(panel, "help"); assertFalse(help.getText().contains("Allowed origins are"));
        });
    }

    private static List<String> resultDialogs(JourneyRegistryTest.NativeUi h, JourneyRegistryTest.NativeUi.Editor editor) throws Exception {
        var results = new java.util.concurrent.CopyOnWriteArrayList<String>();
        h.edt(() -> {
            JourneyDialogs dialogs = new JourneyDialogs() {
                public Path file(java.awt.Component parent, boolean save) { throw new AssertionError("Unexpected file chooser"); }
                public boolean confirm(java.awt.Component parent, Object content, String title) { throw new AssertionError("Unexpected confirmation"); }
                public void inform(java.awt.Component parent, String text) { results.add(text); }
            };
            var field = UiController.class.getDeclaredField("dialogs"); field.setAccessible(true); field.set(editor.ui, dialogs);
        });
        return results;
    }

    @ParameterizedTest @ValueSource(strings = {"", "https://login.example/private", "invalid-private-origin"})
    void invalidOriginsRevealTheExactInlineErrorWithoutAResultDialog(String value) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(project(true))) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            var results = resultDialogs(h, editor);
            HttpAuthenticationPanel panel = h.member(editor.ui, "httpAuthentication");
            Map<String,JTextField> fields = h.member(panel, "fields"); var origins = fields.get("httpOrigins");
            h.edt(() -> {
                origins.setText(value);
                ((JButton)h.member(editor.ui, "testButton")).doClick(0);
            });
            h.await(() -> ((JTextArea)origins.getClientProperty("validationMessage")).isVisible());
            h.edt(() -> {
                var error = (JTextArea)origins.getClientProperty("validationMessage");
                assertTrue(error.getText().contains(value.isEmpty() ? "enter at least one exact" : value.startsWith("https:") ? "cannot include a page path" : "use exact HTTP(S) server addresses"), error.getText());
                assertFalse(error.getText().contains("invalid-private-origin"));
                assertEquals("HTTP authentication", WizardTestPages.selected(h.member(editor.ui, "wizard")));
                assertTrue(results.isEmpty()); assertTrue(editor.clock.workers.isEmpty());
                origins.setText("https://login.example"); assertFalse(error.isVisible());
                assertTrue(origins.getAccessibleContext().getAccessibleDescription().contains("No paths"));
            });
        }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void missingPasswordIsInlineForThePasswordAndNoPopupEvenWhenTheFailureIsWrapped(boolean wrapped) throws Exception {
        var h = harness();
        try (var editor = h.new Editor(project(false))) {
            var entry = editor.registry.snapshot().resolve("employee"); open(h, editor, entry.identity().key());
            var results = resultDialogs(h, editor);
            var failure = new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.MISSING_SECRET,
                    "Enter the HTTP authentication password before testing.").atInput(AuthenticationFailure.Input.HTTP_PASSWORD);
            HttpTransportFactory factory = new HttpTransportFactory() {
                public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec, SecretStore.Values values, long deadline) {
                    return CompletableFuture.failedFuture(wrapped ? new java.util.concurrent.CompletionException(failure) : failure);
                }
                public HttpMessageBody.Allocator bodies() { return new HttpMessageBody.Allocator(1024); }
                public void close() {}
            };
            try (var manager = new HttpIdentityManager(editor.registry, editor.secrets, factory)) {
                h.edt(() -> { editor.ui.httpIdentities(manager); ((JButton)h.member(editor.ui, "testButton")).doClick(0); });
                HttpAuthenticationPanel panel = h.member(editor.ui, "httpAuthentication"); JPasswordField password = h.member(panel, "password");
                h.await(() -> ((JTextArea)password.getClientProperty("validationMessage")).isVisible());
                h.edt(() -> {
                    assertEquals(failure.getMessage(), ((JTextArea)password.getClientProperty("validationMessage")).getText());
                    assertEquals("HTTP authentication", WizardTestPages.selected(h.member(editor.ui, "wizard")));
                    assertTrue(results.isEmpty());
                    password.setText("new-fixture-password");
                    assertFalse(((JTextArea)password.getClientProperty("validationMessage")).isVisible());
                });
            }
        }
    }

    @Test void rejectedHttpIdentityShowsTheObservedStatusAtTheGroupWithoutBlamingThePassword() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(project(false))) {
            var entry = editor.registry.snapshot().resolve("employee"); open(h, editor, entry.identity().key());
            var results = resultDialogs(h, editor);
            HttpTransportFactory factory = new HttpTransportFactory() {
                private final HttpMessageBody.Allocator allocator = new HttpMessageBody.Allocator(1024);
                public CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec, SecretStore.Values values, long deadline) {
                    return CompletableFuture.completedFuture(new HttpAuthenticationService() {
                        public boolean isOpen() { return true; }
                        public void close() {}
                        public Delivery admit(long until) { return new Delivery() {
                            public CompletableFuture<Response> exchange(Request request) {
                                try (var builder = allocator.builder(0)) {
                                    return CompletableFuture.completedFuture(new Response(401, List.of(), builder.finish(),
                                            new HttpAuthenticationEvidence(HttpAuthentication.Protocol.BASIC, HttpAuthenticationEvidence.Status.REJECTED)));
                                }
                            }
                            public void close() {}
                        }; }
                    });
                }
                public HttpMessageBody.Allocator bodies() { return allocator; }
                public void close() {}
            };
            try (var manager = new HttpIdentityManager(editor.registry, editor.secrets, factory)) {
                h.edt(() -> { editor.ui.httpIdentities(manager); ((JButton)h.member(editor.ui, "testButton")).doClick(0); });
                HttpAuthenticationPanel panel = h.member(editor.ui, "httpAuthentication"); JComboBox<?> protocol = h.member(panel, "protocol");
                h.await(() -> ((JTextArea)protocol.getClientProperty("validationMessage")).isVisible());
                h.edt(() -> {
                    assertTrue(((JTextArea)protocol.getClientProperty("validationMessage")).getText().contains("HTTP 401"));
                    JPasswordField password = h.member(panel, "password");
                    assertFalse(((JTextArea)password.getClientProperty("validationMessage")).isVisible());
                    assertEquals("HTTP authentication", WizardTestPages.selected(h.member(editor.ui, "wizard")));
                    assertTrue(results.isEmpty());
                });
            }
        }
    }

    @Test void backgroundValidationKeepsTheCurrentPageAndSecretPathsFindThePassword() throws Exception {
        var h = harness();
        try (var editor = h.new Editor(project(false))) {
            open(h, editor, editor.registry.snapshot().resolve("employee").identity().key());
            h.edt(() -> {
                WizardTestPages.select(h.member(editor.ui, "wizard"), "Test & use");
                h.call(editor.ui, "showInvalidField", new Class<?>[]{String.class,String.class,boolean.class}, "secrets.httpPassword:", "Enter the password.", false);
                assertEquals("Test & use", WizardTestPages.selected(h.member(editor.ui, "wizard")));
                HttpAuthenticationPanel panel = h.member(editor.ui, "httpAuthentication"); JPasswordField password = h.member(panel, "password");
                assertEquals("Enter the password.", ((JTextArea)password.getClientProperty("validationMessage")).getText());
            });
        }
    }

    @Test void emptyUsernameRevealsUsernameRatherThanAGenericAuthenticationError() throws Exception {
        var h=harness();
        try(var editor=h.new Editor(project(true))) {
            open(h,editor,editor.registry.snapshot().resolve("employee").identity().key());
            var results=resultDialogs(h,editor);HttpAuthenticationPanel panel=h.member(editor.ui,"httpAuthentication");
            Map<String,JTextField> fields=h.member(panel,"fields");var username=fields.get("httpUsername");
            h.edt(()->{username.setText("");((JButton)h.member(editor.ui,"testButton")).doClick(0);});
            h.await(()->((JTextArea)username.getClientProperty("validationMessage")).isVisible());
            h.edt(()->{
                assertTrue(((JTextArea)username.getClientProperty("validationMessage")).getText().contains("enter a username"));
                assertEquals("HTTP authentication",WizardTestPages.selected(h.member(editor.ui,"wizard")));assertTrue(results.isEmpty());
            });
        }
    }

    @Test void browserLoginHttpFailureRevealsThePasswordWithoutAResultDialog() throws Exception {
        var h=harness();
        var failure=new AuthenticationFailure(AuthenticationFailure.Phase.SETUP,AuthenticationFailure.Cause.MISSING_SECRET,
                "Enter the HTTP authentication password before testing.").atInput(AuthenticationFailure.Input.HTTP_PASSWORD);
        try(var editor=h.new Editor(project(true),(entry,recovery,deadline,cancelled)->{throw failure;})) {
            open(h,editor,editor.registry.snapshot().resolve("employee").identity().key());var results=resultDialogs(h,editor);
            h.edt(()->((JButton)h.member(editor.ui,"testButton")).doClick(0));
            h.await(()->!editor.clock.workers.isEmpty());editor.clock.runWorker();
            HttpAuthenticationPanel panel=h.member(editor.ui,"httpAuthentication");JPasswordField password=h.member(panel,"password");
            h.await(()->((JTextArea)password.getClientProperty("validationMessage")).isVisible());
            h.edt(()->{
                assertEquals(failure.getMessage(),((JTextArea)password.getClientProperty("validationMessage")).getText());
                assertEquals("HTTP authentication",WizardTestPages.selected(h.member(editor.ui,"wizard")));assertTrue(results.isEmpty());
            });
        }
    }
}

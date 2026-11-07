package bpsh.ui;

import bpsh.browser.BrowserFailureClassifier;
import bpsh.config.Config;
import bpsh.config.ConfigManager;
import bpsh.credentials.AuthenticationResult;
import bpsh.credentials.CredentialUse;
import bpsh.credentials.TokenExtractorTest;
import bpsh.events.JourneyEventLog;
import bpsh.http.SessionRecovery;
import bpsh.http.SessionRecoveryTest;
import bpsh.model.AuthenticationFailure;
import bpsh.model.JourneyDefinition;
import bpsh.model.JourneyKey;
import bpsh.session.AuthenticationCoordinator;
import bpsh.session.AuthenticationCoordinatorTest;
import bpsh.session.CoordinatorFixtures;
import bpsh.support.AuthLabSupport;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Establishes bounded history, actual coordinator coverage and native event-dock behavior. */
class JourneyEventLogTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary;
    private static final Instant NOW = Instant.parse("2026-11-05T12:00:00Z");
    /** @return Fresh stable owner independent of its readable alias. */
    private static JourneyKey key() { return new JourneyKey(JourneyDefinition.Scope.PROJECT, UUID.randomUUID()); }

    @Test void historyIsIsolatedByStableIdentityAndCoalescesRepeatedWarnings() {
        var log = new JourneyEventLog(); var first = key(); var second = key();
        log.append(first, NOW, JourneyEventLog.Level.ERROR, "Missing PIN. Enter it in certificate settings.");
        log.append(second, NOW, JourneyEventLog.Level.INFO, "Login succeeded.");
        log.append(first, NOW.plusSeconds(1), JourneyEventLog.Level.ERROR, "Missing PIN. Enter it in certificate settings.");
        assertEquals(1, log.snapshot(first).size()); assertEquals(1, log.snapshot(second).size());
        assertFalse(log.snapshot(first).getFirst().message().contains("succeeded"));
        log.clear(first); assertTrue(log.snapshot(first).isEmpty()); assertEquals(1, log.snapshot(second).size());
        log.close(); log.append(first, NOW, JourneyEventLog.Level.INFO, "Late completion."); assertTrue(log.snapshot(first).isEmpty());
    }
    @Test void bothPerJourneyAndTotalHistoryHaveFiniteBounds() {
        var log = new JourneyEventLog(); var first = key();
        for (int i = 0; i < 250; i++) log.append(first, NOW.plusSeconds(i), JourneyEventLog.Level.INFO, "Attempt " + i);
        assertEquals(200, log.snapshot(first).size()); assertEquals("Attempt 50", log.snapshot(first).getFirst().message());
        var owners = java.util.stream.IntStream.range(0, 24).mapToObj(i -> key()).toList();
        for (var owner : owners) for (int i = 0; i < 200; i++) log.append(owner, NOW.plusSeconds(i), JourneyEventLog.Level.INFO, "Event " + i);
        assertEquals(4000, owners.stream().mapToInt(owner -> log.snapshot(owner).size()).sum()); assertTrue(log.snapshot(first).isEmpty());
        log.append(first, NOW, JourneyEventLog.Level.ERROR, "x".repeat(10000)); assertTrue(log.snapshot(first).getFirst().message().length() <= JourneyEventLog.MESSAGE_LIMIT + 1);
    }
    @Test void automaticAcquisitionLogsLifecycleWithoutDependingOnUiPollingOrRetainingTokenValues() throws Exception {
        long start = System.nanoTime(), ready, checked; var observed = new java.util.LinkedHashMap<String, Object>();
        try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults())) {
            ready = System.nanoTime();
            var owner = fixture.entry(0).identity().key(); var ticket = fixture.acquire(0); fixture.clock.runWorker(); ticket.future().join();
            var messages = fixture.coordinator.events().snapshot(owner).stream().map(JourneyEventLog.Event::message).toList();
            assertEquals(List.of("Authentication queued.", "Login attempt 1 started.", "Credentials captured."), messages);
            assertFalse(messages.toString().contains("fixture-")); assertTrue(fixture.coordinator.events().snapshot(fixture.entry(1).identity().key()).isEmpty());
            var state = fixture.coordinator.status(fixture.entry(0).identity());
            observed.put("nativePhase", state.phase().name()); observed.put("nativeCause", "NONE");
            observed.put("stateMatches", state.phase() == AuthenticationCoordinator.Phase.READY && state.usableToken() && state.failure() == null);
            observed.put("currentRevision", fixture.registry.snapshot().isCurrent(fixture.entry(0).identity())); observed.put("protectedUseVerified", state.acceptedUse());
            SwingUtilities.invokeAndWait(() -> {
                var panel = new JourneyEventLogPanel(fixture.coordinator.events(), () -> {}); panel.refresh(owner, "employee");
                var table = member(panel, "table", JTable.class); int row = table.getRowCount() - 1; table.setRowSelectionInterval(row, row);
                String summary = table.getValueAt(row, 2).toString(), details = member(panel, "detail", JTextArea.class).getText();
                String rendered = ((JLabel) table.prepareRenderer(table.getCellRenderer(row, 2), row, 2)).getText();
                observed.put("summaryMatches", summary.equals(messages.getLast()) && rendered.equals(summary) && table.getValueAt(row, 1).equals("Info"));
                observed.put("detailsMatch", details.contains(messages.getLast()) && details.contains("Type: Info"));
                var outputs = List.of(summary, details);
                observed.put("redacted", outputs.stream().noneMatch(text -> text.contains("fixture-")));
                observed.put("requiredMessageMatches", outputs.stream().allMatch(text -> {
                    String lower = text.toLowerCase(java.util.Locale.ROOT);
                    boolean captured = lower.contains("credential") && (lower.contains("captur") || lower.contains("extract"));
                    boolean qualified = (lower.contains("protected") || lower.contains("service"))
                            && (lower.contains("unverified") || lower.contains("not verified") || lower.contains("not been verified"));
                    boolean claimsAcceptance = lower.contains("login succeeded") || lower.contains("authenticated") || lower.contains("request accepted") || lower.contains("access verified");
                    return captured && (qualified || !claimsAcceptance);
                }));
                observed.put("forbiddenClaimAbsent", outputs.stream().noneMatch(text -> text.toLowerCase(java.util.Locale.ROOT).contains("protected access verified")));
            });
            fixture.coordinator.invalidate(fixture.entry(0).identity()); assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("cleared"));
            checked = System.nanoTime();
        }
        AuthLabSupport.component("CORE.diagnostics.extraction-only-success", observed, java.util.Map.of("startupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(ready - start),
                "caseMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(checked - ready), "cleanupMs", java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - checked)));
        assertAll(observed.entrySet().stream().filter(e -> e.getValue() instanceof Boolean && !e.getKey().equals("protectedUseVerified")).map(e -> (org.junit.jupiter.api.function.Executable) () ->
                assertTrue((boolean) e.getValue(), "Extraction-only presentation must satisfy " + e.getKey() + "; protected access has not been verified.")));
    }
    @Test void applicationResponseFeedbackReportsItsStatusWithoutClaimingAuthentication() {
        for (int status : List.of(200, 204)) try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults());
                var recovery = new SessionRecovery(fixture.coordinator, fixture.clock::nanos)) {
            var ticket = fixture.acquire(0); fixture.clock.runWorker(); ticket.future().join();
            var entry = fixture.entry(0); var token = fixture.coordinator.peek(entry.identity());
            var rule = new JourneyDefinition.Recovery(false, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
            recovery.record(17, List.of(new CredentialUse(entry.identity(), token.version(), rule)), false);
            recovery.receivedPlan(17, status, () -> { throw new AssertionError("Status feedback must not inspect a login page's body."); }, false, true);
            var message = fixture.coordinator.events().snapshot(entry.identity().key()).getLast().message();
            assertEquals("Request using this journey's credentials returned HTTP " + status + ".", message);
            assertFalse(message.toLowerCase().contains("accepted"));
        }
    }
    @org.junit.jupiter.api.TestFactory java.util.stream.Stream<org.junit.jupiter.api.DynamicTest> terminalFailuresRecordSafeRecovery() {
        return List.of("attempts-exhausted","protected-use-rejected","success-after-failure","stale-result").stream().map(variant->
            org.junit.jupiter.api.DynamicTest.dynamicTest("[case=CORE.diagnostics."+variant+"]",()->transitionPresentation(variant)));
    }
    /** Extends the event owner with actual editor/coordinator transitions, using simulated backoff. */
    private void transitionPresentation(String variant) throws Exception {
        long began=System.nanoTime();var h=new JourneyRegistryTest().new NativeUi();h.root=java.nio.file.Files.createTempDirectory(temporary,"transition-");
        var attempts=new java.util.concurrent.atomic.AtomicInteger();var succeeds=new java.util.concurrent.atomic.AtomicBoolean(variant.equals("protected-use-rejected")||variant.equals("stale-result"));
        var runtime=new java.util.concurrent.atomic.AtomicReference<CoordinatorFixtures.ManualRuntime>();
        java.util.Map<String,Object> observed;
        try(var editor=h.new Editor(JourneyRegistryTest.fixture(ConfigManager.DocumentKind.PROJECT,false,false),Config.Controls.defaults(),(entry,recovery,deadline,cancelled)->{
            attempts.incrementAndGet();
            if(!succeeds.get()) {
                if(variant.equals("attempts-exhausted"))throw BrowserFailureClassifier.networkFailure("ERR_CONNECTION_REFUSED");
                var extractor=TokenExtractorTest.json("access_token");extractor.considerJson(TokenExtractorTest.bytes("{}"));throw assertThrows(AuthenticationFailure.class,extractor::result);
            }
            return new AuthenticationResult(entry.identity(),"CANARY_CAPTURED_CREDENTIAL",runtime.get().instant(),runtime.get().nanos());
        })) {
            runtime.set(editor.clock);
            var original=editor.registry.snapshot().resolve("employee");var owner=original.identity().key();
            h.edt(()->h.call(editor.ui,"open",new Class<?>[]{JourneyKey.class},owner));h.await(()->{try{return !(boolean)h.member(editor.ui,"editorLoading");}catch(Exception error){return false;}});
            h.edt(()->h.call(editor.ui,"authenticate",new Class<?>[]{boolean.class},false));h.await(()->!editor.clock.workers.isEmpty());
            if(variant.equals("stale-result")) {
                var held=editor.clock.workers.poll();assertNotNull(held);
                h.edt(()->editor.fields().get("url").setText("https://login.example/revised-login"));h.await(()->{try{return editor.saved();}catch(Exception error){return false;}});
                var replacement=editor.registry.snapshot().resolve("employee");assertTrue(replacement.identity().generation()>original.identity().generation());
                h.edt(()->h.call(editor.ui,"authenticate",new Class<?>[]{boolean.class},false));held.run();h.await(()->!editor.clock.workers.isEmpty());editor.clock.runWorker();assertNull(editor.coordinator.peek(original.identity()));
            } else {
                editor.clock.runWorker();
                if(variant.equals("attempts-exhausted")){editor.clock.advance(5000);editor.clock.runWorker();editor.clock.advance(15_000);editor.clock.runWorker();assertEquals(3,attempts.get());}
                else if(variant.equals("success-after-failure")) {
                    assertNotNull(editor.coordinator.status(original.identity()).failure());succeeds.set(true);
                    h.edt(()->h.call(editor.ui,"authenticate",new Class<?>[]{boolean.class},false));h.await(()->!editor.clock.workers.isEmpty());editor.clock.runWorker();
                    assertTrue(editor.coordinator.events().snapshot(owner).stream().anyMatch(e->e.level()==JourneyEventLog.Level.ERROR));
                } else {
                    var initial=editor.coordinator.peek(original.identity());assertNotNull(initial);var rule=SessionRecoveryTest.lossRule();
                    var recovery=editor.coordinator.recover(List.of(new CredentialUse(initial.identity(),initial.version(),rule)));editor.clock.runWorker();assertTrue(recovery.future().isDone());
                    var replacement=editor.coordinator.peek(original.identity());assertNotEquals(initial.version(),replacement.version());
                    editor.coordinator.rejectedReplacement(editor.coordinator.provenance(new CredentialUse(replacement.identity(),replacement.version(),rule),true),403);
                }
            }
            var current=editor.registry.snapshot().resolve("employee");boolean success=variant.equals("success-after-failure")||variant.equals("stale-result");var state=editor.coordinator.status(current.identity());
            assertEquals(success?AuthenticationCoordinator.Phase.READY:AuthenticationCoordinator.Phase.PAUSED,state.phase());
            if(success){assertNull(state.failure());assertNotNull(editor.coordinator.peek(current.identity()));}
            else{assertNotNull(state.failure());assertNull(editor.coordinator.peek(current.identity()));int before=attempts.get();editor.clock.advance(3_600_000);assertTrue(editor.clock.workers.isEmpty());assertEquals(before,attempts.get());}
            var captured=new java.util.concurrent.atomic.AtomicReference<java.util.Map<String,Object>>();
            h.edt(()->{
                h.call(editor.ui,"refreshJourneyUi",new Class<?>[]{});SessionStatusBar bar=h.member(editor.ui,"status");if(!bar.isLogOpen())((JToggleButton)h.member(bar,"eventLog")).doClick(0);
                JourneyEventLogPanel panel=h.member(editor.ui,"eventLog");JTable table=h.member(panel,"table");int row=table.getRowCount()-1;assertTrue(row>=0);table.setRowSelectionInterval(row,row);
                String summary=table.getValueAt(row,2).toString(),details=((JTextArea)h.member(panel,"detail")).getText();var last=editor.coordinator.events().snapshot(owner).getLast();String expected=success?"Credentials captured.":state.failure().getMessage(),severity=success?"Info":"Error";
                var messages=new java.util.ArrayList<>(List.of(summary,details,bar.getText()));var facts=new java.util.LinkedHashMap<String,Object>();
                facts.put("nativePhase",success?"READY":state.failure().phase().name());facts.put("nativeCause",success?"NONE":state.failure().reason().name());
                facts.put("summaryMatches",summary.equals(expected)&&last.message().equals(expected)&&table.getValueAt(row,1).equals(severity));facts.put("detailsMatch",details.contains(expected)&&details.contains("Type: "+severity));
                String currentText=bar.getText().toLowerCase(java.util.Locale.ROOT);
                facts.put("stateMatches",success?state.failure()==null&&state.usableToken()&&currentText.contains("credentials")&&currentText.contains("captur"):bar.getText().equals(expected)&&!state.usableToken()&&state.failure()!=null);
                facts.put("currentRevision",current.identity().equals(h.member(editor.ui,"editingIdentity"))&&editor.registry.snapshot().isCurrent(current.identity())&&(!variant.equals("stale-result")||current.identity().generation()>original.identity().generation()&&editor.coordinator.peek(original.identity())==null));
                if(success)facts.put("protectedUseVerified",state.acceptedUse());
                else {
                    var tagged=editor.diagnostics.request(990,current.definition().alias(),state.failure(),true);var ordinary=editor.diagnostics.request(991,current.definition().alias(),state.failure(),false);messages.add(tagged.text());messages.add(ordinary.text());
                    facts.put("requestFeedbackMatches",tagged.requestStopped()&&!ordinary.requestStopped()&&tagged.text().contains("Request was not sent.")&&ordinary.text().contains("unchanged request was sent"));
                    facts.put("noPartialPublication",editor.coordinator.peek(current.identity())==null);
                }
                List<String> required=variant.equals("attempts-exhausted")?List.of("connection","refused","paused after 3 attempts"):variant.equals("protected-use-rejected")?List.of("application","rejected","replacement"):List.of("credentials","captured");
                facts.put("requiredMessageMatches",messages.stream().allMatch(text->required.stream().allMatch(word->text.toLowerCase(java.util.Locale.ROOT).contains(word))));
                facts.put("forbiddenClaimAbsent",messages.stream().noneMatch(text->{String lower=text.toLowerCase(java.util.Locale.ROOT);return lower.contains("incorrect password")||lower.contains("extraction failed")||lower.contains("login succeeded")||success&&lower.contains("no string");}));
                facts.put("redacted",messages.stream().noneMatch(text->text.contains("CANARY")||text.contains("https://login.example")));
                if(variant.equals("attempts-exhausted")){facts.put("attempts",attempts.get());facts.put("state",state.phase().name());}captured.set(facts);
            });
            observed=captured.get();assertNotNull(observed);
        }
        AuthLabSupport.component("CORE.diagnostics."+variant,observed,java.util.Map.of("startupMs",0L,"caseMs",java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began),"cleanupMs",0L));
        assertAll(observed.entrySet().stream().filter(e->e.getValue() instanceof Boolean&&!e.getKey().equals("protectedUseVerified")).map(e->(org.junit.jupiter.api.function.Executable)()->assertTrue((boolean)e.getValue(),"Current presentation must satisfy "+e.getKey()+" for "+variant)));
    }
    @Test void backgroundRetryAndCancellationAreRecordedWithoutUiCallers() {
        try (var fixture = new AuthenticationCoordinatorTest.Fixture(Config.Controls.defaults())) {
            fixture.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT));
            fixture.acquire(0); fixture.clock.runWorker();
            var owner = fixture.entry(0).identity().key();
            assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("Retrying in 5 seconds"));
            fixture.clock.advance(5000); assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("attempt 2"));
            assertTrue(fixture.coordinator.cancelAuthentication(fixture.entry(0).identity()));
            assertTrue(fixture.coordinator.events().snapshot(owner).getLast().message().contains("cancelled"));
            assertEquals(JourneyEventLog.Level.WARNING, fixture.coordinator.events().snapshot(owner).getLast().level());
        }
    }
    @Test void eventDockFiltersLiteralTextAndSeverityAndSwitchesJourneyWithoutLeakingDetails() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var log = new JourneyEventLog(); var first = key(); var second = key();
            log.append(first, NOW, JourneyEventLog.Level.INFO, "Login started."); log.append(first, NOW.plusSeconds(1), JourneyEventLog.Level.ERROR, "<html>Missing cookie.");
            log.append(second, NOW, JourneyEventLog.Level.WARNING, "Cancelled.");
            var panel = new JourneyEventLogPanel(log, () -> {}); panel.refresh(first, "employee");
            var table = member(panel, "table", JTable.class); assertEquals(2, table.getRowCount());
            var search = member(panel, "search", JTextField.class); search.setText("<html>"); assertEquals(1, table.getRowCount());
            table.setRowSelectionInterval(0, 0); assertTrue(member(panel, "detail", JTextArea.class).getText().contains("<html>Missing cookie."));
            assertEquals("<html>Missing cookie.", ((JLabel) table.prepareRenderer(table.getCellRenderer(0, 2), 0, 2)).getText());
            search.setText(""); panel.refresh(second, "admin"); assertEquals(1, table.getRowCount());
            assertFalse(member(panel, "detail", JTextArea.class).getText().contains("cookie"));
            @SuppressWarnings("unchecked") var levels = (java.util.Map<JourneyEventLog.Level, JToggleButton>) member(panel, "levels", java.util.Map.class);
            levels.get(JourneyEventLog.Level.WARNING).doClick(); assertEquals(0, table.getRowCount());
            levels.get(JourneyEventLog.Level.WARNING).doClick(); member(panel, "clear", JButton.class).doClick(); assertEquals(0, table.getRowCount()); assertEquals(2, log.snapshot(first).size());
        });
    }
    @Test void compactDockKeepsTimestampAndEventDetailReadable() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new JourneyEventLogPanel(new JourneyEventLog(), () -> {});
            panel.setSize(960, 310); layout(panel); layout(panel); panel.initializeDivider(); layout(panel);
            var split = member(panel, "detailSplit", JSplitPane.class);
            assertTrue(split.getRightComponent().getWidth() >= 280);
            var table = member(panel, "table", JTable.class);
            assertTrue(table.getColumnModel().getColumn(0).getMinWidth() > table.getFontMetrics(table.getFont()).stringWidth("23:59:59 31 Dec 2026"));
        });
    }
    /** @param component Owned local layout subtree. */
    private static void layout(java.awt.Component component) { if (component instanceof java.awt.Container container) { container.doLayout(); for (var child : container.getComponents()) layout(child); } }
    /** @param target Owned test component. @param name Stable private seam. @param type Expected member type. @return Local component, never an installed-app control. */
    private static <T> T member(Object target, String name, Class<T> type) { try { var field = target.getClass().getDeclaredField(name); field.setAccessible(true); return type.cast(field.get(target)); } catch (ReflectiveOperationException error) { throw new AssertionError(error); } }
}

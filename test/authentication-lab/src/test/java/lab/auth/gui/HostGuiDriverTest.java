package lab.auth.gui;

import com.google.gson.*;
import java.awt.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import lab.auth.*;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiDriverTest {
    @Test void browserStepSignalsRemainFixedCategoriesWithoutPrivateValues() {
        for(var row:java.util.Map.of("Step 4 \u2014 Click element timed out.","BROWSER_STEP_TIMEOUT",
                "Step 4 \u2014 Click element failed.","BROWSER_STEP_FAILED").entrySet()) {
            var signals=HostGuiDiagnostics.failureSignals(java.util.List.of(row.getKey()+" PRIVATE_PASSWORD C:/PRIVATE_PATH"));
            assertTrue(((java.util.List<?>)signals.get("markers")).contains(row.getValue()));
            assertFalse(signals.toString().contains("PRIVATE_"));
        }
    }
    @Test void selectedJourneyRememberingTestPageRevealsSetupBeforeVerifyingItsVisibleName() {
        HostGuiSelectors.edt(()->{
            var pages=new javax.swing.JTabbedPane();var setup=new javax.swing.JPanel();pages.addTab("Setup",setup);
            pages.addTab("Test & use",new javax.swing.JPanel());pages.setSelectedIndex(1);
            var name=new javax.swing.JTextField("Chosen journey"){
                @Override public boolean isShowing(){return pages.getSelectedIndex()==0;}
            };
            name.getAccessibleContext().setAccessibleName("name");setup.add(name);
            var selected=new javax.swing.JList<>(new String[]{"Chosen journey"});selected.setSelectedIndex(0);
            var setupVisits=new AtomicInteger();
            HostGuiDriver.verifyJourneyEditor(pages,selected,0,"Chosen journey",()->{
                setupVisits.incrementAndGet();pages.setSelectedIndex(0);
            },condition->assertTrue(condition.getAsBoolean(),"A hidden name must not stall verification on a remembered Test page"));
            assertEquals(1,setupVisits.get());assertTrue(name.isShowing());return true;
        });
    }
    @Test void visibleJourneyVerificationWaitsForTheSelectedEditorsOwnNameAndEnabledInput() {
        HostGuiSelectors.edt(()->{
            var root=new javax.swing.JPanel();var name=new javax.swing.JTextField("Previous journey"){
                @Override public boolean isShowing(){return true;}
            };
            name.getAccessibleContext().setAccessibleName("name");root.add(name);
            var selected=new javax.swing.JList<>(new String[]{"Chosen journey"});selected.setSelectedIndex(0);
            var waits=new AtomicInteger();
            HostGuiDriver.verifyJourneyEditor(root,selected,0,"Chosen journey",()->{},condition->{
                if(waits.incrementAndGet()==1){assertTrue(condition.getAsBoolean());return;}
                assertFalse(condition.getAsBoolean(),"Old editor contents must not qualify the selected journey");
                name.setText("Chosen journey");name.setEnabled(false);assertFalse(condition.getAsBoolean());
                name.setEnabled(true);assertTrue(condition.getAsBoolean());
                selected.clearSelection();assertFalse(condition.getAsBoolean());
            });
            assertEquals(2,waits.get());return true;
        });
    }
    @Test void startupSelectionRequiresOneShowingOwnedModalOrOtherwiseOneShowingFrame() {
        record Candidate(boolean showing,boolean modal,boolean frame){}
        var frame=new Candidate(true,false,true);var hidden=new Candidate(false,true,false);var modal=new Candidate(true,true,false);
        assertSame(frame,HostGuiDiagnostics.startupWindow(java.util.List.of(frame,hidden),Candidate::showing,Candidate::modal,Candidate::frame));
        assertSame(modal,HostGuiDiagnostics.startupWindow(java.util.List.of(frame,modal),Candidate::showing,Candidate::modal,Candidate::frame));
        assertNull(HostGuiDiagnostics.startupWindow(java.util.List.of(frame,new Candidate(true,false,true)),Candidate::showing,Candidate::modal,Candidate::frame));
        assertNull(HostGuiDiagnostics.startupWindow(java.util.List.of(modal,new Candidate(true,true,false)),Candidate::showing,Candidate::modal,Candidate::frame));
        assertNull(HostGuiDiagnostics.startupWindow(java.util.List.of(new Candidate(true,false,false)),Candidate::showing,Candidate::modal,Candidate::frame));
    }
    @Test void startupInventoryRetainsOnlyFixedWizardCategoriesNotCaptionsOrInputValues() {
        HostGuiSelectors.edt(()->{
            var panel=new javax.swing.JPanel();panel.add(new javax.swing.JButton("Next"));panel.add(new javax.swing.JLabel("Next >"));
            var start=new javax.swing.JButton("Start Burp");start.setEnabled(false);panel.add(start);
            panel.add(new javax.swing.JButton("PRIVATE_CAPTION"));panel.add(new javax.swing.JTextField("Next"));
            panel.add(new javax.swing.JPasswordField("Start Burp"));
            var controls=HostGuiDiagnostics.startupControls(panel);assertEquals(3,controls.size());
            assertEquals(2,controls.stream().filter(row->row.get("category").equals("NEXT")).count());
            assertEquals(false,controls.stream().filter(row->row.get("category").equals("START_BURP")).findFirst().orElseThrow().get("enabled"));
            assertFalse(controls.toString().contains("PRIVATE_"));assertFalse(controls.toString().contains("Start Burp"));
            assertEquals("BURP_COMMUNITY",HostGuiDiagnostics.startupTitleCategory("Burp Suite Community Edition v2026.10.1 - Temporary project"));
            assertEquals("DELETE_TEMP_FILES",HostGuiDiagnostics.startupTitleCategory("Delete old temporary files?"));
            assertEquals("UNRECOGNIZED",HostGuiDiagnostics.startupTitleCategory("PRIVATE_PROJECT C:/PRIVATE_PATH"));return true;
        });
    }
    @Test void privateScreenshotRendersOnlyTheOwnedSurfaceAndKeepsAllocationBounds() {
        HostGuiSelectors.edt(()->{
            var panel=new javax.swing.JPanel(){@Override public boolean isShowing(){return true;}};
            panel.setSize(32,24);panel.setBackground(Color.MAGENTA);panel.setOpaque(true);
            var image=HostGuiDiagnostics.printSurface(panel);assertNotNull(image);assertEquals(32,image.getWidth());assertEquals(24,image.getHeight());
            assertEquals(Color.MAGENTA.getRGB(),image.getRGB(10,10));
            panel.setSize(4097,24);assertNull(HostGuiDiagnostics.printSurface(panel));assertNull(HostGuiDiagnostics.printSurface(null));
            var hidden=new javax.swing.JPanel();hidden.setSize(32,24);assertNull(HostGuiDiagnostics.printSurface(hidden));return true;
        });
    }
    @Test void idleEdtIsRetainedWithoutThreadNamesOrUnrelatedIdleWorkers() {
        var idleEdt=new Thread("PRIVATE_EDT_NAME");var unrelated=new Thread("PRIVATE_OTHER_NAME");
        var snapshots=Map.of(idleEdt,new StackTraceElement[]{new StackTraceElement("java.awt.EventDispatchThread","pumpEvents","PRIVATE_SOURCE.java",1)},
                unrelated,new StackTraceElement[]{new StackTraceElement("java.util.concurrent.ThreadPoolExecutor","getTask","PRIVATE_SOURCE.java",1)});
        var result=HostGuiDiagnostics.threadSnapshots(snapshots);assertEquals(1,result.size());assertEquals(idleEdt.threadId(),result.getFirst().get("id"));
        assertEquals(java.util.List.of("java.awt.EventDispatchThread.pumpEvents"),result.getFirst().get("frames"));assertFalse(result.toString().contains("PRIVATE_"));
    }
    @Test void missingReadyFrameStillProducesPrivateStartupMetadata() throws Exception {
        UUID operation=UUID.randomUUID();
        HostGuiDiagnostics.privateControls(directory,operation,null,new JsonObject());
        HostGuiDiagnostics.privateFailureSignals(directory,operation,null);
        Path prefix=directory.resolve("gui/private-diagnostics");
        var controls=LabJson.read(prefix.resolve(operation+".controls.json"),65536);
        var signals=LabJson.read(prefix.resolve(operation+".signals.json"),65536);
        assertTrue(controls.has("startupWindows"));assertTrue(signals.has("startupWindows"));
        assertTrue(signals.getAsJsonObject("startupWindows").has("showingWindowCount"));
        assertFalse(signals.toString().contains(directory.toString()));
    }
    @Test void nonvisualJourneyStatusAndHiddenInlineErrorsClassifyWithoutReadingGeneralDescriptionsOrPasswords() {
        HostGuiSelectors.edt(()->{
            var root=new javax.swing.JPanel();var status=new javax.swing.JToolBar();
            status.getAccessibleContext().setAccessibleName("Journey actions");
            status.getAccessibleContext().setAccessibleDescription("PRIVATE_STATUS The saved journey changed. Reload it before testing.");
            status.setVisible(false);root.add(status);
            var inline=new javax.swing.JEditorPane("text/html","<html><body>The journey is missing its HTTP authentication password. PRIVATE_INLINE</body></html>");
            inline.getAccessibleContext().setAccessibleName("Input error");inline.setVisible(false);root.add(inline);
            var unrelated=new javax.swing.JTextField("PRIVATE_FIELD");
            unrelated.getAccessibleContext().setAccessibleDescription("java.lang.PRIVATE_SECRETException: PRIVATE_DESCRIPTION\nThe browser could not complete the login.");root.add(unrelated);
            var password=new javax.swing.JPasswordField("The login service has stopped. PRIVATE_PASSWORD");
            password.getAccessibleContext().setAccessibleName("Input error");root.add(password);
            var signals=HostGuiDiagnostics.failureSignals(root);
            assertEquals(java.util.List.of("HTTP_PASSWORD_MISSING","UI_SAVED_JOURNEY_STALE"),signals.get("markers"));
            assertEquals(java.util.List.of(),signals.get("exceptions"));assertFalse(signals.toString().contains("PRIVATE_"));
            assertFalse(((java.util.List<?>)signals.get("sourceLiteralMatches")).isEmpty());return true;
        });
    }
    @Test void nonvisualDiagnosticSourcesKeepTheSameTextBounds() {
        HostGuiSelectors.edt(()->{
            var root=new javax.swing.JPanel();var status=new javax.swing.JToolBar();
            status.getAccessibleContext().setAccessibleName("Journey actions");status.getAccessibleContext().setAccessibleDescription("x".repeat(65537));root.add(status);
            var inline=new javax.swing.JTextArea("x".repeat(65537));inline.getAccessibleContext().setAccessibleName("Input error");root.add(inline);
            var signals=HostGuiDiagnostics.failureSignals(root);assertEquals(true,signals.get("truncated"));
            assertEquals(java.util.List.of(),signals.get("markers"));return true;
        });
    }
    @Test void libraryOriginsAreOptionalPrivateSignalsAndNeverChangeThePublicFailureResult() throws Exception {
        var snapshots=new AtomicInteger();
        var instrumentation=(java.lang.instrument.Instrumentation)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{java.lang.instrument.Instrumentation.class},(proxy,method,args)->{
                    assertEquals("getAllLoadedClasses",method.getName());snapshots.incrementAndGet();return new Class<?>[]{Gson.class};
                });
        var session=new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),directory.toRealPath());
        UUID operation=UUID.randomUUID();
        try {
            HostGuiDiagnostics.configureLibraryOrigins(instrumentation,session);
            var surface=new javax.swing.JPanel();surface.add(new javax.swing.JTextArea("PRIVATE_UI_VALUE"));
            HostGuiDiagnostics.privateFailureSignals(directory,operation,surface);
            Path signals=directory.resolve("gui/private-diagnostics/"+operation+".signals.json");
            var data=LabJson.read(signals,65536);
            assertTrue(data.getAsJsonObject("libraryOrigins").get("available").getAsBoolean());
            assertEquals(1,snapshots.get());assertFalse(Files.readString(signals).contains("PRIVATE_UI_VALUE"));
            assertFalse(Files.readString(signals).contains(directory.toString()));
            assertFalse(HostGuiDiagnostics.failureSignals(java.util.List.of("Login failed.")).containsKey("libraryOrigins"));
        } finally {HostGuiDiagnostics.configureLibraryOrigins(null,session);}
    }
    @Test void nativeHtmlOutputIsReadAsDocumentTextRatherThanSerializedWrappedMarkup() {
        HostGuiSelectors.edt(()->{
            String problem="The request could not be prepared for authentication.";
            var errors=new javax.swing.JEditorPane("text/html","<html><body><p>PROXY:2: BPSH left the request unchanged. Journey host_a: "+problem+"</p></body></html>");
            assertFalse(errors.getText().contains(problem),"The host-like HTML writer must wrap this diagnostic.");
            var tabs=new javax.swing.JTabbedPane();tabs.addTab("Details",new javax.swing.JPanel());
            tabs.addTab("Output",new javax.swing.JTextArea());tabs.addTab("Errors",errors);
            var signals=HostGuiDiagnostics.failureSignals(tabs);
            assertTrue(((java.util.List<?>)signals.get("markers")).contains("REQUEST_PREPARATION_FAILED"));
            assertFalse(((java.util.List<?>)signals.get("sourceLiteralMatches")).isEmpty());return true;
        });
    }
    @Test void sourceLiteralDiagnosticsReturnOnlyTrustedLocationsNeverMatchedValues() {
        var dictionary=Map.of("bapp/src/main/java/bpsh/Example.java:1:1","A fixed source-owned failure explanation.");
        assertEquals(java.util.List.of("bapp/src/main/java/bpsh/Example.java:1:1"),HostGuiDiagnostics.sourceLiteralMatches(
                java.util.List.of("PRIVATE_SECRET A fixed source-owned failure explanation. /PRIVATE_PATH"),dictionary));
        assertTrue(HostGuiDiagnostics.sourceLiteralMatches(java.util.List.of("PRIVATE_SECRET /PRIVATE_PATH"),dictionary).isEmpty());
        assertTrue(HostGuiDiagnostics.sourceLiteralMatches(java.util.List.of("x".repeat(65537)),dictionary).isEmpty());
        var generated=HostGuiDiagnostics.failureSignals(java.util.List.of("The request could not be prepared for authentication."));
        assertEquals(true,generated.get("sourceLiteralCatalogAvailable"));
        assertFalse(((java.util.List<?>)generated.get("sourceLiteralMatches")).isEmpty());
        assertFalse(generated.toString().contains("PRIVATE_"));
        assertTrue(((java.util.List<?>)HostGuiDiagnostics.failureSignals(java.util.List.of(
                "The request could not be\n\tprepared for authentication.")).get("markers")).contains("REQUEST_PREPARATION_FAILED"));
    }
    @Test void privateFailureSignalsExcludeRequestEditorsSettingsAndPasswordInputs() {
        HostGuiSelectors.edt(()->{
            var root=new javax.swing.JPanel();root.add(new javax.swing.JTextArea("java.lang.PRIVATE_SECRETException: PRIVATE_REQUEST"));
            var nativeTabs=new javax.swing.JTabbedPane();nativeTabs.addTab("Details",new javax.swing.JPanel());
            nativeTabs.addTab("Output",new javax.swing.JTextArea("loaded with native saved journeys"));
            var errors=new javax.swing.JPanel();errors.add(new javax.swing.JTextArea("java.lang.NoClassDefFoundError: PRIVATE_PATH"));
            errors.add(new javax.swing.JPasswordField("java.lang.PRIVATE_PASSWORDException"));nativeTabs.addTab("Errors",errors);root.add(nativeTabs);
            var table=new javax.swing.JTable(new Object[][]{{"time","Info","Changes saved."}},new Object[]{"Time","Type","Message"});root.add(table);
            var signals=HostGuiDiagnostics.failureSignals(root);
            assertEquals(2,signals.get("nativeOutputPanels"));assertEquals(java.util.List.of("java.lang.NoClassDefFoundError"),signals.get("exceptions"));
            assertEquals(java.util.List.of("CHANGES_SAVED","EXTENSION_LOADED"),signals.get("markers"));
            assertFalse(signals.toString().contains("PRIVATE_"));return true;
        });
    }
    @Test void failureSignalsRetainOnlyFixedMarkersAndBoundedExceptionIdentifiers() {
        String text="The extension could not start. PRIVATE_SECRET https://private.invalid/secret\n"
                +"java.lang.NoClassDefFoundError: PRIVATE_CLASS_PATH\n"
                +" at bpsh.burp.http.SessionRequestProcessor.process(PrivateSource.java:123)\n"
                +" at other.PrivateLibrary.method(PrivateSource.java:4)\n"
                +"Changes saved.\n";
        var signals=HostGuiDiagnostics.failureSignals(java.util.List.of(text));
        assertEquals(java.util.List.of("CHANGES_SAVED","EXTENSION_START_FAILED"),signals.get("markers"));
        assertEquals(java.util.List.of("java.lang.NoClassDefFoundError"),signals.get("exceptions"));
        assertEquals(java.util.List.of("bpsh.burp.http.SessionRequestProcessor.process"),signals.get("frames"));
        assertFalse(signals.toString().contains("PRIVATE_"));assertFalse(signals.toString().contains("private.invalid"));
        assertFalse(signals.toString().contains("PrivateSource"));assertFalse(signals.toString().contains("PrivateLibrary"));
        assertEquals(true,HostGuiDiagnostics.failureSignals(java.util.List.of("x".repeat(65537))).get("truncated"));
    }
    @Test void failureSignalsDistinguishUnknownRequestPreparationFromGenericUiAndLoginFailures() {
        var cases=Map.ofEntries(
                Map.entry("REQUEST_PREPARATION_FAILED","The request could not be prepared for authentication."),
                Map.entry("UI_ACTION_FAILED","The action failed."),
                Map.entry("UI_JOURNEY_ACTION_FAILED","The action could not be completed for this journey."),
                Map.entry("LOGIN_FAILED","Login failed."),
                Map.entry("BROWSER_LOGIN_FAILED","The browser could not complete the login."),
                Map.entry("BROWSER_SESSION_START_FAILED","The browser session could not start."));
        cases.forEach((marker,message)->assertEquals(java.util.List.of(marker),
                HostGuiDiagnostics.failureSignals(java.util.List.of(message)).get("markers"),marker));
    }
    @Test void failureSignalsClassifyPreNetworkFailuresWithoutRetainingJourneyOrSecretData() {
        var messages=java.util.List.of(
                "An enabled automatic journey is unavailable.",
                "Journey alias PRIVATE_ALIAS: The tag could not be matched to an available saved journey.",
                "This journey has incomplete or invalid settings.",
                "This HTTP-only journey has no captured token or cookie.",
                "The saved login values no longer match this journey's configuration.",
                "The journey is missing its HTTP authentication password.",
                "The journey is missing its mTLS PIN.",
                "Step 3 — Enter secret: no secret value was supplied.",
                "Enter the secret for this step.",
                "The client-certificate PIN is missing.",
                "A journey already uses this generated tag. Choose a different journey name.");
        var signals=HostGuiDiagnostics.failureSignals(messages);
        assertEquals(new TreeSet<>(java.util.List.of("AUTOMATIC_JOURNEY_UNAVAILABLE","TAG_JOURNEY_UNAVAILABLE",
                "JOURNEY_INVALID","HTTP_ONLY_TOKEN_UNAVAILABLE","SECRET_CONFIGURATION_MISMATCH","HTTP_PASSWORD_MISSING",
                "MTLS_PIN_MISSING","STEP_SECRET_MISSING","STEP_SECRET_REQUIRED","CERTIFICATE_PIN_MISSING","UI_ALIAS_COLLISION")).stream().toList(),
                signals.get("markers"));
        assertFalse(signals.toString().contains("PRIVATE_"));assertFalse(signals.toString().contains("Step 3"));
    }
    @Test void failureSignalsClassifyAssetAndCacheFailuresWithoutCopyingPathSuffixes() {
        var signals=HostGuiDiagnostics.failureSignals(java.util.List.of(
                "Browser setup could not finish in C:/PRIVATE_CACHE/PRIVATE_SECRET.",
                "The cached browser files are incomplete or damaged: /home/PRIVATE_USER/PRIVATE_CACHE.",
                "The browser's temporary files could not be deleted from /tmp/PRIVATE_PROFILE.",
                "Bundled Chromium does not support PRIVATE_TARGET.",
                "Library C:/PRIVATE_LIBRARY: cannot read the saved journey library.",
                "Library C:/PRIVATE_LIBRARY: changed since this edit; reload and reapply it.",
                "Library C:/PRIVATE_LIBRARY: edit lock is busy; wait for the other writer and retry.",
                "The extension JAR is missing its bundled browser files.",
                "Another browser setup is still running.",
                "The bundled browser driver files are missing.",
                "Burp cannot execute the bundled browser driver.",
                "The browser driver exited during initialization."));
        assertEquals(java.util.List.of("BROWSER_ASSETS_MISSING","BROWSER_CACHE_BUSY","BROWSER_CACHE_DAMAGED",
                "BROWSER_DRIVER_EXECUTE_DENIED","BROWSER_DRIVER_INIT_EXIT","BROWSER_DRIVER_MISSING",
                "BROWSER_PLATFORM_UNSUPPORTED","BROWSER_SETUP_FAILED","BROWSER_TEMP_CLEANUP_FAILED",
                "LIBRARY_EDIT_BUSY","LIBRARY_EDIT_STALE","LIBRARY_READ_FAILED"),signals.get("markers"));
        assertFalse(signals.toString().contains("PRIVATE_"));assertFalse(signals.toString().contains("C:/"));
        assertFalse(signals.toString().contains("/home/"));assertFalse(signals.toString().contains("/tmp/"));
    }
    @Test void failureSignalsDistinguishTimeoutStaleAndCapacityOutcomes() {
        var cases=Map.ofEntries(
                Map.entry("BROWSER_SETUP_TIMEOUT","Bundled browser setup timed out."),
                Map.entry("LOGIN_ATTEMPT_TIMEOUT","The login attempt timed out."),
                Map.entry("LOGIN_TOTAL_TIMEOUT","The total login timeout was reached."),
                Map.entry("LOGIN_REQUEST_TIMEOUT","The request timed out while waiting for login."),
                Map.entry("STORAGE_DRAFT_STALE","Storage changed after this draft opened. Reload the journey and reapply the edit."),
                Map.entry("TOKEN_COMMIT_STALE","The journey changed or its token expired while the request was being prepared."),
                Map.entry("JOURNEY_LOGIN_STALE","The journey changed while login was running."),
                Map.entry("LOGIN_QUEUE_FULL","The login queue is full."),
                Map.entry("LOGIN_GLOBAL_WAITERS_FULL","Too many requests are waiting for login."),
                Map.entry("LOGIN_JOURNEY_WAITERS_FULL","Too many requests are waiting for this journey to log in."),
                Map.entry("EXTENSION_UNLOADING","The extension is unloading."),
                Map.entry("BROWSER_SERVICE_STOPPED","The browser service has stopped."));
        cases.forEach((marker,message)->assertEquals(java.util.List.of(marker),
                HostGuiDiagnostics.failureSignals(java.util.List.of(message)).get("markers"),marker));
    }
    @Test void failureSignalsAcceptThrowableHeadersButNotExceptionNamesEmbeddedInMessages() {
        String text="A message mentions java.lang.PRIVATE_EMBEDDEDException: PRIVATE_SECRET\n"
                +"    Advice: java.lang.PRIVATE_ADVICEError should not be a throwable\n"
                +"java.lang.IllegalStateException: PRIVATE_PATH\n"
                +"  Caused by: java.io.IOException: PRIVATE_SECRET\n"
                +"\tbpsh.journey.ConfigurationException: PRIVATE_ALIAS\n";
        var signals=HostGuiDiagnostics.failureSignals(java.util.List.of(text));
        assertEquals(java.util.List.of("bpsh.journey.ConfigurationException","java.io.IOException","java.lang.IllegalStateException"),
                signals.get("exceptions"));
        assertFalse(signals.toString().contains("PRIVATE_"));
    }
    @Test void boundedThreadDiagnosticsKeepUiAndNewLoaderWorkInsteadOfOnlyOldThreads() {
        var snapshots=new LinkedHashMap<Thread,StackTraceElement[]>();
        var ui=new Thread("PRIVATE_UI_NAME");snapshots.put(ui,new StackTraceElement[]{
                new StackTraceElement("java.awt.EventDispatchThread","run","PRIVATE_SOURCE",1),
                new StackTraceElement("burp.Frame","dispatch","PRIVATE_SOURCE",1)});
        for(int i=0;i<60;i++)snapshots.put(new Thread("PRIVATE_WORKER_NAME"),new StackTraceElement[]{
                new StackTraceElement("burp.Worker","run","PRIVATE_SOURCE",1)});
        var loader=new Thread("PRIVATE_LOADER_NAME");snapshots.put(loader,new StackTraceElement[]{
                new StackTraceElement("bpsh.browser.runtime.BrowserArchiveCodec","decode","PRIVATE_SOURCE",1)});
        var archive=new Thread("PRIVATE_ARCHIVE_NAME");snapshots.put(archive,new StackTraceElement[]{
                new StackTraceElement("java.io.FileInputStream","read","PRIVATE_SOURCE",1),
                new StackTraceElement("burp.Loader","load","PRIVATE_SOURCE",1)});
        var result=HostGuiDiagnostics.threadSnapshots(snapshots);assertEquals(48,result.size());
        assertEquals(ui.threadId(),result.get(0).get("id"));assertEquals(loader.threadId(),result.get(1).get("id"));
        assertEquals(archive.threadId(),result.get(2).get("id"));assertFalse(result.toString().contains("PRIVATE_"));
    }
    @Test void privateThreadDiagnosticsKeepOnlyBoundedIdentifiersWithoutSourceOrArgumentData() {
        var frames=new StackTraceElement[]{new StackTraceElement("burp.Loader","load","PRIVATE_SOURCE_PATH",123),
                new StackTraceElement("java.io.FileInputStream","read","PRIVATE_SECRET",1),
                new StackTraceElement("PRIVATE_SECRET","method","PRIVATE_PATH",1)};
        var safe=HostGuiDiagnostics.safeThreadFrames(frames);assertEquals(java.util.List.of("burp.Loader.load","java.io.FileInputStream.read"),safe);
        assertFalse(safe.toString().contains("PRIVATE_"));
    }
    @Test void nativeLoadingDiagnosticsRetainOnlyStackFrameIdentifiers() {
        String text="PRIVATE_SECRET\n at java.base/java.util.Arrays.copyOf(PrivatePath.java:9)\n"
                +" at java.base@26.0.2/java.io.ByteArrayOutputStream.ensureCapacity(PrivatePath.java:12)\n"
                +" at java.io.ByteArrayOutputStream.write(PrivatePath.java:14)\n"
                +" at burp.Z_rf.Za(Unknown Source)\n at burp.Za3r.ZU(PrivatePath.java:9)\n at other.Library.method(Unknown Source)\n"
                +" at /PRIVATE_PATH/java.io.FileInputStream.read(PrivatePath.java:2)\n";
        var frames=HostGuiDiagnostics.loadingFrames(text);assertEquals(java.util.List.of("java.util.Arrays.copyOf",
                "java.io.ByteArrayOutputStream.ensureCapacity","java.io.ByteArrayOutputStream.write","burp.Z_rf.Za","burp.Za3r.ZU"),frames);
        assertFalse(frames.toString().contains("PRIVATE_SECRET"));assertFalse(frames.toString().contains("PrivatePath"));
        assertFalse(frames.toString().contains("PRIVATE_PATH"));assertFalse(frames.toString().contains("26.0.2"));
        assertEquals(32,HostGuiDiagnostics.loadingFrames(" at java.io.FileInputStream.read(Unknown Source)\n".repeat(33)).size());
        assertTrue(HostGuiDiagnostics.loadingFrames("x".repeat(32769)).isEmpty());
    }
    @TempDir Path directory;
    private HostGuiDriver driver(AtomicInteger inputs) throws Exception {
        return driver(inputs,Clock.fixed(Instant.ofEpochMilli(1000),ZoneOffset.UTC));
    }
    private HostGuiDriver driver(AtomicInteger inputs,Clock clock) throws Exception {
        var session=new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),directory.toRealPath());
        return new HostGuiDriver(session,new HostGuiDriver.Input(){public void click(Component c,Point p){inputs.incrementAndGet();}
            public void keys(int... keys){inputs.incrementAndGet();}public void text(String value){inputs.incrementAndGet();}},clock);
    }
    private LabHostGuiProtocol.Command command(long deadline) {
        return new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.CLOSE,deadline,new JsonObject());
    }
    @Test void cancelledExpiredAndUnreadyOperationsNeverGenerateInput() throws Exception {
        var inputs=new AtomicInteger();var driver=driver(inputs);
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command(1000))).getMessage());
        assertEquals("GUI_NOT_READY",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command(2000))).getMessage());
        Files.writeString(directory.resolve("cancel"),"");
        assertEquals("GUI_CANCELLED",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command(2000))).getMessage());
        assertEquals(0,inputs.get());
    }
    @Test void diagnosticsNeverReturnEditorOrPasswordContents() {
        HostGuiSelectors.edt(()->{
            var panel=new javax.swing.JPanel();panel.add(new javax.swing.JTextField("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            panel.add(new javax.swing.JPasswordField("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            panel.add(new javax.swing.JLabel("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            panel.add(new javax.swing.JButton("SECRET_SENTINEL"){@Override public boolean isShowing(){return true;}});
            var result=HostGuiDiagnostics.capture(panel);assertEquals(1,result.getAsJsonObject("counts").get("text").getAsInt());
            assertEquals(1,result.getAsJsonObject("counts").get("password").getAsInt());assertFalse(result.toString().contains("SECRET_SENTINEL"));return true;
        });
    }
    @Test void stateWaitDeadlineProducesNoInput() throws Exception {
        var inputs=new AtomicInteger();var driver=driver(inputs,Clock.systemUTC());
        var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.READY,System.currentTimeMillis()+150,new JsonObject());
        assertEquals("GUI_DEADLINE",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command)).getMessage());assertEquals(0,inputs.get());
    }
    @Test void cancellationDuringAStateWaitProducesNoInput() throws Exception {
        var inputs=new AtomicInteger();var driver=driver(inputs,Clock.systemUTC());var scheduler=java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
        try {
            scheduler.schedule(()->{try{Files.writeString(directory.resolve("cancel"),"");}catch(java.io.IOException failed){throw new AssertionError(failed);}},100,java.util.concurrent.TimeUnit.MILLISECONDS);
            var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.READY,System.currentTimeMillis()+3000,new JsonObject());
            assertEquals("GUI_CANCELLED",assertThrows(HostGuiSelectors.Failure.class,()->driver.perform(command)).getMessage());assertEquals(0,inputs.get());
        }finally{scheduler.shutdownNow();}
    }
}

package lab.auth.gui;

import com.google.gson.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import javax.swing.*;

/** Safe diagnostics omit editor contents, field values and arbitrary UI messages. */
public final class HostGuiDiagnostics {
    private HostGuiDiagnostics() {}
    private static volatile HostLibraryOrigins libraryOrigins=new HostLibraryOrigins(null,Map.of());
    private record ProductSource(HostLibraryOrigins origins,java.nio.file.Path path,String sha256) {}
    private static volatile ProductSource productSource;
    /** Configures only expected captured source locations; premain still starts just the existing worker. */
    static void configureLibraryOrigins(java.lang.instrument.Instrumentation instrumentation,lab.auth.LabHostGuiProtocol.Session session) {
        var sources=new EnumMap<HostLibraryOrigins.Origin,java.nio.file.Path>(HostLibraryOrigins.Origin.class);
        sources.put(HostLibraryOrigins.Origin.PRODUCT,session.root().resolve("assets/"+session.productSha256()+".jar"));
        sources.put(HostLibraryOrigins.Origin.HELPER,session.root().resolve("assets/"+session.helperSha256()+".jar"));
        String[] classPath=System.getProperty("java.class.path","").split(java.util.regex.Pattern.quote(java.io.File.pathSeparator),-1);
        if(classPath.length==1&&!classPath[0].isBlank())try{sources.put(HostLibraryOrigins.Origin.HOST,java.nio.file.Path.of(classPath[0]));}
        catch(java.nio.file.InvalidPathException unavailable){/* Unknown host source remains unknown. */}
        var observed=new HostLibraryOrigins(instrumentation,sources);libraryOrigins=observed;
        productSource=new ProductSource(observed,sources.get(HostLibraryOrigins.Origin.PRODUCT),session.productSha256());
    }
    /** Binds the actual loaded entry to the captured JAR location and current bytes. */
    static boolean productSourceMatched() {
        var expected=productSource;if(expected==null||!productArtifactCurrent(expected))return false;
        return expected.origins().productEntryArtifactMatches(java.nio.file.Path.of(System.getProperty("java.io.tmpdir")),expected.sha256());
    }
    private static boolean productArtifactCurrent(ProductSource expected) {
        try {
            var path=expected.path();long size=java.nio.file.Files.size(path);
            return java.nio.file.Files.isRegularFile(path,java.nio.file.LinkOption.NOFOLLOW_LINKS)&&size>0&&size<134217728L
                    &&lab.auth.LabJson.sha256(path).equals(expected.sha256())&&java.nio.file.Files.size(path)==size;
        }catch(Exception unavailable){return false;}
    }
    static void privateProductSource(java.nio.file.Path root,UUID operation) {
        try {
            var expected=productSource;var diagnostic=expected==null?new com.google.gson.JsonObject():expected.origins().productEntrySources();
            diagnostic.addProperty("collectorConfigured",expected!=null);diagnostic.addProperty("capturedArtifactCurrent",expected!=null&&productArtifactCurrent(expected));
            if(expected!=null)diagnostic.add("ownedLocations",expected.origins().productEntryLocations(root,java.nio.file.Path.of(System.getProperty("java.io.tmpdir")),expected.sha256()));
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".product-source.json");
            java.nio.file.Files.createDirectories(output.getParent());lab.auth.LabJson.writeNew(output,diagnostic);
        }catch(Exception unavailable){/* Independent optional metadata, no UI thread or arbitrary source path is accessed. */}
    }
    private static final java.util.regex.Pattern DISPLAY_SPACE=java.util.regex.Pattern.compile("[\\s\\u00a0]+");
    private static final Map<String,String> SOURCE_LITERALS=sourceLiterals();
    /** Source-owned text is an optional diagnostic dictionary, never a product control or pass condition. */
    private static Map<String,String> sourceLiterals() {
        try(var input=HostGuiDiagnostics.class.getResourceAsStream("source-diagnostic-literals.json")) {
            if(input==null)return Map.of();byte[] raw=input.readNBytes(2*1024*1024+1);
            if(raw.length>2*1024*1024)return Map.of();
            var json=lab.auth.LabJson.object(lab.auth.LabJson.parse(raw),"version","literals");
            if(lab.auth.LabJson.positive(json.get("version"))!=1||json.getAsJsonArray("literals").size()>10000)return Map.of();
            var result=new LinkedHashMap<String,String>();
            for(var item:json.getAsJsonArray("literals")) {
                var row=lab.auth.LabJson.object(item,"location","value");String location=lab.auth.LabJson.text(row,"location"),value=lab.auth.LabJson.text(row,"value");
                if(!location.matches("bapp/src/main/java/bpsh/[A-Za-z0-9_/]+\\.java:[1-9][0-9]*:[1-9][0-9]*")||value.length()<24||value.length()>512)return Map.of();
                result.put(location,value);
            }
            return Map.copyOf(result);
        }catch(Exception unavailable){return Map.of();}
    }
    /** Emits only authored source locations, including for previously unclassified guidance. */
    static List<String> sourceLiteralMatches(Collection<String> texts,Map<String,String> dictionary) {
        var matches=new TreeSet<String>();var plain=new ArrayList<String>();int remaining=1048576;
        for(String text:texts)if(text!=null&&text.length()<=65536&&text.length()<=remaining){plain.add(displayText(text));remaining-=text.length();}
        for(var entry:dictionary.entrySet())for(String text:plain)if(text.contains(displayText(entry.getValue()))) {
            matches.add(entry.getKey());break;
        }
        return matches.stream().limit(128).toList();
    }
    private static String displayText(String text){return DISPLAY_SPACE.matcher(text).replaceAll(" ");}
    private record DiagnosticTarget(Container surface,Map<String,Object> startup) {}
    /** Only this JVM's showing windows are candidates; ambiguity never selects an arbitrary window. */
    static <T> T startupWindow(Collection<T> windows,java.util.function.Predicate<T> showing,
                               java.util.function.Predicate<T> modalDialog,java.util.function.Predicate<T> frame) {
        var visible=windows.stream().filter(showing).toList();
        var modals=visible.stream().filter(modalDialog).toList();
        if(!modals.isEmpty())return modals.size()==1?modals.getFirst():null;
        var frames=visible.stream().filter(frame).toList();return frames.size()==1?frames.getFirst():null;
    }
    static String startupTitleCategory(String title) {
        if(title==null)return "UNRECOGNIZED";
        if(title.matches("Burp Suite Community Edition(?: v?[0-9]{4}\\.[0-9]{1,2}(?:\\.[0-9]{1,2})?)?(?: - Temporary project)?"))return "BURP_COMMUNITY";
        return switch(title) {
            case "Burp Suite" -> "BURP";
            case "Welcome to Burp Suite" -> "BURP_WELCOME";
            case "Select project", "Project selection" -> "PROJECT_SELECTION";
            case "Delete old temporary files?" -> "DELETE_TEMP_FILES";
            case "Burp Suite License Agreement", "Terms and Conditions" -> "TERMS_AGREEMENT";
            default -> "UNRECOGNIZED";
        };
    }
    /** Fixed wizard categories only: text inputs, arbitrary captions and descriptions are not retained. */
    static List<Map<String,Object>> startupControls(Container surface) {
        var captions=Map.ofEntries(Map.entry("Next","NEXT"),Map.entry("Next >","NEXT"),Map.entry("Start Burp","START_BURP"),
                Map.entry("Continue with Burp Suite Community Edition","CONTINUE_COMMUNITY"),Map.entry("Leave","LEAVE"),
                Map.entry("Temporary project","TEMPORARY_PROJECT"),Map.entry("New project on disk","NEW_PROJECT"),
                Map.entry("Open existing project","OPEN_PROJECT"),Map.entry("Use Burp defaults","USE_DEFAULTS"),
                Map.entry("Back","BACK"),Map.entry("Cancel","CANCEL"));
        var result=new ArrayList<Map<String,Object>>();
        for(Component component:HostGuiSelectors.all(surface))if(component instanceof AbstractButton||component instanceof JLabel) {
            String category=captions.get(HostGuiSelectors.label(component));
            if(category!=null&&result.size()<128)result.add(Map.of("category",category,"showing",component.isShowing(),"enabled",HostGuiSelectors.actionEnabled(component)));
        }
        return List.copyOf(result);
    }
    private static DiagnosticTarget diagnosticTarget(Container supplied) {
        if(supplied!=null) {
            // A modal Settings window can cover the supplied main frame. The active
            // window is still a public Window in this exact owned Burp JVM.
            Window active=KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
            return new DiagnosticTarget(active!=null&&active.isShowing()?active:supplied,Map.of());
        }
        var all=Arrays.asList(Window.getWindows());var showing=all.stream().filter(Window::isShowing).toList();
        boolean truncated=showing.size()>32;
        Window selected=truncated?null:startupWindow(showing,Window::isShowing,w->w instanceof Dialog dialog&&dialog.isModal(),w->w instanceof Frame);
        var rows=new ArrayList<Map<String,Object>>();
        for(Window window:showing.stream().limit(32).toList()) {
            String kind=window instanceof Dialog dialog&&dialog.isModal()?"MODAL_DIALOG":window instanceof Dialog?"DIALOG":window instanceof Frame?"FRAME":"WINDOW";
            String title=window instanceof Dialog dialog?dialog.getTitle():window instanceof Frame frame?frame.getTitle():null;
            rows.add(Map.of("kind",kind,"showing",window.isShowing(),"focused",window.isFocused(),"titleCategory",startupTitleCategory(title),"wizardControls",startupControls(window)));
        }
        return new DiagnosticTarget(selected,Map.of("ownedWindowCount",all.size(),"showingWindowCount",showing.size(),
                "selected",selected==null?"NONE":selected instanceof Dialog?"MODAL_DIALOG":"FRAME","truncated",truncated,"windows",List.copyOf(rows)));
    }
    public static JsonObject capture(Container root) {
        return HostGuiSelectors.edt(()->{
            var result=new JsonObject();var counts=new TreeMap<String,Integer>();var labels=new TreeSet<String>();
            for(Component component:HostGuiSelectors.all(root)) {
                if(!component.isShowing())continue;
                String role=component instanceof JPasswordField?"password":component instanceof javax.swing.text.JTextComponent?"text":
                        component instanceof AbstractButton?"button":component instanceof JTable?"table":component instanceof JTabbedPane?"tabs":"other";
                counts.merge(role,1,Integer::sum);String label=HostGuiSelectors.label(component);if(lab.auth.LabHostGuiProtocol.SAFE_LABELS.contains(label))labels.add(label);
            }
            var safeCounts=new JsonObject();counts.forEach(safeCounts::addProperty);var safeLabels=new JsonArray();labels.forEach(safeLabels::add);
            result.add("counts",safeCounts);result.add("labels",safeLabels);return result;
        },250);
    }
    /** Fixed captions and public roles only; no vendor class names or arbitrary accessible text. */
    static void privateControls(java.nio.file.Path root,UUID operation,Container surface,JsonObject controlState) {
        try {
            var target=HostGuiSelectors.edt(()->diagnosticTarget(surface),250);
            var controls=target.surface()==null?List.of():HostGuiSelectors.edt(()->HostGuiSelectors.all(target.surface()).stream().filter(Component::isShowing)
                    .filter(c->lab.auth.LabHostGuiProtocol.SAFE_LABELS.contains(HostGuiSelectors.label(c)))
                    .limit(128).map(c->Map.of("label",HostGuiSelectors.label(c),"kind",c instanceof AbstractButton?"BUTTON":c instanceof JLabel?"LABEL":"OTHER",
                            "enabled",HostGuiSelectors.actionEnabled(c),"mouseHandler",c.getMouseListeners().length>0)).toList(),250);
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".controls.json");
            var data=new JsonObject();data.add("controls",lab.auth.LabJson.JSON.toJsonTree(controls));data.add("controlState",controlState.deepCopy());
            data.addProperty("surfaceShowing",target.surface()!=null&&HostGuiSelectors.edt(target.surface()::isShowing,250));
            data.addProperty("surfaceFocused",target.surface()!=null&&HostGuiSelectors.edt(()->target.surface() instanceof Window window&&window.isFocused(),250));
            if(!target.startup().isEmpty())data.add("startupWindows",lab.auth.LabJson.JSON.toJsonTree(target.startup()));
            java.nio.file.Files.createDirectories(output.getParent());lab.auth.LabJson.writeNew(output,data);
        }catch(Exception unavailable){/* Optional diagnosis cannot replace the primary result. */}
    }
    /** Classifies public UI diagnostics without retaining messages, editor values or source paths. */
    static Map<String,Object> failureSignals(Collection<String> texts) {
        var markers=new TreeSet<String>();var exceptions=new TreeSet<String>();var frames=new LinkedHashSet<String>();
        var known=Map.ofEntries(
                Map.entry("EXTENSION_LOADED","loaded with native saved journeys"),
                Map.entry("EXTENSION_START_FAILED","The extension could not start."),
                Map.entry("REQUEST_UNCHANGED","BPSH left the request unchanged."),
                Map.entry("REQUEST_DROP_REQUESTED","Burp was asked to drop this request."),
                Map.entry("CHANGES_SAVED","Changes saved."),Map.entry("AUTOSAVE_STOPPED","Automatic saving stopped."),
                Map.entry("HTTP_UNAVAILABLE","HTTP authentication is unavailable."),Map.entry("LOGIN_FAILED","Login failed."),
                Map.entry("REQUEST_PREPARATION_FAILED","The request could not be prepared for authentication."),
                Map.entry("AUTOMATIC_JOURNEY_UNAVAILABLE","An enabled automatic journey is unavailable."),
                Map.entry("TAG_JOURNEY_UNAVAILABLE","The tag could not be matched to an available saved journey."),
                Map.entry("JOURNEY_INVALID","This journey has incomplete or invalid settings."),
                Map.entry("HTTP_ONLY_TOKEN_UNAVAILABLE","This HTTP-only journey has no captured token or cookie."),
                Map.entry("SECRET_CONFIGURATION_MISMATCH","The saved login values no longer match this journey's configuration."),
                Map.entry("HTTP_PASSWORD_MISSING","The journey is missing its HTTP authentication password."),
                Map.entry("MTLS_PIN_MISSING","The journey is missing its mTLS PIN."),
                Map.entry("STEP_SECRET_MISSING","Enter secret: no secret value was supplied."),
                Map.entry("STEP_SECRET_REQUIRED","Enter the secret for this step."),
                Map.entry("CERTIFICATE_PIN_MISSING","The client-certificate PIN is missing."),
                Map.entry("BROWSER_LOGIN_FAILED","The browser could not complete the login."),
                Map.entry("BROWSER_SESSION_START_FAILED","The browser session could not start."),
                Map.entry("BROWSER_SETUP_TIMEOUT","Bundled browser setup timed out."),
                Map.entry("BROWSER_SPACE_INSUFFICIENT","There is not enough free space to prepare the bundled browser."),
                Map.entry("BROWSER_ASSETS_MISSING","The extension JAR is missing its bundled browser files."),
                Map.entry("BROWSER_CACHE_BUSY","Another browser setup is still running."),
                Map.entry("BROWSER_FILES_ACCESS_DENIED","Burp cannot access the bundled browser files."),
                Map.entry("BROWSER_CACHE_VERIFY_FAILED","The cached browser files could not be verified."),
                Map.entry("BROWSER_MANIFEST_INVALID","The bundled browser configuration is invalid."),
                Map.entry("BROWSER_BUNDLE_PLATFORM_MISMATCH","This browser bundle was built for a different operating system or processor architecture."),
                Map.entry("BROWSER_RUNTIME_LOAD_FAILED","The bundled browser runtime could not load."),
                Map.entry("BROWSER_DRIVER_EXECUTE_DENIED","Burp cannot execute the bundled browser driver."),
                Map.entry("BROWSER_DRIVER_MISSING","The bundled browser driver files are missing."),
                Map.entry("BROWSER_DRIVER_INIT_EXIT","The browser driver exited during initialization."),
                Map.entry("BROWSER_DRIVER_START_FAILED","The browser driver could not start."),
                Map.entry("BROWSER_DEBUG_UNSAFE","Playwright debug logging is enabled and could expose login values."),
                // These constant prefixes classify path/target-bearing messages without retaining their suffixes.
                Map.entry("BROWSER_SETUP_FAILED","Browser setup could not finish in "),
                Map.entry("BROWSER_CACHE_DAMAGED","The cached browser files are incomplete or damaged: "),
                Map.entry("BROWSER_TEMP_CLEANUP_FAILED","The browser's temporary files could not be deleted from "),
                Map.entry("BROWSER_PLATFORM_UNSUPPORTED","Bundled Chromium does not support "),
                Map.entry("UI_ACTION_FAILED","The action failed."),
                Map.entry("UI_JOURNEY_ACTION_FAILED","The action could not be completed for this journey."),
                Map.entry("UI_ALIAS_COLLISION","A journey already uses this generated tag. Choose a different journey name."),
                Map.entry("UI_SAVED_JOURNEY_STALE","The saved journey changed. Reload it before testing."),
                Map.entry("UI_SELECTED_JOURNEY_STALE","This journey changed after it was selected. Reload it, review the configuration, and try again."),
                Map.entry("STORAGE_DRAFT_STALE","Storage changed after this draft opened. Reload the journey and reapply the edit."),
                Map.entry("STORAGE_FINAL_SAVE_STALE","Storage changed before the final save."),
                Map.entry("JOURNEY_LOGIN_STALE","The journey changed while login was running."),
                Map.entry("TOKEN_COMMIT_STALE","The journey changed or its token expired while the request was being prepared."),
                Map.entry("LOGIN_SERVICE_STOPPED","The login service has stopped."),
                Map.entry("BROWSER_SERVICE_STOPPED","The browser service has stopped."),
                Map.entry("EXTENSION_UNLOADING","The extension is unloading."),
                Map.entry("LOGIN_BROWSER_START_FAILED","The login browser could not start."),
                Map.entry("LOGIN_ATTEMPT_TIMEOUT","The login attempt timed out."),
                Map.entry("LOGIN_TOTAL_TIMEOUT","The total login timeout was reached."),
                Map.entry("LOGIN_REQUEST_TIMEOUT","The request timed out while waiting for login."),
                Map.entry("LOGIN_QUEUE_FULL","The login queue is full."),
                Map.entry("LOGIN_GLOBAL_WAITERS_FULL","Too many requests are waiting for login."),
                Map.entry("LOGIN_JOURNEY_WAITERS_FULL","Too many requests are waiting for this journey to log in."),
                Map.entry("LIBRARY_READ_FAILED","cannot read the saved journey library"),
                Map.entry("LIBRARY_EDIT_STALE","changed since this edit; reload and reapply it"),
                Map.entry("LIBRARY_EDIT_BUSY","edit lock is busy; wait for the other writer and retry"));
        var throwable=java.util.regex.Pattern.compile("(?m)^[\\t ]*(?:Caused by: )?((?:burp|bpsh|java|javax|jdk|sun)\\.[A-Za-z0-9_$.]*(?:Exception|Error))(?=[:\\t ]|$)");
        var stack=java.util.regex.Pattern.compile("(?m)^\\s*at ((?:burp|bpsh|java|javax|jdk|sun)\\.[A-Za-z0-9_$.<>]+)\\([^\\r\\n]{0,160}\\)\\s*$");
        var stepFailure=java.util.regex.Pattern.compile("(?<!\\S)Step [1-9][0-9]{0,2} \u2014 [^.\\r\\n]{1,80} (timed out|failed)\\.");
        int consumed=0;boolean truncated=false;
        for(String text:texts) {
            if(text==null)continue;
            if(text.length()>65536||consumed+text.length()>1048576){truncated=true;continue;}
            consumed+=text.length();String plain=displayText(text);known.forEach((code,literal)->{if(plain.contains(literal))markers.add(code);});
            stepFailure.matcher(plain).results().limit(32).forEach(match->markers.add(match.group(1).equals("timed out")?"BROWSER_STEP_TIMEOUT":"BROWSER_STEP_FAILED"));
            throwable.matcher(text).results().limit(32).map(match->match.group(1)).filter(id->id.length()<=160).forEach(exceptions::add);
            stack.matcher(text).results().limit(48).map(match->match.group(1)).filter(id->id.length()<=160).forEach(frames::add);
        }
        return Map.of("markers",List.copyOf(markers),"exceptions",exceptions.stream().limit(32).toList(),
                "frames",frames.stream().limit(48).toList(),"truncated",truncated,
                "sourceLiteralMatches",sourceLiteralMatches(texts,SOURCE_LITERALS),"sourceLiteralCatalogAvailable",!SOURCE_LITERALS.isEmpty());
    }
    /** Reads fixed diagnostic surfaces, including nonvisual status; never general request or settings editors. */
    static Map<String,Object> failureSignals(Container surface) {
        var texts=new ArrayList<String>();int[] remaining={1048576};boolean[] truncated={false};int panels=0;
        java.util.function.Consumer<String> accept=text->{
            if(text==null)return;
            if(text.length()>65536||text.length()>remaining[0])truncated[0]=true;
            else {texts.add(text);remaining[0]-=text.length();}
        };
        java.util.function.Consumer<javax.swing.text.JTextComponent> acceptDocument=text->{
            if(text instanceof JPasswordField)return;
            var document=text.getDocument();int length=document.getLength();
            if(length>65536)truncated[0]=true;
            else try{accept.accept(document.getText(0,length));}catch(javax.swing.text.BadLocationException changed){truncated[0]=true;}
        };
        for(Component component:HostGuiSelectors.all(surface)) {
            var accessible=component.getAccessibleContext();
            String accessibleName=accessible==null?null:accessible.getAccessibleName();
            if("Journey actions".equals(accessibleName))accept.accept(accessible.getAccessibleDescription());
            if("Input error".equals(accessibleName)&&component instanceof javax.swing.text.JTextComponent text)acceptDocument.accept(text);
            if(component instanceof JTabbedPane tabs&&tabs.indexOfTab("Details")>=0&&tabs.indexOfTab("Output")>=0&&tabs.indexOfTab("Errors")>=0) {
                for(String title:List.of("Output","Errors"))if(tabs.getComponentAt(tabs.indexOfTab(title)) instanceof Container pane) {
                    panels++;
                    for(Component child:HostGuiSelectors.all(pane))if(child instanceof javax.swing.text.JTextComponent text&&!(text instanceof JPasswordField)) {
                        acceptDocument.accept(text);
                    }
                }
            }
            if(component instanceof JTable table&&HostGuiSelectors.column(table,"Time")>=0
                    &&HostGuiSelectors.column(table,"Type")>=0&&HostGuiSelectors.column(table,"Message")>=0) {
                if(table.getRowCount()>2000)truncated[0]=true;
                for(int row=0;row<Math.min(2000,table.getRowCount());row++)accept.accept(Objects.toString(table.getValueAt(row,HostGuiSelectors.column(table,"Message")),""));
            }
        }
        var result=new LinkedHashMap<>(failureSignals(texts));result.put("nativeOutputPanels",panels);
        if(truncated[0])result.put("truncated",true);return Map.copyOf(result);
    }
    /** Hidden output/error tabs are read without selecting them or changing the test's input path. */
    static void privateFailureSignals(java.nio.file.Path root,UUID operation,Container surface) {
        try {
            var target=HostGuiSelectors.edt(()->diagnosticTarget(surface),250);
            var signals=new LinkedHashMap<>(target.surface()==null?failureSignals(List.of()):HostGuiSelectors.edt(()->failureSignals(target.surface()),250));
            if(!target.startup().isEmpty())signals.put("startupWindows",target.startup());
            signals.put("libraryOrigins",libraryOrigins.capture());
            signals.put("heap",HostHeapDiagnostics.snapshot());
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".signals.json");
            java.nio.file.Files.createDirectories(output.getParent());lab.auth.LabJson.writeNew(output,signals);
        }catch(Exception unavailable){/* Optional read-only diagnosis cannot change the primary result. */}
    }
    /** Renders only the exact owned window; other processes' foreground pixels never enter private images. */
    static void privateScreenshot(java.nio.file.Path root,UUID operation,Window fallback) {
        try {
            var capture=HostGuiSelectors.edt(()->printSurface(diagnosticTarget(fallback).surface()),250);
            if(capture==null)return;
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".png");
            java.nio.file.Files.createDirectories(output.getParent());
            javax.imageio.ImageIO.write(capture,"png",output.toFile());
        }catch(Exception|OutOfMemoryError unavailable){/* Never replace the primary failure or print private data. */}
    }
    static java.awt.image.BufferedImage printSurface(Container surface) {
        if(surface==null||!surface.isShowing()||surface.getWidth()<1||surface.getHeight()<1||surface.getWidth()>4096||surface.getHeight()>4096)return null;
        long bytes=4L*surface.getWidth()*surface.getHeight();var runtime=Runtime.getRuntime();
        if(runtime.maxMemory()-(runtime.totalMemory()-runtime.freeMemory())<bytes+(32L<<20))return null;
        var image=new java.awt.image.BufferedImage(surface.getWidth(),surface.getHeight(),java.awt.image.BufferedImage.TYPE_INT_RGB);
        var graphics=image.createGraphics();try{surface.printAll(graphics);}finally{graphics.dispose();}return image;
    }
    static java.util.List<String> safeThreadFrames(StackTraceElement[] frames) {
        return Arrays.stream(frames).filter(frame->frame.getClassName().matches("(?:burp|bpsh|java|javax|jdk|sun)\\.[A-Za-z0-9_$.]+")
                &&frame.getMethodName().matches("[A-Za-z0-9_$<>]+"))
                .map(frame->frame.getClassName()+"."+frame.getMethodName()).filter(frame->frame.length()<=160).limit(16).toList();
    }
    /** Safe identifiers from owned JVM threads only, with no names, messages, source files or argument values. */
    static java.util.List<Map<String,Object>> threadSnapshots(Map<Thread,StackTraceElement[]> snapshots) {
        return snapshots.entrySet().stream().filter(entry->Arrays.stream(entry.getValue())
                        .anyMatch(frame->frame.getClassName().startsWith("burp.")||frame.getClassName().startsWith("bpsh.")||frame.getClassName().equals("java.awt.EventDispatchThread")))
                .sorted(Comparator.<Map.Entry<Thread,StackTraceElement[]>>comparingInt(entry->threadPriority(entry.getValue()))
                        .thenComparing(Comparator.comparingLong((Map.Entry<Thread,StackTraceElement[]> entry)->entry.getKey().threadId()).reversed()))
                .limit(48).map(entry->Map.<String,Object>of("id",entry.getKey().threadId(),"state",entry.getKey().getState().name(),"frames",safeThreadFrames(entry.getValue()))).toList();
    }
    private static int threadPriority(StackTraceElement[] frames) {
        if(Arrays.stream(frames).anyMatch(frame->frame.getClassName().equals("java.awt.EventDispatchThread")))return 0;
        if(Arrays.stream(frames).anyMatch(frame->frame.getClassName().startsWith("bpsh.")))return 1;
        if(Arrays.stream(frames).anyMatch(frame->frame.getClassName().matches("(?:java\\.io\\..*|java\\.util\\.zip\\..*|jdk\\.internal\\.loader\\..*|java\\.lang\\.ClassLoader)")))return 2;
        return 3;
    }
    static void privateThreads(java.nio.file.Path root,UUID operation) {
        try {
            var threads=threadSnapshots(Thread.getAllStackTraces());
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".threads.json");
            java.nio.file.Files.createDirectories(output.getParent());lab.auth.LabJson.writeNew(output,Map.of("threads",threads));
        }catch(Exception|OutOfMemoryError unavailable){/* Preserve the primary result under memory pressure. */}
    }
    /** Extracts identifiers only; exception messages, source locations and paths are never retained. */
    static java.util.List<String> loadingFrames(String text) {
        if(text.length()>32768)return java.util.List.of();
        return java.util.regex.Pattern.compile("(?m)^[ \\t]*at (?:(?:java|jdk)\\.[A-Za-z0-9_.]+(?:@[A-Za-z0-9.+_-]+)?/)?"
                        +"((?:burp|bpsh|java|javax|jdk|sun)\\.[A-Za-z0-9_$.<>]+)\\([^\\r\\n]{0,120}\\)[ \\t]*$")
                .matcher(text).results().map(match->match.group(1)).filter(frame->frame.length()<=160).limit(32).toList();
    }
    /** Optional private loader diagnosis from the known native error dialog; never used as a selector. */
    static void privateLoadingFrames(java.nio.file.Path root,UUID operation) {
        try {
            var frames=HostGuiSelectors.edt(()->Arrays.stream(Window.getWindows())
                    .filter(w->w instanceof Dialog d&&d.isShowing()&&d.getTitle().equals("Error loading extension"))
                    .flatMap(w->HostGuiSelectors.all(w).stream()).filter(c->c instanceof javax.swing.text.JTextComponent&&!(c instanceof JPasswordField))
                    .flatMap(c->loadingFrames(((javax.swing.text.JTextComponent)c).getText()).stream()).distinct().limit(32).toList(),250);
            if(frames.isEmpty())return;
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".loading-frames.json");
            java.nio.file.Files.createDirectories(output.getParent());lab.auth.LabJson.writeNew(output,Map.of("frames",frames));
        }catch(Exception unavailable){/* Optional diagnosis cannot replace the primary result. */}
    }
}

package lab.auth.gui;

import com.google.gson.*;
import java.awt.*;
import java.util.*;
import javax.swing.*;

/** Safe diagnostics omit editor contents, field values and arbitrary UI messages. */
public final class HostGuiDiagnostics {
    private HostGuiDiagnostics() {}
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
        if(surface==null)return;
        try {
            var controls=HostGuiSelectors.edt(()->HostGuiSelectors.all(surface).stream().filter(Component::isShowing)
                    .filter(c->lab.auth.LabHostGuiProtocol.SAFE_LABELS.contains(HostGuiSelectors.label(c)))
                    .limit(128).map(c->Map.of("label",HostGuiSelectors.label(c),"kind",c instanceof AbstractButton?"BUTTON":c instanceof JLabel?"LABEL":"OTHER",
                            "enabled",HostGuiSelectors.actionEnabled(c),"mouseHandler",c.getMouseListeners().length>0)).toList(),250);
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".controls.json");
            var data=new JsonObject();data.add("controls",lab.auth.LabJson.JSON.toJsonTree(controls));data.add("controlState",controlState.deepCopy());
            data.addProperty("surfaceShowing",HostGuiSelectors.edt(surface::isShowing,250));
            data.addProperty("surfaceFocused",HostGuiSelectors.edt(()->surface instanceof Window window&&window.isFocused(),250));
            java.nio.file.Files.createDirectories(output.getParent());lab.auth.LabJson.writeNew(output,data);
        }catch(Exception unavailable){/* Optional diagnosis cannot replace the primary result. */}
    }
    /** A focused window from this JVM only; images stay private and are never published as evidence. */
    static void privateScreenshot(java.nio.file.Path root,UUID operation,Window fallback) {
        try {
            var bounds=HostGuiSelectors.edt(()->{
                var windows=Arrays.stream(Window.getWindows()).filter(w->w.isShowing()&&w.isFocused()).toList();
                if(windows.size()!=1)return null;
                Window window=windows.getFirst();return window.getBounds().intersection(window.getGraphicsConfiguration().getBounds());
            },250);
            java.awt.image.BufferedImage capture;
            if(bounds==null)capture=HostGuiSelectors.edt(()->{
                if(fallback==null||!fallback.isShowing()||fallback.getWidth()<1||fallback.getHeight()<1||fallback.getWidth()>4096||fallback.getHeight()>4096)return null;
                long bytes=4L*fallback.getWidth()*fallback.getHeight();var runtime=Runtime.getRuntime();
                if(runtime.maxMemory()-(runtime.totalMemory()-runtime.freeMemory())<bytes+(32L<<20))return null;
                var image=new java.awt.image.BufferedImage(fallback.getWidth(),fallback.getHeight(),java.awt.image.BufferedImage.TYPE_INT_RGB);
                var graphics=image.createGraphics();try{fallback.printAll(graphics);}finally{graphics.dispose();}return image;
            },250);
            else {if(bounds.width<=0||bounds.height<=0||bounds.width>4096||bounds.height>4096)return;capture=new Robot().createScreenCapture(bounds);}
            if(capture==null)return;
            var output=lab.auth.LabJson.owned(root,"gui/private-diagnostics/"+operation+".png");
            java.nio.file.Files.createDirectories(output.getParent());
            javax.imageio.ImageIO.write(capture,"png",output.toFile());
        }catch(Exception|OutOfMemoryError unavailable){/* Never replace the primary failure or print private data. */}
    }
    static java.util.List<String> safeThreadFrames(StackTraceElement[] frames) {
        return Arrays.stream(frames).filter(frame->frame.getClassName().matches("(?:burp|bpsh|java|javax|jdk|sun)\\.[A-Za-z0-9_$.]+")
                &&frame.getMethodName().matches("[A-Za-z0-9_$<>]+"))
                .map(frame->frame.getClassName()+"."+frame.getMethodName()).filter(frame->frame.length()<=160).limit(16).toList();
    }
    /** Safe identifiers from owned JVM threads only, with no names, messages, source files or argument values. */
    static java.util.List<Map<String,Object>> threadSnapshots(Map<Thread,StackTraceElement[]> snapshots) {
        return snapshots.entrySet().stream().filter(entry->Arrays.stream(entry.getValue())
                        .anyMatch(frame->frame.getClassName().startsWith("burp.")||frame.getClassName().startsWith("bpsh.")))
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
        return java.util.regex.Pattern.compile("(?m)^\\s*at (burp\\.[A-Za-z0-9_$.<>]+)\\([^\\r\\n]{0,120}\\)\\s*$")
                .matcher(text).results().limit(32).map(match->match.group(1)).toList();
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

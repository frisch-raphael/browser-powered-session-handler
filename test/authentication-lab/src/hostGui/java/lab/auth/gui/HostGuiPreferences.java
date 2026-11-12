package lab.auth.gui;

import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.prefs.*;
import lab.auth.LabJson;

/** Isolated public JDK preference backend; never falls back to host registry preferences. */
public final class HostGuiPreferences implements PreferencesFactory {
    private final Store store;
    private final Preferences user;
    private final Preferences system;
    public HostGuiPreferences() {
        this(configuredRoot());
    }
    public HostGuiPreferences(Path directory) {
        try {
            store=new Store(directory.toRealPath());
            user=new Node(null,"",store,"user");system=new Node(null,"",store,"system");
            Path approved=directory.resolve("approved-preferences.json");
            if(Files.isRegularFile(approved)) {
                var json=LabJson.object(LabJson.read(approved,65536),"version","burp");
                LabJson.require(LabJson.positive(json.get("version"))==1,"GUI_PREFS_VERSION");
                var burp=LabJson.object(json.get("burp"),"burp.eula","use_community_edition");
                for(var entry:burp.entrySet())user.node("burp").put(entry.getKey(),LabJson.text(entry.getValue()));
            }
        }catch(IOException|RuntimeException failed){throw new IllegalStateException("GUI_PREFERENCES_UNAVAILABLE");}
    }
    private static Path configuredRoot() {
        String value=System.getProperty("lab.host.preferences");
        if(value==null)throw new IllegalStateException("GUI_PREFERENCES_ROOT_REQUIRED");return Path.of(value);
    }
    @Override public Preferences userRoot(){return user;}
    @Override public Preferences systemRoot(){return system;}

    /** One-time provisioning copies only the guest's existing approved choices. No agreement is accepted. */
    public static void main(String[] args) {
        try {
            LabJson.require(args.length==2&&args[0].equals("export-approved")&&System.getProperty("java.util.prefs.PreferencesFactory")==null,"GUI_PREFS_EXPORT_ARGUMENTS");
            var source=Preferences.userRoot().node("burp");var values=new LinkedHashMap<String,String>();
            for(String key:List.of("burp.eula","use_community_edition")) {
                String value=source.get(key,null);LabJson.require(value!=null&&!value.isBlank(),"GUI_PREFS_NOT_PROVISIONED");values.put(key,value);
            }
            Path target=Path.of(args[1]).toAbsolutePath();LabJson.writeNew(target,Map.of("version",1,"burp",values));
            System.out.println("Approved preference subset exported privately.");
        }catch(IOException|RuntimeException failed){System.err.println("Approved preference export unavailable.");System.exit(3);}
    }
    private static final class Store {
        final Path root;final Map<String,Map<String,String>> values=new TreeMap<>();
        Store(Path root) throws IOException {
            this.root=root;
            Path file=root.resolve("preferences.json");
            if(Files.isRegularFile(file)) {
                var json=LabJson.object(LabJson.read(file,1_048_576),"version","nodes");
                LabJson.require(LabJson.positive(json.get("version"))==1,"GUI_PREFS_VERSION");
                for(var row:LabJson.object(json.get("nodes")).entrySet()) {
                    LabJson.require(row.getKey().matches("(?:user|system)/.*"),"GUI_PREFS_NODE");
                    var entries=new TreeMap<String,String>();
                    LabJson.object(row.getValue()).entrySet().forEach(e->entries.put(e.getKey(),LabJson.string(e.getValue())));values.put(row.getKey(),entries);
                }
            }
        }
        synchronized void save() throws BackingStoreException {
            Path temporary=null;
            try {
                temporary=Files.createTempFile(root,"prefs-",".json");
                Files.writeString(temporary,LabJson.JSON.toJson(Map.of("version",1,"nodes",values)));
                try{Files.move(temporary,root.resolve("preferences.json"),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
                catch(AtomicMoveNotSupportedException unsupported){Files.move(temporary,root.resolve("preferences.json"),StandardCopyOption.REPLACE_EXISTING);}
            }catch(IOException failed){throw new BackingStoreException("GUI_PREFS_WRITE_FAILED");}
            finally {if(temporary!=null)try{Files.deleteIfExists(temporary);}catch(IOException ignored){}}
        }
    }
    private static final class Node extends AbstractPreferences {
        private final Store store;private final String tree;
        Node(Node parent,String name,Store store,String tree){super(parent,name);this.store=store;this.tree=tree;}
        private String key(){return tree+absolutePath();}
        private Map<String,String> values(){return store.values.computeIfAbsent(key(),unused->new TreeMap<>());}
        @Override protected void putSpi(String key,String value){synchronized(store){values().put(key,value);}}
        @Override protected String getSpi(String key){synchronized(store){return values().get(key);}}
        @Override protected void removeSpi(String key){synchronized(store){values().remove(key);}}
        @Override protected void removeNodeSpi(){synchronized(store){String prefix=key();store.values.keySet().removeIf(k->k.equals(prefix)||k.startsWith(prefix+"/"));}}
        @Override protected String[] keysSpi(){synchronized(store){return values().keySet().toArray(String[]::new);}}
        @Override protected String[] childrenNamesSpi(){synchronized(store){String prefix=key();if(!prefix.endsWith("/"))prefix+="/";final String start=prefix;
            return store.values.keySet().stream().filter(k->k.startsWith(start)&&k.length()>start.length()).map(k->k.substring(start.length()).split("/",2)[0]).distinct().toArray(String[]::new);}}
        @Override protected AbstractPreferences childSpi(String name){var node=new Node(this,name,store,tree);synchronized(store){node.values();}return node;}
        @Override protected void syncSpi() throws BackingStoreException{store.save();}
        @Override protected void flushSpi() throws BackingStoreException{store.save();}
    }
}

package lab.auth.gui;

import java.lang.instrument.Instrumentation;
import java.nio.file.*;
import lab.auth.*;

/** Starts only the public GUI driver; no bytecode transformer or product hook. */
public final class HostGuiBootstrap {
    private HostGuiBootstrap() {}
    public static void premain(String ownedRoot,Instrumentation instrumentation) {
        Thread worker=new Thread(()->{
            HostHeapDiagnostics heap=null;
            try {
                var session=LabHostGuiProtocol.session(Path.of(ownedRoot));
                heap=HostHeapDiagnostics.start(session.root());
                HostGuiDiagnostics.configureLibraryOrigins(instrumentation,session);
                new HostGuiDriver(session).run();
            }
            catch(Exception failed) {
                try {Path root=Path.of(ownedRoot).toRealPath();LabJson.writeNew(root.resolve("gui-bootstrap-failed.json"),
                        java.util.Map.of("version",1,"code","GUI_BOOTSTRAP_FAILED"));}
                catch(Exception unavailable){/* Never log private input, exception messages or stack traces. */}
            }
            finally {if(heap!=null)heap.close();}
        },"authlab-owned-gui");worker.setDaemon(true);worker.start();
    }
}

package bpsh.support;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Actual descendant process witness shared by native browser tests and captured acceptance. */
public class BrowserProcessWitness implements AutoCloseable {
        public final long began=System.nanoTime();
    private final Map<Long,Instant> observed=new ConcurrentHashMap<>();
    private final java.util.Set<Long> drivers=ConcurrentHashMap.newKeySet();
    private final java.util.concurrent.ScheduledExecutorService observer=Executors.newSingleThreadScheduledExecutor();
    private long alive;private boolean closed;
    public BrowserProcessWitness(){observer.scheduleAtFixedRate(this::sample,0,5,TimeUnit.MILLISECONDS);}
    private void sample(){ProcessHandle.current().descendants().forEach(handle->{
        String command=handle.info().command().orElse("").replace('\\','/').toLowerCase(java.util.Locale.ROOT);
        if(command.endsWith("/node.exe")||command.endsWith("/node")||command.endsWith("/chrome.exe")||command.endsWith("/chrome")||command.endsWith("/javaw.exe")||command.endsWith("/java"))observed.putIfAbsent(handle.pid(),handle.info().startInstant().orElse(Instant.EPOCH));
        if(command.endsWith("/node.exe")||command.endsWith("/node"))drivers.add(handle.pid());
    });}
    public int processes(){return observed.size();}public int drivers(){return drivers.size();}public long alive(){return alive;}
    public void requireObserved(int expectedDrivers){assertTrue(closed);assertFalse(observed.isEmpty(),"A real browser process witness is required.");assertEquals(expectedDrivers,drivers.size(),"Require exactly the owned driver count.");}
    @Override public void close() throws Exception {
        if(closed)return;closed=true;sample();observer.shutdownNow();assertTrue(observer.awaitTermination(2,TimeUnit.SECONDS));
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        do {
            alive=observed.entrySet().stream().filter(entry->ProcessHandle.of(entry.getKey()).filter(handle->handle.isAlive()
                    &&(entry.getValue().equals(Instant.EPOCH)||handle.info().startInstant().orElse(Instant.EPOCH).equals(entry.getValue()))).isPresent()).count();
            if(alive==0)break;Thread.sleep(10);
        }while(System.nanoTime()<deadline);
        assertEquals(0,alive,"Observed browser/driver descendants must close after their owner returns.");
    }
}

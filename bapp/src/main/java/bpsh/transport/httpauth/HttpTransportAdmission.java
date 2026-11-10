package bpsh.transport.httpauth;

import bpsh.authentication.http.HttpMessageBody;
import java.io.IOException;
import java.util.IdentityHashMap;
import java.util.Map;

/** Atomic global/per-scope admission shared by every adapter using one runtime. */
final class HttpTransportAdmission {
    final HttpConnectionBudget connections=new HttpConnectionBudget();
    final java.util.function.LongSupplier clock;
    volatile Runnable reclaimIdle=()->{ };
    HttpTransportAdmission() {this(System::nanoTime);}
    HttpTransportAdmission(java.util.function.LongSupplier clock) {this.clock=clock;}
    void beforeConnect() {if(connections.used()>=16)reclaimIdle.run();}
    final HttpMessageBody.Allocator bodies=new HttpMessageBody.Allocator(64L*1024*1024);
    private final Map<Object,Integer> scopes=new IdentityHashMap<>();
    private int admitted;
    synchronized Permit acquire(Object scope) throws IOException {
        int local=scopes.getOrDefault(scope,0);
        if(admitted>=64 || local>=16)throw new IOException("HTTP authentication delivery capacity is exhausted.");
        admitted++;scopes.put(scope,local+1);return new Permit(scope);
    }
    synchronized int admitted() {return admitted;}
    final class Permit implements AutoCloseable {
        private final Object scope;
        private boolean closed;
        private Permit(Object scope) {this.scope=scope;}
        @Override public void close() {
            synchronized(HttpTransportAdmission.this) {
                if(closed)return;closed=true;admitted--;
                int remaining=scopes.get(scope)-1;
                if(remaining==0)scopes.remove(scope);else scopes.put(scope,remaining);
            }
        }
    }
}

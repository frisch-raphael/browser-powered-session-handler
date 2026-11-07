package lab.federation;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;

/** Case-private protocol hooks. They change one declared field and never implement an OAuth exchange. */
final class FederationProtocol implements ApplicationListener<ContextClosedEvent>,AutoCloseable {
    enum Variant {
        EXPIRED("code-expired","before-token-exchange","token_uri"),
        CLIENT_HOLD("client-publication-hold","before-client-session","client_publication");
        final String label,checkpoint,field;
        Variant(String label,String checkpoint,String field){this.label=label;this.checkpoint=checkpoint;this.field=field;}
        static Variant parse(String label){return Arrays.stream(values()).filter(v->v.label.equals(label)).findFirst().orElseThrow(()->new Failure(400,"BAD_INPUT"));}
    }
    static final class Failure extends RuntimeException {
        final int status;final String code;
        Failure(int status,String code){super(code);this.status=status;this.code=code;}
    }
    private final FederationApplication.Settings settings;
    private final List<Map<String,Object>> events=new ArrayList<>();
    private long sequence;
    private Variant variant;
    private CountDownLatch gate;
    private boolean waiting,released,retired,simulatedResponse;

    FederationProtocol(FederationApplication.Settings settings){this.settings=settings;}
    synchronized Variant variant(){return variant;}
    synchronized boolean simulatedExpiry(){return variant==Variant.EXPIRED;}
    synchronized boolean simulatedResponseObserved(){return simulatedResponse;}

    /** Only this exact prepared negative case can arm its one declared checkpoint, before its next login. */
    synchronized void arm(String name,String checkpoint) {
        if(retired)throw new Failure(410,"RETIRED");
        Variant selected=Variant.parse(name);
        String owner=selected==Variant.EXPIRED?"FED.negative.code-expired":"FED.broker.cancelled";
        if(!settings.caseId().equals(owner)||variant!=null)throw new Failure(409,"STATE_CONFLICT");
        if(!selected.checkpoint.equals(checkpoint))throw new Failure(400,"BAD_INPUT");
        variant=selected;gate=new CountDownLatch(1);event("LOGIN","control-armed-"+selected.label);
    }

    /** Waits for explicit release, bounded independently from the browser's production attempt deadline. */
    void checkpoint(String checkpoint) {
        CountDownLatch selected;
        synchronized(this) {
            if(retired)throw new Failure(410,"RETIRED");
            event(checkpoint.equals("before-token-exchange")?"TOKEN_EXCHANGE":"PROTECTED",checkpoint);
            if(variant==null||!variant.checkpoint.equals(checkpoint))return;
            waiting=true;selected=gate;notifyAll();
        }
        boolean opened;
        try{opened=selected.await(5,TimeUnit.SECONDS);}catch(InterruptedException error){Thread.currentThread().interrupt();throw new Failure(410,"RETIRED");}
        synchronized(this) {
            if(retired)throw new Failure(410,"RETIRED");
            if(!opened){event("LOGIN","checkpoint-deadline");throw new Failure(504,"DEADLINE");}
        }
    }
    synchronized void release(String checkpoint) {
        if(retired)throw new Failure(410,"RETIRED");
        if(variant==null||!variant.checkpoint.equals(checkpoint))throw new Failure(404,"NOT_FOUND");
        if(!waiting||released)throw new Failure(409,"STATE_CONFLICT");
        released=true;gate.countDown();event("LOGIN","checkpoint-released");notifyAll();
    }
    synchronized void exchangeStarted(){event("TOKEN_EXCHANGE","token-exchange-started");}
    synchronized void exchangeAccepted(){event("TOKEN_EXCHANGE","token-exchange-accepted");}
    synchronized void changedField(){if(variant!=null)event("TOKEN_EXCHANGE","changed-field-"+variant.field);}
    synchronized void expiredResponse(){
        if(retired||variant!=Variant.EXPIRED)throw new Failure(404,"NOT_FOUND");
        simulatedResponse=true;event("TOKEN_EXCHANGE","simulated-expired-code-response");
    }
    synchronized void sessionEstablished(){event("PROTECTED","client-session-established");}
    synchronized void clientCookieEstablished(){event("PROTECTED","client-cookie-established");}
    synchronized void rejected(String category) {
        String safe=Set.of("invalid_state_parameter","authorization_request_not_found","invalid_grant","invalid_token_response","invalid_request").contains(category)?category:"unclassified";
        event("TOKEN_EXCHANGE","client-rejected-"+safe);
    }
    private synchronized void event(String phase,String name) {
        long next=++sequence;
        if(events.size()<10000)events.add(Map.of("sequence",next,"time",Instant.now().toString(),"phase",phase,"name",name,"safeIds",List.of()));
    }
    synchronized List<Map<String,Object>> events(){return List.copyOf(events);}
    synchronized List<Map<String,Object>> checkpoints(){
        return variant==null?List.of():List.of(Map.of("name",variant.checkpoint,"state",retired?"RETIRED":released?"RELEASED":waiting?"WAITING":"ARMED"));
    }
    synchronized boolean truncated(){return sequence>10000;}

    /** ContextClosedEvent precedes web-server draining, so a held request cannot delay normal Stop. */
    @Override public void onApplicationEvent(ContextClosedEvent event){close();}
    @Override public synchronized void close(){
        if(retired)return;retired=true;if(gate!=null)gate.countDown();event("LOGIN","protocol-retired");notifyAll();
    }
}

package bpsh.browser.runtime;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.CDPSession;
import com.microsoft.playwright.PlaywrightException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/** Installs response interception before an owned Chromium page starts its scripts. */
final class EarlyBrowserTargets implements AutoCloseable {
    private final BrowserContext context;
    private final CDPSession root;
    private final Consumer<CDPSession> initializer;
    private final List<Target> targets = new ArrayList<>();
    private final Set<String> targetIds = new HashSet<>();
    private boolean closed;

    /** @param context Sole context in an attempt-owned browser. @param initializer Bounded response setup. */
    EarlyBrowserTargets(BrowserContext context, Consumer<CDPSession> initializer) {
        this.context=context;this.initializer=initializer;root=context.browser().newBrowserCDPSession();
        try { observe(root,true); enable(root,true,true); }
        catch(RuntimeException failed){close();throw failed;}
    }
    /** Subscribes before enabling automatic target attachment. */
    private void observe(CDPSession parent,boolean browserLevel) {
        var children=new HashMap<String,Target>();
        parent.on("Target.attachedToTarget",event->{
            var info=event.getAsJsonObject("targetInfo");String targetId=info.get("targetId").getAsString();
            String id=event.get("sessionId").getAsString();String flatId=browserLevel?id:null;
            String type=info.get("type").getAsString();
            if(targetIds.contains(targetId))return; // Ignore our explicit nested attachment notification.
            if(closed||!type.equals("page")&&!type.equals("iframe")) {
                var args=new JsonObject();args.addProperty("sessionId",id);parent.send("Target.detachFromTarget",args);return;
            }
            targetIds.add(targetId);
            if(targets.size()>=64)throw new PlaywrightException("Too many owned browser targets.");
            if(browserLevel) {
                // Browser auto-attachment requires flat mode. Keep that target paused while opening
                // its public nested channel, then release the temporary flat attachment after setup.
                var args=new JsonObject();args.addProperty("targetId",targetId);args.addProperty("flatten",false);
                id=parent.send("Target.attachToTarget",args).get("sessionId").getAsString();
            }
            var target=new Target(parent,id,targetId);children.put(id,target);targets.add(target);
            try { initializer.accept(target);observe(target,false);enable(target,true,false); }
            finally {
                if(flatId!=null){var args=new JsonObject();args.addProperty("sessionId",flatId);parent.send("Target.detachFromTarget",args);}
                if(!target.closed)target.send("Runtime.runIfWaitingForDebugger");
            }
        });
        parent.on("Target.receivedMessageFromTarget",event->{
            var child=children.get(event.get("sessionId").getAsString());
            if(child!=null)child.dispatch(JsonParser.parseString(event.get("message").getAsString()).getAsJsonObject());
        });
        parent.on("Target.detachedFromTarget",event->{var child=children.remove(event.get("sessionId").getAsString());if(child!=null){targets.remove(child);targetIds.remove(child.targetId);child.ended();}});
    }
    /** Uses nested sessions so commands and replies stay on the public CDP API. */
    private static void enable(CDPSession session,boolean enabled,boolean flat) {
        var args=new JsonObject();args.addProperty("autoAttach",enabled);args.addProperty("waitForDebuggerOnStart",enabled);args.addProperty("flatten",flat);
        session.send("Target.setAutoAttach",args);
    }
    @Override public void close() {
        if(closed)return;closed=true;
        try{enable(root,false,true);}catch(RuntimeException ignored){/* owned browser may have closed */}
        targets.forEach(Target::ended);targets.clear();targetIds.clear();
        try{root.detach();}catch(RuntimeException ignored){/* owned browser may have closed */}
    }
    /** Public-CDP nested target channel; pending replies are bounded and never retain vendor diagnostics. */
    private final class Target implements CDPSession {
        private final CDPSession parent;
        private final String id,targetId;
        private final Map<Integer,CompletableFuture<JsonObject>> pending=new HashMap<>();
        private final Map<String,List<Consumer<JsonObject>>> listeners=new HashMap<>();
        private final List<Consumer<CDPSession>> closeListeners=new ArrayList<>();
        private int sequence;
        private boolean closed;
        /** @param parent Owning protocol channel. @param id Its attached child session. @param targetId Owned target identity. */
        Target(CDPSession parent,String id,String targetId){this.parent=parent;this.id=id;this.targetId=targetId;}
        @Override public JsonObject send(String method,JsonObject parameters) {
            if(closed||pending.size()>=64)throw protocolFailure();
            int number=++sequence;var reply=new CompletableFuture<JsonObject>();pending.put(number,reply);
            try {
                var command=new JsonObject();command.addProperty("id",number);command.addProperty("method",method);command.add("params",parameters);
                var envelope=new JsonObject();envelope.addProperty("sessionId",id);envelope.addProperty("message",command.toString());
                parent.send("Target.sendMessageToTarget",envelope);
                context.waitForCondition(reply::isDone);
                try{return reply.join();}catch(java.util.concurrent.CompletionException failed){throw protocolFailure();}
            }finally{pending.remove(number);}
        }
        /** Routes one reply/event from the parent; caller stays on the original Playwright worker. */
        void dispatch(JsonObject message) {
            if(closed)return;
            if(message.has("id")) {
                var reply=pending.get(message.get("id").getAsInt());if(reply==null)return;
                if(message.has("error"))reply.completeExceptionally(protocolFailure());
                else reply.complete(message.has("result")?message.getAsJsonObject("result"):new JsonObject());
            }else if(message.has("method")) {
                var handlers=List.copyOf(listeners.getOrDefault(message.get("method").getAsString(),List.of()));
                var args=message.has("params")?message.getAsJsonObject("params"):new JsonObject();handlers.forEach(handler->handler.accept(args));
            }
        }
        /** Revokes pending replies and listeners after target loss or owner shutdown. */
        void ended(){if(closed)return;closed=true;pending.values().forEach(reply->reply.completeExceptionally(protocolFailure()));
            listeners.clear();List.copyOf(closeListeners).forEach(listener->listener.accept(this));closeListeners.clear();}
        @Override public void on(String event,Consumer<JsonObject> listener){listeners.computeIfAbsent(event,ignored->new ArrayList<>()).add(listener);}
        @Override public void off(String event,Consumer<JsonObject> listener){listeners.getOrDefault(event,new ArrayList<>()).remove(listener);}
        @Override public void onClose(Consumer<CDPSession> listener){closeListeners.add(listener);}
        @Override public void offClose(Consumer<CDPSession> listener){closeListeners.remove(listener);}
        @Override public void detach(){if(closed)return;try{var args=new JsonObject();args.addProperty("sessionId",id);parent.send("Target.detachFromTarget",args);}finally{ended();}}
    }
    /** Fixed failure text excludes protocol errors, URLs and response data. */
    private static PlaywrightException protocolFailure(){return new PlaywrightException("The owned Chromium target protocol failed.");}
}

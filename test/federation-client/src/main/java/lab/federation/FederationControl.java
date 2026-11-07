package lab.federation;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.JsonNode;

/** Separate child-control listener; application routes never expose its key or forward requests here. */
public final class FederationControl implements ApplicationListener<ApplicationReadyEvent>, AutoCloseable {
    private final FederationApplication.Settings settings;
    private final ConfigurableApplicationContext context;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final CountDownLatch stopped = new CountDownLatch(1);
    private volatile RuntimeException cleanupFailure;
    private final Instant started = Instant.now();
    private boolean published;

    FederationControl(FederationApplication.Settings settings, ConfigurableApplicationContext context) throws IOException {
        this.settings = settings; this.context = context;
        if (Files.exists(settings.directory().resolve("ready-" + settings.role() + ".json"))) throw new IOException("Child launch directory already has a readiness record.");
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 16);
        server.setExecutor(executor); server.createContext("/", this::handle);
    }

    /** Readiness is published after the HTTPS server actually starts, never merely after bean construction. */
    @Override public synchronized void onApplicationEvent(ApplicationReadyEvent event) {
        if (published || closed.get()) return;
        try { server.start(); publish("READY"); published = true; }
        catch (IOException | RuntimeException error) { close(); throw new IllegalStateException("Federation readiness failed."); }
    }

    /** Handles only authenticated, versioned operations and returns closed-field safe errors. */
    private void handle(HttpExchange exchange) throws IOException {
        String caseId = null; Long expected = null;
        try {
            var authorization = exchange.getRequestHeaders().get("Authorization");
            if (authorization == null || authorization.size() != 1 || !MessageDigest.isEqual(authorization.getFirst().getBytes(StandardCharsets.UTF_8),
                    ("Bearer " + settings.controlKey()).getBytes(StandardCharsets.UTF_8))) { error(exchange, 401, "UNAUTHORIZED", caseId, expected); return; }
            String base = "/control/v1/runs/" + settings.runId();
            String path = exchange.getRequestURI().getRawPath();
            String caseBase=base+"/cases/"+settings.caseId();
            if(settings.role().equals("client")&&exchange.getRequestMethod().equals("POST")&&path.equals(caseBase+"/federation-control")) {
                caseId=settings.caseId();JsonNode body=operation(exchange,Set.of("generation","variant","checkpoint"));expected=body.get("generation").asLong();
                if(expected!=settings.generation()){error(exchange,409,"GENERATION_CONFLICT",caseId,expected);return;}
                if(!body.get("variant").isString()||!body.get("checkpoint").isString())throw new IllegalArgumentException();
                context.getBean(FederationProtocol.class).arm(body.get("variant").asString(),body.get("checkpoint").asString());
                json(exchange,200,Map.of("generation",expected,"armed",true));return;
            }
            if(settings.role().equals("client")&&exchange.getRequestMethod().equals("POST")&&path.startsWith(caseBase+"/gates/")&&path.endsWith("/release")) {
                caseId=settings.caseId();JsonNode body=operation(exchange,Set.of("generation"));expected=body.get("generation").asLong();
                if(expected!=settings.generation()){error(exchange,409,"GENERATION_CONFLICT",caseId,expected);return;}
                String checkpoint=path.substring((caseBase+"/gates/").length(),path.length()-"/release".length());
                context.getBean(FederationProtocol.class).release(checkpoint);json(exchange,200,Map.of("generation",expected,"released",true));return;
            }
            if (path.equals(base + "/stop") && exchange.getRequestMethod().equals("POST")) {
                JsonNode body = body(exchange);
                if (body == null || !body.isObject() || !new HashSet<>(body.propertyNames()).equals(Set.of("generation")) || !body.get("generation").isIntegralNumber()
                        || !body.get("generation").canConvertToLong() || body.get("generation").asLong() < 1) { error(exchange,400,"BAD_INPUT",caseId,expected); return; }
                expected = body.get("generation").asLong();
                if (expected != settings.generation()) { error(exchange,409,"GENERATION_CONFLICT",caseId,expected); return; }
                json(exchange,202,Map.of("state","STOPPING")); Thread.startVirtualThread(context::close); return;
            }
            String snapshot = base + "/cases/" + settings.caseId() + "/snapshot";
            if (path.equals(snapshot) && exchange.getRequestMethod().equals("GET")) {
                caseId = settings.caseId();
                String query = exchange.getRequestURI().getRawQuery();
                if (query == null || !query.matches("generation=[1-9][0-9]{0,18}")) { error(exchange,400,"BAD_INPUT",caseId,expected); return; }
                expected = Long.parseLong(query.substring(11));
                if (expected != settings.generation()) { error(exchange,409,"GENERATION_CONFLICT",caseId,expected); return; }
                var result = new LinkedHashMap<String,Object>(); result.put("runId",settings.runId()); result.put("caseId",settings.caseId()); result.put("generation",settings.generation());
                FederationProtocol protocol=settings.role().equals("client")?context.getBean(FederationProtocol.class):null;
                result.put("state",closed.get()?"CLOSED":"PREPARED"); result.put("checkpoints",protocol==null?List.of():protocol.checkpoints());
                var counters = new LinkedHashMap<String,Object>(); for(String name:List.of("httpIngress","routed","actions","connections","tlsHandshakes","applicationBytes")) counters.put(name,null);
                result.put("counters",counters); result.put("events",protocol==null?List.of():protocol.events()); result.put("truncated",protocol!=null&&protocol.truncated()); json(exchange,200,result); return;
            }
            error(exchange,404,"NOT_FOUND",caseId,expected);
        } catch (FederationProtocol.Failure failure) { error(exchange,failure.status,failure.code,caseId,expected); }
        catch (TooLarge error) { error(exchange,413,"TOO_LARGE",caseId,expected); }
        catch (IllegalArgumentException error) { error(exchange,400,"BAD_INPUT",caseId,expected); }
        catch (Exception error) { error(exchange,500,"INTERNAL",caseId,expected); }
        finally { exchange.close(); }
    }

    /** Limits control input before parsing; malformed parser details never leave the listener. */
    private static JsonNode body(HttpExchange exchange) throws IOException {
        String type = exchange.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !type.split(";",2)[0].trim().equalsIgnoreCase("application/json")) throw new IllegalArgumentException();
        byte[] bytes = exchange.getRequestBody().readNBytes(65_537); if(bytes.length>65_536)throw new TooLarge();
        try { return FederationApplication.JSON.readTree(bytes); } catch (RuntimeException error) { throw new IllegalArgumentException(); }
    }
    private static final class TooLarge extends IOException {}
    private static JsonNode operation(HttpExchange exchange,Set<String> fields) throws IOException {
        if(exchange.getRequestURI().getRawQuery()!=null)throw new IllegalArgumentException();
        JsonNode value=body(exchange);
        if(value==null||!value.isObject()||!new HashSet<>(value.propertyNames()).equals(fields)||!value.get("generation").isIntegralNumber()
                ||!value.get("generation").canConvertToLong()||value.get("generation").asLong()<1)throw new IllegalArgumentException();return value;
    }

    /** Writes the shared safe error envelope without any source exception or request-body text. */
    private void error(HttpExchange exchange,int status,String code,String caseId,Long expected) throws IOException {
        var detail = new LinkedHashMap<String,Object>(); detail.put("code",code); detail.put("message",code); detail.put("runId",settings.runId());
        detail.put("caseId",caseId); detail.put("generation",expected); json(exchange,status,Map.of("error",detail));
    }
    private static void json(HttpExchange exchange,int status,Object value) throws IOException {
        byte[] bytes = FederationApplication.JSON.writeValueAsBytes(value); exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(status,bytes.length); try(var output=exchange.getResponseBody()){output.write(bytes);}
    }

    /** Writes only the child bootstrap descriptor, inside its private launch directory. */
    private void publish(String state) throws IOException {
        var descriptor = new LinkedHashMap<String,Object>(); descriptor.put("readinessVersion",1); descriptor.put("invocationId",settings.invocationId());
        descriptor.put("runId",settings.runId()); descriptor.put("caseId",settings.caseId()); descriptor.put("generation",settings.generation()); descriptor.put("role",settings.role());
        descriptor.put("pid",ProcessHandle.current().pid()); descriptor.put("startedAt",started.toString()); descriptor.put("state",state); descriptor.put("origin",settings.applicationOrigin().toString());
        descriptor.put("controlUri","http://127.0.0.1:"+server.getAddress().getPort()+"/control/v1/runs/"+settings.runId()); descriptor.put("controlKey",settings.controlKey());
        Path path = settings.directory().resolve("ready-"+settings.role()+".json");
        Path pending = settings.directory().resolve("ready-"+settings.role()+".pending");
        Files.createFile(pending);
        try {
            restrict(pending); Files.write(pending,FederationApplication.JSON.writeValueAsBytes(descriptor));
            for(int attempt=0;;attempt++) {
                try { Files.move(pending,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING); break; }
                catch(AccessDeniedException error) {
                    if(attempt==4)throw error;
                    try { Thread.sleep(25L<<attempt); }
                    catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException("Readiness publication interrupted.");}
                }
            }
        } finally { Files.deleteIfExists(pending); }
    }
    private static void restrict(Path path) throws IOException {
        var posix = Files.getFileAttributeView(path,PosixFileAttributeView.class);
        if(posix!=null)Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
        else {
            var acl=Files.getFileAttributeView(path,AclFileAttributeView.class); if(acl==null)throw new IOException("Private readiness permissions unavailable.");
            acl.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(acl.getOwner()).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));
        }
    }
    /** Settles owned listener work before recording the closed child state. */
    @Override public void close() {
        if(!closed.compareAndSet(false,true))return;
        try {
            server.stop(0); executor.shutdownNow();
            if(!executor.awaitTermination(3,TimeUnit.SECONDS))throw new IllegalStateException("Federation control cleanup deadline."); if(published)publish("CLOSED");
        }
        catch(InterruptedException error){Thread.currentThread().interrupt();cleanupFailure=new IllegalStateException("Federation control cleanup interrupted.");throw cleanupFailure;}
        catch(IOException error){cleanupFailure=new UncheckedIOException("Federation control terminal record failed.",error);throw cleanupFailure;}
        catch(RuntimeException error){cleanupFailure=error;throw error;}
        finally { stopped.countDown(); }
    }
    /** Keeps the child main alive until terminal state is retained, including when stop runs on a virtual thread. */
    public void awaitClosed() throws InterruptedException { stopped.await(); if(cleanupFailure!=null)throw cleanupFailure; }
}

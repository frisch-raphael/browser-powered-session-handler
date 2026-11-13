package lab.auth;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LabHostWindowsListenersTest {
    private static byte[] bytes(String text){return text.getBytes(StandardCharsets.ISO_8859_1);}
    private static Set<Integer> parse(String table){return LabHostWindowsListeners.parse(bytes(table),123);}
    private static String row(String local,String remote,String state,long pid){return "  TCP    "+local+"    "+remote+"    "+state+"    "+pid+"\r\n";}
    private static void failure(String code,org.junit.jupiter.api.function.Executable action) {
        assertEquals(code,assertThrows(IllegalArgumentException.class,action).getMessage());
    }

    @Test void observesOnlyExactOwnedLoopbackListeningPortsAcrossWindowsAddressForms() {
        String table="Connexions actives\r\n  Proto  Adresse locale  Adresse distante  Etat  PID\r\n"
                +row("127.0.0.1:8081","0.0.0.0:0","LISTENING",123)
                +row("[::1]:8082","[::]:0","LISTENING",123)
                +row("[::FFFF:127.0.0.1]:8083","[::ffff:0.0.0.0]:0","LISTENING",123)
                +row("127.0.0.1:9000","0.0.0.0:0","LISTENING",124)
                +row("127.0.0.1:9001","127.0.0.1:8081","ESTABLISHED",123)
                +row("0.0.0.0:9002","0.0.0.0:0","LISTENING",123)
                +row("[::]:9003","[::]:0","LISTENING",123)
                +row("127.0.0.2:9004","0.0.0.0:0","LISTENING",123);
        assertEquals(Set.of(8081,8082,8083),parse(table));
    }

    @Test void wrongPidPortStateAndWildcardCannotProveARequiredListener() {
        for(String candidate:List.of(
                row("127.0.0.1:8081","0.0.0.0:0","LISTENING",124),
                row("127.0.0.1:8082","0.0.0.0:0","LISTENING",123),
                row("127.0.0.1:8081","127.0.0.1:2222","ESTABLISHED",123),
                row("0.0.0.0:8081","0.0.0.0:0","LISTENING",123),
                row("[::]:8081","[::]:0","LISTENING",123),
                row("127.0.0.2:8081","0.0.0.0:0","LISTENING",123))) {
            assertFalse(parse(candidate).contains(8081));
        }
        assertEquals(Set.of(),parse(""));
    }

    @Test void refusesMalformedAmbiguousAndNonNumericRowsWithoutEchoingTheirContents() {
        String valid=row("127.0.0.1:8081","0.0.0.0:0","LISTENING",123);
        for(String table:List.of(
                valid+valid,
                "TCP 127.0.0.1:8081 0.0.0.0:0 LISTENING 123 EXTRA_PRIVATE_VALUE",
                "TCP 127.0.0.1:8081 0.0.0.0:0 LISTENING 123 124",
                "TCP localhost:8081 0.0.0.0:0 LISTENING 123",
                "TCP 127.0.0.1:65536 0.0.0.0:0 LISTENING 123",
                "TCP 127.0.0.1:0 0.0.0.0:0 LISTENING 123",
                "TCP [::::]:8081 [::]:0 LISTENING 123",
                "TCP [deadbeef]:8081 [::]:0 LISTENING 123",
                "TCP 999.0.0.1:8081 0.0.0.0:0 LISTENING 123",
                "TCP 127.0.0.1:8081 0.0.0.0:0 LISTENING -123",
                "TCP 127.0.0.1:8081 0.0.0.0:0 LISTENING 4294967296",
                "TCP 127.0.0.1:8081 127.0.0.1:0 LISTENING 123",
                "TCP 127.0.0.1:8081 0.0.0.0:22 LISTENING 123",
                "TCP "+"PRIVATE".repeat(100))) {
            failure("HOST_LISTENER_QUERY_MALFORMED",()->parse(table));
        }
    }

    @Test void boundsTheWholeTableAndEveryLineBeforeParsing() {
        byte[] boundary=new byte[LabHostWindowsListeners.OUTPUT_LIMIT];Arrays.fill(boundary,(byte)'\n');
        assertEquals(Set.of(),LabHostWindowsListeners.parse(boundary,123));
        failure("HOST_LISTENER_QUERY_OVERSIZE",()->LabHostWindowsListeners.parse(new byte[boundary.length+1],123));
        failure("HOST_LISTENER_QUERY_MALFORMED",()->parse("x".repeat(LabHostWindowsListeners.LINE_LIMIT+1)));
        failure("HOST_LISTENER_IDENTITY",()->LabHostWindowsListeners.parse(new byte[0],0));
    }

    @Test void queryCompletesWithinTheUnchangedBudgetAndCollectsOnlyBoundedBytes() throws Exception {
        assertEquals(10_000,LabHostWindowsListeners.QUERY_TIMEOUT_MILLIS);
        var query=new QueryProcess(bytes("numeric output"),false,0);
        assertArrayEquals(bytes("numeric output"),LabHostWindowsListeners.collect(query,1000,()->true));
        assertFalse(query.isAlive());assertTrue(query.stream.closed);
    }

    @Test void nonzeroExitIsDistinctAndNeverLeaksCommandOutput() {
        var query=new QueryProcess(bytes("PRIVATE_ENDPOINTS"),false,7);
        failure("HOST_LISTENER_QUERY_EXIT",()->LabHostWindowsListeners.collect(query,1000,()->true));
        assertFalse(query.isAlive());assertTrue(query.stream.closed);
    }

    @Test void timeoutStopsOnlyTheDirectOwnedQuery() {
        var query=new QueryProcess(new byte[0],true,0);
        failure("HOST_LISTENER_QUERY_TIMEOUT",()->LabHostWindowsListeners.collect(query,15,()->true));
        assertTrue(query.destroyed);assertFalse(query.isAlive());assertTrue(query.stream.closed);
    }

    @Test void oversizedOutputStopsItsQueryAndHasADistinctFailure() {
        var query=new QueryProcess(new byte[LabHostWindowsListeners.OUTPUT_LIMIT+1],true,0);
        failure("HOST_LISTENER_QUERY_OVERSIZE",()->LabHostWindowsListeners.collect(query,1000,()->true));
        assertTrue(query.destroyed);assertFalse(query.isAlive());assertTrue(query.stream.closed);
    }

    @Test void changedBurpIdentityCannotAcceptAnOtherwiseSuccessfulObservation() {
        var query=new QueryProcess(bytes("numeric output"),false,0);var checks=new AtomicInteger();
        failure("HOST_LISTENER_IDENTITY",()->LabHostWindowsListeners.collect(query,1000,()->checks.incrementAndGet()==1));
        assertTrue(query.stream.closed);
    }

    @Test void unreadableOutputHasAFixedFailureAndReleasesTheStream() {
        var query=new QueryProcess(new byte[0],false,0);query.stream.unreadable=true;
        failure("HOST_LISTENER_QUERY_READ",()->LabHostWindowsListeners.collect(query,1000,()->true));
        assertTrue(query.stream.closed);
    }

    @Test void interruptionStillStopsAndReleasesTheOwnedQuery() {
        var query=new QueryProcess(new byte[0],true,0);query.interruptWait=true;
        try {
            assertThrows(InterruptedException.class,()->LabHostWindowsListeners.collect(query,1000,()->true));
            assertTrue(query.destroyed);assertFalse(query.isAlive());assertTrue(query.stream.closed);
        }finally{Thread.interrupted();}
    }

    private static final class QueryProcess extends Process {
        final TrackedStream stream;boolean alive,destroyed,interruptWait;final int exit;
        QueryProcess(byte[] output,boolean alive,int exit){stream=new TrackedStream(output);this.alive=alive;this.exit=exit;}
        @Override public OutputStream getOutputStream(){return OutputStream.nullOutputStream();}
        @Override public InputStream getInputStream(){return stream;}
        @Override public InputStream getErrorStream(){return InputStream.nullInputStream();}
        @Override public int waitFor(){return exitValue();}
        @Override public boolean waitFor(long time,TimeUnit unit) throws InterruptedException {
            if(interruptWait){interruptWait=false;throw new InterruptedException();}
            if(alive)TimeUnit.NANOSECONDS.sleep(unit.toNanos(time));return !alive;
        }
        @Override public int exitValue(){if(alive)throw new IllegalThreadStateException();return exit;}
        @Override public void destroy(){destroyForcibly();}
        @Override public Process destroyForcibly(){destroyed=true;alive=false;return this;}
        @Override public boolean isAlive(){return alive;}
    }
    private static final class TrackedStream extends InputStream {
        private final ByteArrayInputStream data;volatile boolean closed,unreadable;
        TrackedStream(byte[] bytes){data=new ByteArrayInputStream(bytes);}
        @Override public int read() throws IOException {if(unreadable)throw new IOException("PRIVATE_ENDPOINTS");return data.read();}
        @Override public int read(byte[] bytes,int off,int len) throws IOException {if(unreadable)throw new IOException("PRIVATE_ENDPOINTS");return data.read(bytes,off,len);}
        @Override public void close(){closed=true;}
    }
}

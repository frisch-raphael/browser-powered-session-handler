package lab.auth;

import java.io.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LabHostMemoryTest {
    @Test void gcSummaryCountsOnlyNumericDistinctObjectsPerCollection() {
        String one="[123ms][debug][gc,humongous] GC(3) Humongous region 0 (object size 1048576)\n";
        var value=LabHostMemory.gcNumbers(one+one+"[124ms][debug][gc,humongous] GC(3) Humongous region 4 (object size 2097152)\n"
                +"[130ms][debug][gc,humongous] GC(4) Humongous region 0 (object size 1048576)\n",true);
        assertTrue(value.get("complete").getAsBoolean());assertEquals(3145728,value.get("peakObservedHumongousBytes").getAsLong());
        assertEquals(2097152,value.get("maxObservedObjectBytes").getAsLong());assertEquals(2,value.get("gcObservations").getAsInt());
        assertFalse(LabHostMemory.gcNumbers(one.stripTrailing(),true).get("complete").getAsBoolean());
        assertTrue(LabHostMemory.gcNumbers(one.replace("\n","\r\n"),true).get("complete").getAsBoolean());
        assertFalse(LabHostMemory.gcNumbers(one+"PRIVATE_SENTINEL\n",true).get("complete").getAsBoolean());
        assertFalse(LabHostMemory.gcNumbers(one+one.replace("1048576","1048577"),true).get("complete").getAsBoolean());
    }
    @Test void gcFileProofRejectsMissingRotatedAndOversizedLogsWithoutPublishingText() throws Exception {
        assertFalse(LabHostMemory.gcSummary(directory).get("complete").getAsBoolean());
        Files.writeString(directory.resolve("gc-private.log"),"[1ms][info][gc,heap] GC(0) Humongous regions: 0->0\n");
        assertTrue(LabHostMemory.gcSummary(directory).get("complete").getAsBoolean());
        Files.writeString(directory.resolve("gc-private.log.0"),"PRIVATE_SENTINEL");
        var value=LabHostMemory.gcSummary(directory);assertFalse(value.get("complete").getAsBoolean());assertFalse(value.toString().contains("PRIVATE_SENTINEL"));
        Path oversized=Files.createDirectory(directory.resolve("oversized"));Files.writeString(oversized.resolve("gc-private.log"),"x".repeat(8*1024*1024+1));
        assertFalse(LabHostMemory.gcSummary(oversized).get("complete").getAsBoolean());
    }
    @TempDir Path directory;
    private final LabHostMemory.Identity identity=new LabHostMemory.Identity(123,1700000000123L);
    private String header(){return "BPSH_MEMORY_V1 123 1700000000123 200\n";}
    private String row(int sequence,long rss){return "S "+sequence+" 123 1700000000123 "+(1700000000123L+sequence*200)+" "+rss+"\n";}
    private LabHostMemory.Parsed parse(String text) throws Exception {
        Path path=directory.resolve("parse.samples");Files.writeString(path,text);
        return LabHostMemory.parse(path,identity);
    }
    @Test void numericSummaryRequiresAnEntireOwnedSampleSequenceAndMatchingFooter() throws Exception {
        var parsed=parse(header()+row(1,1024)+row(2,4096)+"END 2\n");
        assertTrue(parsed.complete());assertEquals(4096,parsed.peak());assertEquals(2,parsed.samples());assertFalse(parsed.overflow());
        assertEquals(1700000000323L,parsed.firstEpochMs());assertEquals(1700000000523L,parsed.lastEpochMs());
        assertEquals(200,parsed.maxGapMs());
        assertFalse(parse(header()+row(1,1024)+"END 2\n").complete());
        assertFalse(parse(header()+"END 0\n").complete());
        assertFalse(parse(header()+row(1,1024)+"END 1\n"+row(2,9999)).complete());
    }
    @Test void wrongIdentityMalformedNumbersMissingFooterAndTruncatedRowsCannotQualify() throws Exception {
        for(String text:List.of("",header()+row(1,100),header()+row(1,100)+"END 1",
                header()+row(1,100).replace("123 1700000000123","124 1700000000123")+"END 1\n",
                header()+row(1,100).replace("1700000000123","1700000000124")+"END 1\n",
                header()+row(2,100)+"END 1\n",header()+row(1,-1)+"END 1\n",
                header()+"S 1 123 1700000000123 1700000000323 999999999999999999999999\nEND 1\n",
                header()+row(1,100)+row(2,200).replace("1700000000523","1700000000223")+"END 2\n",
                header()+row(1,100)+row(2,200).replace("1700000000523","1700000005323")+"END 2\n",
                header().replace("200","201")+row(1,100)+"END 1\n"))assertFalse(parse(text).complete());
    }
    @Test void overflowAndOversizedInputRemainBoundedAndNeverComplete() throws Exception {
        var overflow=parse(header()+row(1,500)+"OVERFLOW 1\n");
        assertTrue(overflow.overflow());assertFalse(overflow.complete());assertEquals(500,overflow.peak());
        var huge=parse("x".repeat(LabHostMemory.MAX_BYTES+1));assertTrue(huge.overflow());assertFalse(huge.complete());
        assertFalse(parse(header()+"x".repeat(200)+"\n").complete());
    }
    @Test void actualSamplingGapAllowsPracticalJitterButRejectsMissingCoverage() throws Exception {
        var boundary=parse(header()+row(1,100)+row(2,200).replace("1700000000523","1700000002323")+"END 2\n");
        assertTrue(boundary.complete());assertEquals(2000,boundary.maxGapMs());
        var missed=parse(header()+row(1,100)+row(2,200).replace("1700000000523","1700000002324")+"END 2\n");
        assertFalse(missed.complete());assertEquals(2001,missed.maxGapMs());
        assertFalse(parse(header()+row(1,100).replace("1700000000323","-1")+"END 1\n").complete());
    }
    @Test void samplingGapRetainsLaterPeaksAndTimesWithoutQualifyingTheRun() throws Exception {
        var parsed=parse(header()+row(1,100)
                +row(2,200).replace("1700000000523","1700000005323")
                +row(3,9000).replace("1700000000723","1700000005523")+"END 3\n");
        assertFalse(parsed.complete());assertFalse(parsed.overflow());assertEquals(3,parsed.samples());
        assertEquals(9000,parsed.peak());assertEquals(1700000000323L,parsed.firstEpochMs());
        assertEquals(1700000005523L,parsed.lastEpochMs());assertEquals(5000,parsed.maxGapMs());
    }
    @Test void linuxRssParserAcceptsOnlyOneBoundedNumericVmRssInKilobytes() {
        assertEquals(42L*1024,LabHostMemory.linuxRss("Name:\tjava\nVmRSS:\t42 kB\nThreads:\t8\n"));
        for(String invalid:List.of("", "VmRSS: 1 MB\n", "VmRSS: -1 kB\n", "VmRSS: 0 kB\n",
                "VmRSS: 1 kB\nVmRSS: 2 kB\n", "VmRSS: 999999999999999999999 kB\n"))
            assertThrows(IllegalArgumentException.class,()->LabHostMemory.linuxRss(invalid));
    }
    @Test void normalCloseStopsTheSamplerAndPublishesOnlyTheFixedNumericFields() throws Exception {
        var sampled=new CountDownLatch(1);
        var memory=LabHostMemory.startSampler(identity,directory,()->new LabHostMemory.Measurement(identity,9000),
                ()->{sampled.countDown();Thread.sleep(20);},20);
        assertTrue(sampled.await(2,TimeUnit.SECONDS));assertFalse(memory.summary().get("complete").getAsBoolean());
        memory.close();memory.close();var summary=memory.summary();
        assertTrue(summary.get("complete").getAsBoolean());assertEquals(9000,summary.get("peakRssBytes").getAsLong());
        assertEquals(Set.of("version","pid","startedEpochMs","intervalMs","peakRssBytes","samples","overflow","complete","firstSampleEpochMs","lastSampleEpochMs","maxSampleGapMs"),summary.keySet());
        assertTrue(memory.stopped());
        assertTrue(memory.awaitFinished(Duration.ofSeconds(1)));
    }
    @Test void changedIdentityAndPrivateSamplerErrorsFailClosedWithoutExceptionDetails() throws Exception {
        var changed=LabHostMemory.startSampler(identity,directory,
                ()->new LabHostMemory.Measurement(new LabHostMemory.Identity(identity.pid(),identity.startedEpochMs()+1),100),()->{},20);
        assertTrue(changed.awaitFinished(Duration.ofSeconds(2)));changed.close();assertFalse(changed.summary().get("complete").getAsBoolean());
        Path other=Files.createDirectory(directory.resolve("other"));
        var broken=LabHostMemory.startSampler(identity,other,()->{throw new IOException("PRIVATE_SENTINEL");},()->{},20);
        assertTrue(broken.awaitFinished(Duration.ofSeconds(2)));broken.close();
        assertFalse(broken.summary().get("complete").getAsBoolean());
        assertFalse(Files.readString(other.resolve(LabHostMemory.SAMPLES)).contains("PRIVATE_SENTINEL"));
    }
    @Test void sampleLimitStopsInsteadOfSilentlyDroppingMeasurements() throws Exception {
        var memory=LabHostMemory.startSampler(identity,directory,()->new LabHostMemory.Measurement(identity,50),()->{},2);
        assertTrue(memory.awaitFinished(Duration.ofSeconds(2)));memory.close();var summary=memory.summary();
        assertEquals(2,summary.get("samples").getAsInt());assertTrue(summary.get("overflow").getAsBoolean());
        assertFalse(summary.get("complete").getAsBoolean());assertTrue(Files.size(directory.resolve(LabHostMemory.SAMPLES))<=LabHostMemory.MAX_BYTES);
    }
    @Test void interruptedCloseStillStopsItsWorkerAndPreservesCancellation() throws Exception {
        var sampled=new CountDownLatch(1);var memory=LabHostMemory.startSampler(identity,directory,
                ()->new LabHostMemory.Measurement(identity,50),()->{sampled.countDown();Thread.sleep(20);},20);
        assertTrue(sampled.await(2,TimeUnit.SECONDS));Thread.currentThread().interrupt();
        try {memory.close();assertTrue(Thread.currentThread().isInterrupted());assertFalse(memory.summary().get("complete").getAsBoolean());}
        finally {Thread.interrupted();}
        assertTrue(memory.awaitFinished(Duration.ofSeconds(1)));
    }
    @Test void anUninterruptibleSamplerIsReportedAsUnstoppedWithoutWaitingForever() throws Exception {
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
        var memory=LabHostMemory.startSampler(identity,directory,()->{
            entered.countDown();boolean done=false;while(!done)try{release.await();done=true;}catch(InterruptedException ignored){}
            return new LabHostMemory.Measurement(identity,100);
        },()->{},20);
        assertTrue(entered.await(2,TimeUnit.SECONDS));
        try {assertTimeoutPreemptively(Duration.ofSeconds(4),memory::close);assertFalse(memory.stopped());assertFalse(memory.summary().get("complete").getAsBoolean());}
        finally {release.countDown();}
        assertTrue(memory.awaitFinished(Duration.ofSeconds(2)));
    }
    @Test void windowsObserverIsOneHiddenProcessAndOnlyItsHandleIsStopped() throws Exception {
        var process=new FakeProcess(false);var commands=new ArrayList<List<String>>();
        var memory=LabHostMemory.startWindows(identity,directory,args->{commands.add(args);
            Files.writeString(directory.resolve(LabHostMemory.SAMPLES),header()+row(1,2048)+"END 1\n");return process;});
        memory.close();assertEquals(1,commands.size());assertTrue(commands.getFirst().contains("Hidden"));
        assertEquals(1,process.forcedStops);assertFalse(memory.summary().get("complete").getAsBoolean());assertTrue(memory.stopped());
    }
    @Test void cleanWindowsObserverAndMissingSamplesAreDistinguished() throws Exception {
        var process=new FakeProcess(true);var memory=LabHostMemory.startWindows(identity,directory,args->{
            Files.writeString(directory.resolve(LabHostMemory.SAMPLES),header()+row(1,2048)+"END 1\n");return process;});
        memory.close();assertTrue(memory.summary().get("complete").getAsBoolean());assertEquals(0,process.forcedStops);
        Path other=Files.createDirectory(directory.resolve("other"));var empty=LabHostMemory.startWindows(identity,other,args->new FakeProcess(true));
        empty.close();assertFalse(empty.summary().get("complete").getAsBoolean());
    }
    @Test void anObserverThatExitedBeforeTheStopRequestCannotClaimCompleteEvidence() throws Exception {
        var process=new FakeProcess(true);var memory=LabHostMemory.startWindows(identity,directory,args->{
            Files.writeString(directory.resolve(LabHostMemory.SAMPLES),header()+row(1,2048)+"END 1\n");return process;});
        process.alive=false;memory.close();assertTrue(memory.stopped());assertFalse(memory.summary().get("complete").getAsBoolean());
    }
    @Test void existingPrivateFilesAndUnownedOrInvalidIdentitiesAreRejected() throws Exception {
        Files.writeString(directory.resolve(LabHostMemory.SAMPLES),"existing");
        assertThrows(IOException.class,()->LabHostMemory.startSampler(identity,directory,()->new LabHostMemory.Measurement(identity,1),()->{},20));
        assertThrows(IllegalArgumentException.class,()->new LabHostMemory.Identity(0,1));
        assertThrows(IllegalArgumentException.class,()->new LabHostMemory.Identity(1,0));
    }
    private static final class FakeProcess extends Process {
        final boolean exitsOnStop;boolean alive=true;int forcedStops;
        FakeProcess(boolean exitsOnStop){this.exitsOnStop=exitsOnStop;}
        public OutputStream getOutputStream(){return OutputStream.nullOutputStream();}
        public InputStream getInputStream(){return InputStream.nullInputStream();}
        public InputStream getErrorStream(){return InputStream.nullInputStream();}
        public int waitFor(){alive=false;return 0;}
        public boolean waitFor(long time,TimeUnit unit){if(exitsOnStop)alive=false;return !alive;}
        public int exitValue(){if(alive)throw new IllegalThreadStateException();return 0;}
        public void destroy(){alive=false;}
        public Process destroyForcibly(){forcedStops++;alive=false;return this;}
        public boolean isAlive(){return alive;}
    }
}

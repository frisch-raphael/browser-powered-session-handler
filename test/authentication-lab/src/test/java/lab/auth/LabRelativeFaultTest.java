package lab.auth;

import java.net.http.*;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static lab.auth.LabLifecycleTest.control;
import static org.junit.jupiter.api.Assertions.*;

class LabRelativeFaultTest {
    @TempDir Path directory;
    private LabRun start() throws Exception {
        return LabRun.start(new LabRun.RunSpec(UUID.randomUUID(),List.of("browser"),ScenarioCatalog.load(),directory,List.of(),5_000));
    }
    private static LabRun.FaultSpec fault(int occurrence,String kind,String checkpoint) {
        return new LabRun.FaultSpec(LabRun.Phase.PROTECTED,occurrence,kind,null,kind.equals("HTTP_ERROR")?503:null,checkpoint);
    }
    @Test void twoRelativeHoldsApplyAfterFortyRealProtectedRequests() throws Exception {
        try(var run=start();var lease=run.prepareCase("BROW.basic.json");var client=ControlledApplication.localClientBuilder().build()) {
            var request=HttpRequest.newBuilder(lease.endpoint("protected/b")).timeout(Duration.ofSeconds(3)).GET().build();
            for(int i=0;i<40;i++)assertEquals(401,client.send(request,HttpResponse.BodyHandlers.discarding()).statusCode());
            lease.armRelativeFault(fault(1,"HOLD","first"));lease.armRelativeFault(fault(2,"HOLD","second"));
            var first=client.sendAsync(request,HttpResponse.BodyHandlers.discarding());var second=client.sendAsync(request,HttpResponse.BodyHandlers.discarding());
            try {
                lease.awaitCheckpoint("first",Duration.ofSeconds(2));lease.awaitCheckpoint("second",Duration.ofSeconds(2));
                assertFalse(first.isDone());assertFalse(second.isDone());lease.release("first");lease.release("second");
                assertEquals(401,first.get(2,TimeUnit.SECONDS).statusCode());assertEquals(401,second.get(2,TimeUnit.SECONDS).statusCode());
                assertEquals(42,lease.occurrences.get(LabRun.Phase.PROTECTED));
                assertTrue(lease.hit(LabRun.Phase.PROTECTED).isEmpty());
            } finally {lease.release("first");lease.release("second");}
        }
    }
    @Test void absoluteAndRelativeSchedulingShareDuplicateDetectionAndReturnOriginalSpecifications() throws Exception {
        try(var run=start();var lease=run.prepareCase("BROW.basic.json")) {
            var absolute=fault(2,"HTTP_ERROR",null);lease.armFault(absolute);
            assertTrue(lease.hit(LabRun.Phase.PROTECTED).isEmpty());
            assertEquals(409,assertThrows(LabRun.ControlException.class,()->lease.armRelativeFault(fault(1,"HTTP_ERROR",null))).status());
            assertSame(absolute,lease.hit(LabRun.Phase.PROTECTED).getFirst());
            var relative=fault(1,"HTTP_ERROR",null);lease.armRelativeFault(relative);
            assertEquals(409,assertThrows(LabRun.ControlException.class,()->lease.armRelativeFault(relative)).status());
            assertSame(relative,lease.hit(LabRun.Phase.PROTECTED).getFirst());
            // A new 'next hit' is distinct after the phase has advanced, even with the same relative specification.
            lease.armRelativeFault(relative);assertSame(relative,lease.hit(LabRun.Phase.PROTECTED).getFirst());
        }
    }
    @Test void relativeSchedulingStopsAtTenThousandAndNeverCreatesAnUnreachableGate() throws Exception {
        try(var run=start();var lease=run.prepareCase("BROW.basic.json")) {
            for(int i=0;i<9968;i++)assertTrue(lease.hit(LabRun.Phase.PROTECTED).isEmpty());
            var last=fault(32,"HTTP_ERROR",null);lease.armRelativeFault(last);
            for(int i=0;i<31;i++)assertTrue(lease.hit(LabRun.Phase.PROTECTED).isEmpty());
            assertSame(last,lease.hit(LabRun.Phase.PROTECTED).getFirst());
            assertEquals(400,assertThrows(LabRun.ControlException.class,()->lease.armRelativeFault(fault(1,"HOLD","unreachable"))).status());
            assertFalse(lease.hasFaultCheckpoint("unreachable"));
        }
    }
    @Test void differentFaultKindsMayShareOneAbsoluteTarget() throws Exception {
        try(var run=start();var lease=run.prepareCase("BROW.basic.json");var executor=Executors.newVirtualThreadPerTaskExecutor()) {
            var hold=fault(1,"HOLD","combined");var rejection=fault(1,"HTTP_ERROR",null);
            lease.armFault(hold);lease.armRelativeFault(rejection);
            var pending=executor.submit(()->lease.hit(LabRun.Phase.PROTECTED));
            lease.awaitCheckpoint("combined",Duration.ofSeconds(2));lease.release("combined");
            assertEquals(List.of(hold,rejection),pending.get(2,TimeUnit.SECONDS));
        }
    }
    @Test void catalogAndControlKeepTheirAbsoluteOccurrenceLimitAndRejectRelativeFlags() throws Exception {
        for(int invalid:List.of(0,33))assertThrows(ScenarioCatalog.CatalogException.class,()->fault(invalid,"HTTP_ERROR",null));
        try(var run=start();var lease=run.prepareCase("BROW.basic.json");var client=ControlledApplication.localClientBuilder().build()) {
            var invalid=new LinkedHashMap<String,Object>();invalid.put("phase","PROTECTED");invalid.put("occurrence",33);
            invalid.put("kind","HTTP_ERROR");invalid.put("status",503);invalid.put("role",null);invalid.put("checkpoint",null);
            assertEquals(400,control(client,run,"/cases/"+lease.id()+"/faults","POST",Map.of("generation",lease.generation(),"fault",invalid)).statusCode());
            invalid.put("occurrence",1);invalid.put("relative",true);
            assertEquals(400,control(client,run,"/cases/"+lease.id()+"/faults","POST",Map.of("generation",lease.generation(),"fault",invalid)).statusCode());
            assertTrue(lease.hit(LabRun.Phase.PROTECTED).isEmpty());
        }
    }
    @Test void checkpointOwnershipAndReleasedGateBehaviorRemainSharedWithAbsoluteFaults() throws Exception {
        try(var run=start();var lease=run.prepareCase("BROW.basic.json");var executor=Executors.newVirtualThreadPerTaskExecutor()) {
            var first=fault(1,"HOLD","shared");lease.armFault(first);
            assertTrue(lease.hasFaultCheckpoint("shared"));assertFalse(lease.hasFaultCheckpoint("other"));
            assertEquals(409,assertThrows(LabRun.ControlException.class,()->lease.armRelativeFault(first)).status());
            var pending=executor.submit(()->lease.hit(LabRun.Phase.PROTECTED));
            lease.awaitCheckpoint("shared",Duration.ofSeconds(2));lease.release("shared");
            assertSame(first,pending.get(2,TimeUnit.SECONDS).getFirst());
            lease.armRelativeFault(first);
            assertTimeoutPreemptively(Duration.ofSeconds(1),()->assertSame(first,lease.hit(LabRun.Phase.PROTECTED).getFirst()));
        }
    }
    @Test void retiringTheLeaseReleasesRelativeHoldsAndRejectsLaterScheduling() throws Exception {
        try(var run=start();var executor=Executors.newVirtualThreadPerTaskExecutor()) {
            var lease=run.prepareCase("BROW.basic.json");lease.armRelativeFault(fault(1,"HOLD","retire"));
            var pending=executor.submit(()->lease.hit(LabRun.Phase.PROTECTED));
            lease.awaitCheckpoint("retire",Duration.ofSeconds(2));lease.close();
            var ended=assertThrows(ExecutionException.class,()->pending.get(2,TimeUnit.SECONDS));
            assertInstanceOf(LabRun.ControlException.class,ended.getCause());assertEquals(410,((LabRun.ControlException)ended.getCause()).status());
            assertEquals(410,assertThrows(LabRun.ControlException.class,()->lease.armRelativeFault(fault(1,"HTTP_ERROR",null))).status());
        }
    }
}

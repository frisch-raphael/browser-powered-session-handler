package bpsh.browser.runtime;

import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static bpsh.browser.runtime.WindowsBrowserJob.Operation.*;
import static org.junit.jupiter.api.Assertions.*;

/** Uses a fake native boundary; these attribution and ownership refusals run on every platform. */
class WindowsBrowserJobDiagnosticsTest {
    private static final Pointer JOB=Pointer.createConstant(100),MEMBER=Pointer.createConstant(200);
    private static long deadline(){return System.nanoTime()+TimeUnit.SECONDS.toNanos(2);}
    private static WindowsBrowserJob.Failure failure(WindowsBrowserJob.Operation operation,Executable action) {
        var result=assertThrows(WindowsBrowserJob.Failure.class,action);assertEquals(operation,result.operation);
        assertNull(result.getCause());assertEquals(0,result.getSuppressed().length);return result;
    }
    private static WindowsBrowserJob job(FakeKernel kernel){return new WindowsBrowserJob(kernel,JOB);}

    @Test void enumerationFailureKeepsItsOwnCodeAndStillReleasesTheJob() {
        var kernel=new FakeKernel();kernel.fail=ENUMERATE_MEMBERS;var owned=job(kernel);
        assertEquals(5L,failure(ENUMERATE_MEMBERS,()->owned.close(deadline())).nativeCode);
        assertEquals(Set.of(JOB),kernel.closed);assertEquals(0,kernel.terminateCalls);
    }

    @Test void malformedMemberCountsHaveAFixedBoundFailureWithoutNativeProse() {
        for(int count:new int[]{-1,16384}) {
            var kernel=new FakeKernel();kernel.memberCount=count;var owned=job(kernel);
            var result=failure(MEMBER_BOUND,()->owned.close(deadline()));
            assertNull(result.nativeCode);assertNull(result.waitResult);assertFalse(result.deadline);
            assertEquals(Set.of(JOB),kernel.closed);
        }
    }

    @Test void accessDeniedSnapshotsTheFirstNativeErrorBeforeAnyLaterReadOrRelease() {
        var kernel=new FakeKernel();kernel.fail=OPEN_MEMBER;kernel.errors.addAll(List.of(5,6));var owned=job(kernel);
        assertEquals(5L,failure(OPEN_MEMBER,()->owned.close(deadline())).nativeCode);
        assertEquals(1,kernel.errorReads);assertEquals(List.of(0x00101000),kernel.accesses);
        assertEquals(Set.of(JOB),kernel.closed);
    }

    @Test void anAlreadyExitedMemberRemainsAnIgnored87Race() throws Exception {
        var kernel=new FakeKernel();kernel.fail=OPEN_MEMBER;kernel.errors.addAll(List.of(87,5));
        job(kernel).close(deadline());assertEquals(1,kernel.errorReads);
        assertEquals(1,kernel.terminateCalls);assertTrue(kernel.waited.isEmpty());assertEquals(Set.of(JOB),kernel.closed);
    }

    @Test void failedMembershipVerificationReleasesItsHandleAndRetainsVerificationCode() {
        var kernel=new FakeKernel();kernel.fail=VERIFY_MEMBER;var owned=job(kernel);
        assertEquals(5L,failure(VERIFY_MEMBER,()->owned.close(deadline())).nativeCode);
        assertEquals(Set.of(JOB,MEMBER),kernel.closed);assertTrue(kernel.waited.isEmpty());
    }

    @Test void reusedPidOutsideTheJobIsNeverRetainedOrWaitedOn() throws Exception {
        var kernel=new FakeKernel();kernel.included=false;job(kernel).close(deadline());
        assertEquals(Set.of(JOB,MEMBER),kernel.closed);assertTrue(kernel.waited.isEmpty());
        assertEquals(1,kernel.terminateCalls);assertEquals(List.of(0x00101000),kernel.accesses);
    }

    @Test void terminationFailureRemainsFailureWhileEveryOwnedHandleIsReleased() throws Exception {
        var kernel=new FakeKernel();kernel.fail=TERMINATE;var owned=job(kernel);
        assertEquals(5L,failure(TERMINATE,()->owned.close(deadline())).nativeCode);
        assertEquals(Set.of(JOB,MEMBER),kernel.closed);assertTrue(kernel.waited.isEmpty());
        owned.close(deadline());assertEquals(1,kernel.terminateCalls);
    }

    @Test void waitTimeoutIsNotMisreportedAsAStaleGetLastError() {
        var kernel=new FakeKernel();kernel.waitResult=258;var owned=job(kernel);
        var result=failure(WAIT_MEMBER,()->owned.close(deadline()));
        assertEquals(258L,result.waitResult);assertNull(result.nativeCode);assertTrue(result.deadline);
        assertEquals(0,kernel.errorReads);assertEquals(List.of(MEMBER),kernel.waited);
    }

    @Test void waitFailedPreservesUnsignedResultAndItsActualNativeError() {
        var kernel=new FakeKernel();kernel.waitResult=-1;kernel.errors.add(6);var owned=job(kernel);
        var result=failure(WAIT_MEMBER,()->owned.close(deadline()));
        assertEquals(0xffff_ffffL,result.waitResult);assertEquals(6L,result.nativeCode);assertFalse(result.deadline);
        assertEquals(1,kernel.errorReads);assertEquals(Set.of(JOB,MEMBER),kernel.closed);
    }

    @Test void accountingQueryFailureAndDeadlineAreDistinct() {
        var unavailable=new FakeKernel();unavailable.fail=OBSERVE_TERMINATION;var first=job(unavailable);
        var nativeFailure=failure(OBSERVE_TERMINATION,()->first.close(deadline()));
        assertEquals(5L,nativeFailure.nativeCode);assertFalse(nativeFailure.deadline);
        var active=new FakeKernel();active.active=1;var second=job(active);
        var expired=failure(DRAIN_DEADLINE,()->second.close(System.nanoTime()-1));
        assertTrue(expired.deadline);assertNull(expired.nativeCode);assertNull(expired.waitResult);
    }

    @Test void memberAndJobHandleReleaseFailuresRemainAttributedAndUnsigned() {
        for(var operation:List.of(RELEASE_MEMBER,RELEASE_JOB)) {
            var kernel=new FakeKernel();kernel.fail=operation;kernel.errors.add(-2);var owned=job(kernel);
            assertEquals(0xffff_fffeL,failure(operation,()->owned.close(deadline())).nativeCode);
            assertEquals(Set.of(JOB,MEMBER),kernel.closed);
        }
    }

    @Test void firstObservationAndFirstCloseAreCopiedOnceWithoutAnyVendorThrowableGraph() {
        String privateText="__UNSAFE_VENDOR_TEXT_8F__";var diagnostics=new WindowsBrowserJob.Diagnostics();
        var original=new WindowsBrowserJob.Failure(OPEN_MEMBER,5L,null,false);
        original.initCause(new IllegalStateException(privateText));original.addSuppressed(new IOException(privateText));
        diagnostics.observation(original);diagnostics.observation(new WindowsBrowserJob.Failure(VERIFY_MEMBER,6L,null,false));
        diagnostics.close(new IllegalStateException(privateText));diagnostics.close(new WindowsBrowserJob.Failure(TERMINATE,7L,null,false));
        var target=new IOException("The owned browser processes did not finish closing.");
        diagnostics.suppressOn(target);diagnostics.suppressOn(target);
        assertEquals(2,target.getSuppressed().length);var observation=(WindowsBrowserJob.Failure)target.getSuppressed()[0];
        assertNotSame(original,observation);assertEquals(OPEN_MEMBER,observation.operation);assertEquals(5L,observation.nativeCode);
        var close=(WindowsBrowserJob.Failure)target.getSuppressed()[1];assertEquals(CLOSE_UNATTRIBUTED,close.operation);assertNull(close.nativeCode);
        for(var safe:target.getSuppressed()){assertNull(safe.getCause());assertEquals(0,safe.getSuppressed().length);}
        var text=new StringWriter();target.printStackTrace(new PrintWriter(text));assertFalse(text.toString().contains(privateText));
    }

    @Test void unknownIoObservationIsUnattributedRatherThanParsedOrRetained() {
        var diagnostics=new WindowsBrowserJob.Diagnostics();diagnostics.observation(new IOException("Windows browser containment: OPEN_MEMBER; nativeCode=5; PRIVATE"));
        var target=new IOException("generic");diagnostics.suppressOn(target);
        var safe=(WindowsBrowserJob.Failure)target.getSuppressed()[0];assertEquals(OBSERVATION_UNATTRIBUTED,safe.operation);
        assertNull(safe.nativeCode);assertNull(safe.getCause());assertFalse(safe.getMessage().contains("PRIVATE"));
    }

    @Test void diagnosticNumericFieldsHaveUnsignedDwordBounds() {
        for(long invalid:new long[]{-1,0x1_0000_0000L}) {
            assertThrows(IllegalArgumentException.class,()->new WindowsBrowserJob.Failure(OPEN_MEMBER,invalid,null,false));
            assertThrows(IllegalArgumentException.class,()->new WindowsBrowserJob.Failure(WAIT_MEMBER,null,invalid,false));
        }
        assertDoesNotThrow(()->new WindowsBrowserJob.Failure(WAIT_MEMBER,0xffff_ffffL,0xffff_ffffL,false));
    }

    @Test void successfulCleanupRetainsNoFailureAndKeepsWaitRightsAndOwnedHandles() throws Exception {
        var kernel=new FakeKernel();job(kernel).close(deadline());assertEquals(List.of(0x00101000),kernel.accesses);
        assertEquals(List.of(MEMBER),kernel.waited);assertEquals(Set.of(JOB,MEMBER),kernel.closed);
        var target=new IOException("generic");new WindowsBrowserJob.Diagnostics().suppressOn(target);assertEquals(0,target.getSuppressed().length);
    }

    private static final class FakeKernel implements WindowsBrowserJob.Kernel {
        WindowsBrowserJob.Operation fail;int memberCount=1,waitResult,active,errorReads,terminateCalls;boolean included=true;
        final Deque<Integer> errors=new ArrayDeque<>();final Set<Pointer> closed=new HashSet<>();
        final List<Integer> accesses=new ArrayList<>();final List<Pointer> waited=new ArrayList<>();
        @Override public Pointer CreateJobObjectW(Pointer attributes,Pointer name){return JOB;}
        @Override public boolean SetInformationJobObject(Pointer job,int kind,Pointer information,int bytes){return true;}
        @Override public boolean AssignProcessToJobObject(Pointer job,Pointer process){return true;}
        @Override public boolean TerminateJobObject(Pointer job,int exitCode){assertEquals(JOB,job);terminateCalls++;return fail!=TERMINATE;}
        @Override public boolean QueryInformationJobObject(Pointer job,int kind,Pointer information,int bytes,Pointer returned) {
            assertEquals(JOB,job);
            if(kind==3){if(fail==ENUMERATE_MEMBERS)return false;information.setInt(4,memberCount);if(memberCount==1)information.setLong(8,77);return true;}
            assertEquals(1,kind);if(fail==OBSERVE_TERMINATION)return false;information.setInt(40,active);return true;
        }
        @Override public Pointer OpenProcess(int access,boolean inherit,int pid){assertEquals(77,pid);assertFalse(inherit);accesses.add(access);return fail==OPEN_MEMBER?null:MEMBER;}
        @Override public boolean IsProcessInJob(Pointer process,Pointer job,IntByReference result){assertEquals(MEMBER,process);assertEquals(JOB,job);result.setValue(included?1:0);return fail!=VERIFY_MEMBER;}
        @Override public int WaitForSingleObject(Pointer handle,int milliseconds){assertEquals(MEMBER,handle);assertTrue(milliseconds>=0&&milliseconds<=2000);waited.add(handle);return waitResult;}
        @Override public boolean CloseHandle(Pointer handle){assertTrue(handle.equals(JOB)||handle.equals(MEMBER));closed.add(handle);return !(fail==RELEASE_MEMBER&&handle.equals(MEMBER)||fail==RELEASE_JOB&&handle.equals(JOB));}
        @Override public int GetLastError(){errorReads++;return errors.isEmpty()?5:errors.removeFirst();}
    }
}

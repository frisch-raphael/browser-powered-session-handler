import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Establishes shared-cycle and reservation policy with controlled clocks; no hardware claims. */
class AuthenticationCoordinatorTest {
    /** Owns a registry, a manual runtime and the coordinator under test. */
    static final class Fixture implements AutoCloseable {
        final SecretStore secrets = new SecretStore();
        final JourneyRegistry registry = new JourneyRegistry(secrets);
        final CoordinatorFixtures.ManualRuntime clock = new CoordinatorFixtures.ManualRuntime();
        final List<JourneyDefinition> definitions = List.of(CoordinatorFixtures.journey("employee"), CoordinatorFixtures.journey("admin"));
        final AtomicInteger attempts = new AtomicInteger();
        final List<Boolean> recoveries = new ArrayList<>();
        final List<Long> deadlines = new ArrayList<>();
        final AuthenticationCoordinator coordinator;
        final AtomicReference<AuthenticationFailure> fail = new AtomicReference<>(), blocked = new AtomicReference<>();
        /** @param controls Initial native controls. */
        Fixture(Config.Controls controls) {
            CoordinatorFixtures.load(registry, definitions);
            coordinator = new AuthenticationCoordinator(registry, controls, clock, (entry, recovery, deadline, cancelled) -> {
                attempts.incrementAndGet(); recoveries.add(recovery); deadlines.add(deadline);
                if (fail.get() != null) throw fail.get();
                return new BrowserFlowRunner.Outcome(entry.identity(), "fixture-" + attempts.get(), clock.instant(), clock.nanos());
            }, entry -> blocked.get());
        }
        /** @param index Account index. @return Current resolvable registry generation. */
        JourneyRegistry.Entry entry(int index) { return registry.snapshot().resolve(definitions.get(index).alias()); }
        /** @param index Account index. @return One request-wide ticket for that journey. */
        AuthenticationCoordinator.Ticket acquire(int index) { return coordinator.acquire(List.of(entry(index))); }
        /** Closes only test-owned coordination and session values. */
        @Override public void close() { coordinator.close(); secrets.close(); }
    }

    @Test void manyRequestsShareOneAttemptAndReleaseEveryReservation() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var callers = java.util.stream.IntStream.range(0, 100).mapToObj(i -> f.acquire(0)).toList();
            assertEquals(100, f.coordinator.capacity().waitingRequests()); assertEquals(1, f.clock.workers.size());
            f.clock.runWorker(); assertEquals(1, f.attempts.get());
            var version = callers.getFirst().future().join().get(f.entry(0).identity()).version();
            callers.forEach(c -> assertEquals(version, c.future().join().get(f.entry(0).identity()).version()));
            assertEquals(0, f.coordinator.capacity().waitingRequests()); assertEquals(1, f.clock.timers());
            assertTrue(f.acquire(0).future().isDone()); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    @Test void distinctReferencesReserveAtomicallyAndRepeatedReferencesCountOnce() {
        try (var f = new Fixture(CoordinatorFixtures.limits(null, 1))) {
            var first = f.acquire(1);
            var refused = f.coordinator.acquire(List.of(f.entry(0), f.entry(1), f.entry(0)));
            assertEquals(AuthenticationFailure.Cause.CAPACITY, CoordinatorFixtures.error(refused).reason());
            assertEquals(0, f.coordinator.status(f.entry(0).identity()).waitingRequests()); assertEquals(1, f.clock.workers.size());
            first.close(); assertEquals(0, f.coordinator.capacity().waitingRequests());
            var repeated = f.coordinator.acquire(List.of(f.entry(0), f.entry(0)));
            assertEquals(1, f.coordinator.capacity().waitingRequests()); assertEquals(1, f.coordinator.status(f.entry(0).identity()).waitingRequests()); repeated.close();
        }
    }
    @Test void limitsApplyIndependentlyAndLiveLoweringDoesNotEvictAdmittedOwners() {
        for (boolean global : List.of(true, false)) try (var f = new Fixture(CoordinatorFixtures.limits(null, null))) {
            var a = f.acquire(0); var b = f.acquire(0);
            f.coordinator.updateControls(CoordinatorFixtures.limits(global ? 1 : null, global ? null : 1));
            assertEquals(AuthenticationFailure.Cause.CAPACITY, CoordinatorFixtures.error(f.acquire(0)).reason()); assertFalse(a.future().isDone()); assertFalse(b.future().isDone());
            f.coordinator.updateControls(CoordinatorFixtures.limits(null, null)); var c = f.acquire(0); f.clock.runWorker();
            assertTrue(a.future().isDone() && b.future().isDone() && c.future().isDone()); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    @Test void cacheOnlyRequestsBypassWaitingLimitsButColdJourneysStillCount() {
        try (var f = new Fixture(CoordinatorFixtures.limits(1, 1))) {
            f.acquire(0); f.clock.runWorker(); var waiting = f.acquire(1);
            assertTrue(f.acquire(0).future().isDone()); assertEquals(1, f.coordinator.capacity().waitingRequests());
            assertEquals(AuthenticationFailure.Cause.CAPACITY, CoordinatorFixtures.error(f.coordinator.acquire(List.of(f.entry(0), f.entry(1)))).reason()); waiting.close();
        }
    }
    @Test void oneCallerTimeoutAndCancellationLeaveOtherOwnersAndTheirBudgetsIntact() {
        try (var f = new Fixture(CoordinatorFixtures.controls(null, null, 1000, 10_000, 30_000))) {
            var first = f.acquire(0); f.clock.advance(500); var second = f.acquire(0); f.clock.advance(500);
            assertEquals(AuthenticationFailure.Cause.TIMEOUT, CoordinatorFixtures.error(first).reason()); assertFalse(second.future().isDone());
            var third = f.acquire(0); third.future().cancel(false); assertEquals(1, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); assertTrue(second.future().isDone()); assertEquals(1, f.attempts.get()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            assertEquals(TimeUnit.SECONDS.toNanos(11), f.deadlines.getFirst());
        }
    }
    @ParameterizedTest @EnumSource(value = AuthenticationFailure.Cause.class, names = {"TRANSPORT", "TEMPORARY_SERVICE"})
    void positivelyTemporaryFailuresHaveAtMostThreeTotalAttemptsThenPauseUntilExplicitTest(AuthenticationFailure.Cause cause) {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.fail.set(CoordinatorFixtures.failure(cause)); var caller = f.acquire(0); f.clock.runWorker();
            for (int seconds : List.of(5, 15)) {
                assertEquals(0, f.coordinator.capacity().runningAttempts()); assertEquals(1, f.coordinator.capacity().queuedCycles());
                f.clock.advance(seconds * 1000L - 1); assertTrue(f.clock.workers.isEmpty()); f.clock.advance(1); f.clock.runWorker();
            }
            assertEquals(cause, CoordinatorFixtures.error(caller).reason()); assertEquals(3, f.attempts.get());
            assertTrue(f.recoveries.stream().noneMatch(Boolean::booleanValue)); assertEquals(0, f.coordinator.capacity().waitingRequests());
            f.clock.advance(60_000); assertTrue(f.clock.workers.isEmpty(), "exhausted refresh must not immediately restart itself");
            assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(f.entry(0).identity()).phase());
            assertEquals(cause, CoordinatorFixtures.error(f.acquire(0)).reason()); assertTrue(f.clock.workers.isEmpty());
            f.fail.set(null); var explicit = f.coordinator.test(f.entry(0), false); f.clock.runWorker();
            assertTrue(explicit.future().isDone()); assertEquals(AuthenticationCoordinator.Phase.READY, f.coordinator.status(f.entry(0).identity()).phase());
        }
    }
    @Test void concurrentLossesShareThreeRecoveryAttemptsAndInitialAcquisitionIsCountedSeparately() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.acquire(0); f.clock.runWorker(); var original = f.coordinator.peek(f.entry(0).identity());
            var rule = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
            f.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT));
            var callers = java.util.stream.IntStream.range(0, 80).mapToObj(i -> f.coordinator.recover(List.of(new SessionRecovery.Used(original.identity(), original.version(), rule)))).toList();
            assertEquals(1, f.clock.workers.size()); f.clock.runWorker(); f.clock.advance(5000); f.clock.runWorker();
            f.fail.set(null); f.clock.advance(15_000); f.clock.runWorker();
            assertEquals(4, f.attempts.get(), "one initial acquisition and three recovery attempts");
            long version = f.coordinator.peek(original.identity()).version();
            callers.forEach(c -> assertEquals(version, c.future().join().get(original.identity()).version()));
            var status = f.coordinator.status(original.identity()); assertEquals(3, status.attempts()); assertFalse(status.acceptedUse());
            assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }

    @Test void rejectedReplacementPauseSurvivesSaveAndTimersWhileAnUnrelatedJourneyStillWorks() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.acquire(0); f.clock.runWorker(); var original = f.coordinator.peek(f.entry(0).identity());
            var rule = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
            f.coordinator.recover(List.of(new SessionRecovery.Used(original.identity(), original.version(), rule))); f.clock.runWorker();
            var replacement = f.coordinator.peek(original.identity());
            var replay = f.coordinator.provenance(new SessionRecovery.Used(replacement.identity(), replacement.version(), rule), true);
            assertTrue(replay.validationEpisode() > 0); f.coordinator.rejectedReplacement(replay, 401);
            var status = f.coordinator.status(original.identity()); assertEquals(AuthenticationCoordinator.Phase.PAUSED, status.phase());
            assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, status.failure().reason()); assertEquals(401, status.failure().httpStatus());
            f.clock.advance(3_600_000); assertTrue(f.clock.workers.isEmpty()); assertNull(f.coordinator.peek(original.identity()));
            assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, CoordinatorFixtures.error(f.acquire(0)).reason());
            var previous = f.definitions.getFirst(); var changed = new JourneyDefinition(previous.id(), "Renamed", "renamed-employee", previous.authenticationUrl(), false,
                    previous.steps(), previous.browser(), previous.extraction(), previous.injection(), previous.cache(), previous.mtls());
            CoordinatorFixtures.load(f.registry, List.of(changed, f.definitions.get(1))); f.coordinator.configurationChanged();
            var current = f.registry.snapshot().resolve("renamed-employee");
            assertNotEquals(original.identity(), current.identity()); assertEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(current.identity()).phase());
            assertEquals(AuthenticationFailure.Cause.AUTH_REJECTED, CoordinatorFixtures.error(f.coordinator.acquire(List.of(current))).reason());
            f.acquire(1); f.clock.runWorker(); assertNotNull(f.coordinator.peek(f.entry(1).identity()));
            var explicit = f.coordinator.test(current, false); f.clock.runWorker(); assertTrue(explicit.future().isDone());
            assertEquals(AuthenticationCoordinator.Phase.READY, f.coordinator.status(current.identity()).phase());
            assertFalse(f.coordinator.status(current.identity()).acceptedUse());
        }
    }

    @Test void acceptedReplacementRearmsOnlyLaterUseAndLateRejectedReplayCannotRetireANewerEpisode() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.acquire(0); f.clock.runWorker(); var original = f.coordinator.peek(f.entry(0).identity());
            var rule = new JourneyDefinition.Recovery(true, JourneyDefinition.RecoveryMode.STATUS_CODE, 401, null);
            f.coordinator.recover(List.of(new SessionRecovery.Used(original.identity(), original.version(), rule))); f.clock.runWorker();
            var replacement = f.coordinator.peek(original.identity());
            var validating = f.coordinator.provenance(new SessionRecovery.Used(replacement.identity(), replacement.version(), rule), true);
            assertFalse(f.coordinator.status(original.identity()).acceptedUse()); f.coordinator.accepted(validating, 200);
            assertTrue(f.coordinator.status(original.identity()).acceptedUse());
            var later = f.coordinator.provenance(new SessionRecovery.Used(replacement.identity(), replacement.version(), rule), false);
            assertEquals(0, later.validationEpisode());
            var next = f.coordinator.recover(List.of(later)); f.coordinator.rejectedReplacement(validating, 401);
            assertNotEquals(AuthenticationCoordinator.Phase.PAUSED, f.coordinator.status(original.identity()).phase());
            f.clock.runWorker(); assertTrue(next.future().isDone());
        }
    }

    @Test void cancelledWorkerMustCloseBeforeAnExplicitReplacementAttemptCanStart() throws Exception {
        try (var secrets = new SecretStore()) {
            var registry = new JourneyRegistry(secrets); var journey = CoordinatorFixtures.journey("serial"); CoordinatorFixtures.load(registry, List.of(journey));
            var clock = new CoordinatorFixtures.ManualRuntime(); var entered = new java.util.concurrent.CountDownLatch(1); var release = new java.util.concurrent.CountDownLatch(1);
            var attempts = new AtomicInteger(); var active = new AtomicInteger();
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, (entry, recovery, deadline, cancelled) -> {
                assertEquals(1, active.incrementAndGet());
                try { if (attempts.incrementAndGet() == 1) { entered.countDown(); try { release.await(5, TimeUnit.SECONDS); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw CoordinatorFixtures.failure(AuthenticationFailure.Cause.CANCELLED); } }
                    return new BrowserFlowRunner.Outcome(entry.identity(), "serial-token", clock.instant(), clock.nanos());
                } finally { active.decrementAndGet(); }
            }, entry -> null)) {
                var entry = registry.snapshot().resolve("serial"); coordinator.acquire(List.of(entry));
                Thread worker = new Thread(clock.workers.remove()); worker.start(); assertTrue(entered.await(5, TimeUnit.SECONDS));
                assertTrue(coordinator.cancelAuthentication(entry.identity())); var explicit = coordinator.test(entry, false);
                assertTrue(clock.workers.isEmpty(), "a cancelled browser still owns this journey's worker slot");
                release.countDown(); worker.join(5000); assertFalse(worker.isAlive()); clock.runWorker();
                assertTrue(explicit.future().isDone()); assertEquals(2, attempts.get()); assertEquals(0, active.get());
            } finally { release.countDown(); }
        }
    }

    @ParameterizedTest @EnumSource(value = AuthenticationFailure.Cause.class, names = {"STEP_TIMEOUT", "EXTRACTION", "TOKEN_EXPIRED", "AUTH_REJECTED", "UNKNOWN", "TRUST", "PIN_REJECTED", "PIN_INDETERMINATE", "PIN_IN_PROGRESS", "MISSING_SECRET"})
    void terminalObservationsNeverReceiveBlindRetries(AuthenticationFailure.Cause cause) {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.fail.set(CoordinatorFixtures.failure(cause)); var caller = f.acquire(0); f.clock.runWorker();
            assertEquals(cause, CoordinatorFixtures.error(caller).reason()); f.clock.advance(120_000); assertTrue(f.clock.workers.isEmpty());
            assertEquals(cause, CoordinatorFixtures.error(f.acquire(0)).reason()); assertEquals(1, f.attempts.get());
        }
    }
    @Test void sharedPinSuppressionOverridesTemporaryTransportWithoutAutomaticResubmission() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT)); f.blocked.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.PIN_INDETERMINATE).atInput(AuthenticationFailure.Input.SECURITY_DEVICE));
            var caller = f.acquire(0); f.clock.runWorker(); assertEquals(AuthenticationFailure.Cause.PIN_INDETERMINATE, CoordinatorFixtures.error(caller).reason());
            f.clock.advance(30_000); assertEquals(1, f.attempts.get());
        }
    }
    @Test void retryAfterCannotExtendTheCycleAndAttemptBudgetStartsOnActualAdmission() {
        try (var f = new Fixture(CoordinatorFixtures.controls(null, null, 30_000, 10_000, 30_000))) {
            f.fail.set(new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.TEMPORARY_SERVICE,
                    "HTTP 503.", "Retry later.", 503, f.clock.instant().plusSeconds(31)));
            var caller = f.acquire(0); f.clock.runWorker(); assertEquals(AuthenticationFailure.Cause.TEMPORARY_SERVICE, CoordinatorFixtures.error(caller).reason()); assertTrue(f.clock.workers.isEmpty());
            assertEquals(TimeUnit.SECONDS.toNanos(11), f.deadlines.getFirst());
        }
    }
    @Test void finiteCycleQueueRejectsNewAtomicRequestsWithoutAttachingOrStartingAnything() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var definitions = java.util.stream.IntStream.range(0, 35).mapToObj(i -> CoordinatorFixtures.journey("journey" + i)).toList();
            CoordinatorFixtures.load(f.registry, definitions); var callers = new ArrayList<AuthenticationCoordinator.Ticket>();
            for (int i = 0; i < 34; i++) callers.add(f.coordinator.acquire(List.of(f.registry.snapshot().resolve("journey" + i))));
            assertEquals(new AuthenticationCoordinator.Capacity(34, 2, 32), f.coordinator.capacity());
            var denied = f.coordinator.acquire(List.of(f.registry.snapshot().resolve("journey34"), f.registry.snapshot().resolve("journey0")));
            assertEquals(AuthenticationFailure.Cause.CAPACITY, CoordinatorFixtures.error(denied).reason()); assertEquals(34, f.coordinator.capacity().waitingRequests());
            f.coordinator.close(); callers.forEach(c -> assertEquals(AuthenticationFailure.Cause.CLOSED, CoordinatorFixtures.error(c).reason()));
            assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    @Test void operatorCancelSupersedesRunningWorkReleasesAllOwnersAndKeepsOtherJourneyAlive() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var a = f.acquire(0); var test = f.coordinator.test(f.entry(0), false); var unrelated = f.acquire(1);
            f.coordinator.cancelAuthentication(f.entry(0).identity());
            assertEquals(AuthenticationFailure.Cause.CANCELLED, CoordinatorFixtures.error(a).reason()); assertEquals(AuthenticationFailure.Cause.CANCELLED, CoordinatorFixtures.error(test).reason());
            assertFalse(unrelated.future().isDone()); assertEquals(AuthenticationFailure.Cause.CANCELLED, CoordinatorFixtures.error(f.acquire(0)).reason());
            f.clock.runWorker(); assertNull(f.coordinator.peek(f.entry(0).identity())); f.clock.runWorker(); assertTrue(unrelated.future().isDone());
            f.fail.set(null); var explicit = f.coordinator.test(f.entry(0), true); f.clock.runWorker(); assertTrue(explicit.future().isDone()); assertTrue(f.recoveries.getLast());
        }
    }
    @Test void cancelRetainsUsableTokenDefersRefreshAndSaveAndTestCanBypassCooldownWithoutClearingPinState() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var first = f.acquire(0); f.clock.runWorker(); TokenSnapshot old = first.future().join().get(f.entry(0).identity());
            var test = f.coordinator.test(f.entry(0), false); f.coordinator.cancelAuthentication(f.entry(0).identity());
            assertSame(old, f.coordinator.peek(f.entry(0).identity())); assertEquals(AuthenticationFailure.Cause.CANCELLED, CoordinatorFixtures.error(test).reason());
            f.clock.runWorker(); f.clock.advance(59_999); assertTrue(f.clock.workers.isEmpty());
            var explicit = f.coordinator.test(f.entry(0), false); f.clock.runWorker(); assertTrue(explicit.future().isDone()); assertFalse(f.recoveries.getLast());
        }
    }
    @Test void backoffAndQueuedCancelRemoveTheirTimersAndRejectLatePublication() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT)); var request = f.acquire(0); f.clock.runWorker();
            f.coordinator.cancelAuthentication(f.entry(0).identity()); assertEquals(AuthenticationFailure.Cause.CANCELLED, CoordinatorFixtures.error(request).reason());
            f.clock.advance(59_999); assertTrue(f.clock.workers.isEmpty()); assertEquals(0, f.coordinator.capacity().queuedCycles());
        }
    }
    @Test void versionInvalidationDoesNotInvalidateAReplacementOrCancelHealthyRefresh() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.acquire(0); f.clock.runWorker(); var old = f.coordinator.peek(f.entry(0).identity()); var refresh = f.coordinator.test(f.entry(0), false);
            assertTrue(f.coordinator.invalidateVersion(old.identity(), old.version())); assertFalse(refresh.future().isDone());
            f.clock.runWorker(); var current = f.coordinator.peek(old.identity()); assertNotNull(current); assertNotEquals(old.version(), current.version());
            assertFalse(f.coordinator.invalidateVersion(old.identity(), old.version())); assertSame(current, f.coordinator.peek(old.identity()));
        }
    }
    @Test void configurationReplacementAndUnloadReleaseWaitersAndRejectRunningLateResults() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var old = f.entry(0).identity(); var caller = f.acquire(0);
            f.registry.disableScope(JourneyDefinition.Scope.PROJECT); f.coordinator.configurationChanged();
            assertEquals(AuthenticationFailure.Cause.STALE, CoordinatorFixtures.error(caller).reason()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            f.clock.runWorker(); assertNull(f.coordinator.peek(old));
            CoordinatorFixtures.load(f.registry, f.definitions); var next = f.acquire(0); f.coordinator.close();
            assertEquals(AuthenticationFailure.Cause.CLOSED, CoordinatorFixtures.error(next).reason()); f.clock.runWorker(); assertNull(f.coordinator.peek(f.entry(0).identity()));
        }
    }
    @Test void expiredCycleReleasesCallersWhileActualWorkerStillOccupiesItsSlot() {
        try (var f = new Fixture(CoordinatorFixtures.controls(null, null, 1000, 1000, 1000))) {
            var caller = f.acquire(0); f.clock.advance(1000); assertEquals(AuthenticationFailure.Cause.TIMEOUT, CoordinatorFixtures.error(caller).reason());
            assertEquals(1, f.coordinator.capacity().runningAttempts()); f.clock.runWorker(); assertEquals(0, f.coordinator.capacity().runningAttempts()); assertNull(f.coordinator.peek(f.entry(0).identity()));
        }
    }
    @Test void invalidLiveControlsLeaveTheAppliedLimitsIntactAndNegativeMonotonicOriginsWork() {
        try (var f = new Fixture(CoordinatorFixtures.limits(1, null))) {
            f.clock.now = -TimeUnit.HOURS.toNanos(1); var first = f.acquire(0); assertFalse(first.future().isDone());
            assertThrows(IllegalArgumentException.class, () -> f.coordinator.updateControls(CoordinatorFixtures.controls(null, null, 999, 1000, 1000)));
            assertEquals(AuthenticationFailure.Cause.CAPACITY, CoordinatorFixtures.error(f.acquire(0)).reason()); f.clock.runWorker(); assertTrue(first.future().isDone());
        }
    }
    @Test void proactiveRefreshRetainsUsableTokenAndHardExpiryStillAppliesDuringRetries() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.acquire(0); f.clock.runWorker(); var old = f.coordinator.peek(f.entry(0).identity());
            f.clock.advance(1_790_000); assertEquals(1, f.clock.workers.size()); assertSame(old, f.coordinator.peek(old.identity()));
            f.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT)); f.clock.runWorker(); assertSame(old, f.coordinator.peek(old.identity()));
            f.clock.advance(5000); f.clock.runWorker(); f.clock.advance(5000); assertNull(f.coordinator.peek(old.identity()));
            assertEquals(1, f.coordinator.capacity().queuedCycles()); assertEquals(0, f.coordinator.capacity().waitingRequests());
        }
    }
    @Test void proactiveQueueDenialHasOneCoalescedDeferredTimerAndNeverRevivesExpiredToken() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var definitions = new ArrayList<>(f.definitions); java.util.stream.IntStream.range(0, 34).forEach(i -> definitions.add(CoordinatorFixtures.journey("busy" + i)));
            CoordinatorFixtures.load(f.registry, definitions); f.acquire(0); f.clock.runWorker(); var old = f.coordinator.peek(f.entry(0).identity());
            f.clock.advance(1_789_000);
            for (int i = 0; i < 34; i++) f.coordinator.acquire(List.of(f.registry.snapshot().resolve("busy" + i)));
            int before = f.clock.timers(); f.clock.advance(1000); assertEquals(before, f.clock.timers());
            assertEquals(new AuthenticationCoordinator.Capacity(34, 2, 32), f.coordinator.capacity()); assertSame(old, f.coordinator.peek(old.identity()));
            f.clock.advance(10_000); assertNull(f.coordinator.peek(old.identity())); assertEquals(before, f.clock.timers());
            assertEquals(2, f.clock.workers.size());
        }
    }
    @Test void explicitRecoveryIsNotRepeatedOnAutomaticTransportRetryAndRetryAfterMayIncreaseDelay() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.fail.set(new AuthenticationFailure(AuthenticationFailure.Phase.NAVIGATION, AuthenticationFailure.Cause.TEMPORARY_SERVICE, "HTTP 503.", "Retry later.", 503, f.clock.instant().plusSeconds(8)));
            var test = f.coordinator.test(f.entry(0), true); f.clock.runWorker(); assertEquals(List.of(true), f.recoveries);
            f.clock.advance(7999); assertTrue(f.clock.workers.isEmpty()); f.clock.advance(1); f.fail.set(null); f.clock.runWorker();
            assertEquals(List.of(true, false), f.recoveries); assertTrue(test.future().isDone());
        }
    }
    @Test void queuedCancelRemovesOnlyTheSelectedCycleAndManualInvalidatePreventsOldCommit() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var definitions = new ArrayList<>(f.definitions); definitions.add(CoordinatorFixtures.journey("queued")); CoordinatorFixtures.load(f.registry, definitions);
            var a = f.acquire(0); var b = f.acquire(1); var entry = f.registry.snapshot().resolve("queued"); var queued = f.coordinator.acquire(List.of(entry));
            f.coordinator.cancelAuthentication(entry.identity()); assertEquals(AuthenticationFailure.Cause.CANCELLED, CoordinatorFixtures.error(queued).reason());
            assertEquals(0, f.coordinator.capacity().queuedCycles()); assertFalse(a.future().isDone()); assertFalse(b.future().isDone());
            f.clock.runWorker(); f.clock.runWorker(); var token = f.coordinator.peek(f.entry(0).identity()); assertNotNull(token);
            f.coordinator.invalidate(token.identity()); assertNull(f.coordinator.peek(token.identity())); var demand = f.acquire(0); f.clock.runWorker(); assertTrue(demand.future().isDone());
        }
    }
    @Test void simultaneousRequestsStillShareExactlyOneCycleAndAtomicReservations() throws Exception {
        try (var f = new Fixture(Config.Controls.defaults())) {
            var threads = java.util.concurrent.Executors.newFixedThreadPool(8);
            try {
                var tasks = java.util.stream.IntStream.range(0, 200).mapToObj(i -> threads.submit(() -> f.acquire(0))).toList();
                var tickets = new ArrayList<AuthenticationCoordinator.Ticket>(); for (var task : tasks) tickets.add(task.get(5, TimeUnit.SECONDS));
                assertEquals(1, f.clock.workers.size()); assertEquals(200, f.coordinator.capacity().waitingRequests()); f.clock.runWorker();
                assertTrue(tickets.stream().allMatch(t -> t.future().isDone())); assertEquals(1, f.attempts.get()); assertEquals(0, f.coordinator.capacity().waitingRequests());
            } finally { threads.shutdownNow(); }
        }
    }
    @Test void pinStateChangedDuringBackoffOrBeforePublicationPreventsRetryAndTokenUse() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.fail.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT)); var caller = f.acquire(0); f.clock.runWorker();
            f.blocked.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.PIN_IN_PROGRESS)); f.clock.advance(5000); f.clock.runWorker();
            assertEquals(AuthenticationFailure.Cause.PIN_IN_PROGRESS, CoordinatorFixtures.error(caller).reason()); assertEquals(1, f.attempts.get());
        }
        try (var f = new Fixture(Config.Controls.defaults())) {
            f.blocked.set(CoordinatorFixtures.failure(AuthenticationFailure.Cause.PIN_INDETERMINATE).atInput(AuthenticationFailure.Input.SECURITY_DEVICE)); var caller = f.acquire(0); f.clock.runWorker();
            assertEquals(AuthenticationFailure.Cause.PIN_INDETERMINATE, CoordinatorFixtures.error(caller).reason()); assertNull(f.coordinator.peek(f.entry(0).identity()));
            assertEquals(AuthenticationFailure.Input.SECURITY_DEVICE, CoordinatorFixtures.error(caller).input().input());
        }
    }
    @Test void idleCancelReportsNoChangeAndDoesNotInvalidateOrApplyCooldown() {
        try (var f = new Fixture(Config.Controls.defaults())) {
            assertFalse(f.coordinator.cancelAuthentication(f.entry(0).identity())); var caller = f.acquire(0); f.clock.runWorker();
            var token = f.coordinator.peek(f.entry(0).identity()); assertNotNull(token); assertTrue(caller.future().isDone());
            int timers = f.clock.timers(); assertFalse(f.coordinator.cancelAuthentication(token.identity())); assertSame(token, f.coordinator.peek(token.identity())); assertEquals(timers, f.clock.timers());
        }
    }

    @Test void setupStagesBelongToTheExactAttemptAndDoNotResetDeadlines() {
        try (var secrets = new SecretStore()) {
            var registry = new JourneyRegistry(secrets); var journey = CoordinatorFixtures.journey("setup");
            CoordinatorFixtures.load(registry, List.of(journey)); var clock = new CoordinatorFixtures.ManualRuntime();
            var owner = new AtomicReference<AuthenticationCoordinator>();
            var callbacks = new ArrayList<java.util.function.Consumer<BrowserRuntimeManager.SetupStage>>();
            var deadlines = new ArrayList<Long>();
            AuthenticationCoordinator.Attempt work = new AuthenticationCoordinator.Attempt() {
                @Override public BrowserFlowRunner.Outcome run(JourneyRegistry.Entry entry, boolean recovery, long deadline, java.util.function.BooleanSupplier cancel) {
                    throw new AssertionError("The production observation overload must be selected.");
                }
                @Override public BrowserFlowRunner.Outcome run(JourneyRegistry.Entry entry, boolean recovery, long deadline,
                        java.util.function.BooleanSupplier cancel, java.util.function.Consumer<BrowserRuntimeManager.SetupStage> observer) throws AuthenticationFailure {
                    callbacks.add(observer); deadlines.add(deadline);
                    if (callbacks.size() == 2) {
                        callbacks.getFirst().accept(BrowserRuntimeManager.SetupStage.EXTRACTING_BROWSER);
                        assertNull(owner.get().status(entry.identity()).setupStage(), "previous attempt cannot write current status");
                    }
                    observer.accept(BrowserRuntimeManager.SetupStage.STARTING_DRIVER);
                    observer.accept(BrowserRuntimeManager.SetupStage.STARTING_DRIVER);
                    assertEquals(BrowserRuntimeManager.SetupStage.STARTING_DRIVER, owner.get().status(entry.identity()).setupStage());
                    if (callbacks.size() == 1) throw CoordinatorFixtures.failure(AuthenticationFailure.Cause.TRANSPORT);
                    return new BrowserFlowRunner.Outcome(entry.identity(), "fixture-token", clock.instant(), clock.nanos());
                }
            };
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, work, entry -> null)) {
                owner.set(coordinator); var entry = registry.snapshot().resolve("setup"); var ticket = coordinator.acquire(List.of(entry));
                clock.runWorker(); assertEquals(AuthenticationCoordinator.Phase.BACKOFF, coordinator.status(entry.identity()).phase());
                assertNull(coordinator.status(entry.identity()).setupStage());
                callbacks.getFirst().accept(BrowserRuntimeManager.SetupStage.VERIFYING_CACHE);
                assertNull(coordinator.status(entry.identity()).setupStage());
                clock.advance(5000); clock.runWorker(); assertTrue(ticket.future().isDone());
                assertEquals(List.of(TimeUnit.SECONDS.toNanos(61), TimeUnit.SECONDS.toNanos(66)), deadlines);
                assertNull(coordinator.status(entry.identity()).setupStage());
                callbacks.getLast().accept(BrowserRuntimeManager.SetupStage.EXTRACTING_BROWSER);
                assertNull(coordinator.status(entry.identity()).setupStage());
                assertEquals(2, coordinator.events().snapshot(entry.identity().key()).stream().filter(e -> e.message().equals("Starting the browser driver...")).count());
            }
        }
    }
    @Test void removedGenerationsRejectLateSetupMessagesAndCredentialPublication() {
        try (var secrets = new SecretStore()) {
            var registry = new JourneyRegistry(secrets); var journey = CoordinatorFixtures.journey("stages");
            CoordinatorFixtures.load(registry, List.of(journey)); var clock = new CoordinatorFixtures.ManualRuntime();
            var owner = new AtomicReference<AuthenticationCoordinator>();
            var callback = new AtomicReference<java.util.function.Consumer<BrowserRuntimeManager.SetupStage>>();
            AuthenticationCoordinator.Attempt work = new AuthenticationCoordinator.Attempt() {
                @Override public BrowserFlowRunner.Outcome run(JourneyRegistry.Entry entry, boolean recovery, long deadline, java.util.function.BooleanSupplier cancel) {
                    throw new AssertionError();
                }
                @Override public BrowserFlowRunner.Outcome run(JourneyRegistry.Entry entry, boolean recovery, long deadline,
                        java.util.function.BooleanSupplier cancel, java.util.function.Consumer<BrowserRuntimeManager.SetupStage> observer) {
                    callback.set(observer); observer.accept(BrowserRuntimeManager.SetupStage.EXTRACTING_BROWSER);
                    assertEquals(BrowserRuntimeManager.SetupStage.EXTRACTING_BROWSER, owner.get().status(entry.identity()).setupStage());
                    registry.disableScope(JourneyDefinition.Scope.PROJECT); owner.get().configurationChanged();
                    observer.accept(BrowserRuntimeManager.SetupStage.STARTING_BROWSER);
                    assertNull(owner.get().status(entry.identity()).setupStage());
                    return new BrowserFlowRunner.Outcome(entry.identity(), "stale-fixture", clock.instant(), clock.nanos());
                }
            };
            try (var coordinator = new AuthenticationCoordinator(registry, Config.Controls.defaults(), clock, work, entry -> null)) {
                owner.set(coordinator); var entry = registry.snapshot().resolve("stages"); var ticket = coordinator.acquire(List.of(entry));
                clock.runWorker(); assertTrue(ticket.future().isCompletedExceptionally()); assertNull(coordinator.peek(entry.identity()));
                coordinator.close(); callback.get().accept(BrowserRuntimeManager.SetupStage.STARTING_DRIVER);
                assertEquals(AuthenticationCoordinator.Phase.CLOSED, coordinator.status(entry.identity()).phase());
                assertNull(coordinator.status(entry.identity()).setupStage());
            }
        }
    }
}

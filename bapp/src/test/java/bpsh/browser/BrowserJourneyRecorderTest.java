package bpsh.browser;

import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.AuthenticationStage;
import bpsh.authentication.session.CoordinatorFixtures;
import bpsh.journey.BrowserSetup;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyRecording;
import bpsh.journey.SecretStore;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Startup failures must release the recording worker and report a terminal result to its dialog. */
class BrowserJourneyRecorderTest {
    @Test void browserSelectionFailureRetainsTheSettingsLocation() throws Exception {
        try (var recorder = new BrowserJourneyRecorder((request, values, visibility, deadline, cancelled, stage) -> {
            throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.ASSET_MISSING,
                    "Burp Browser is missing.").atInput(AuthenticationFailure.Input.BROWSER_EXECUTABLE);
        }, BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {}, 1000)) {
            var finished = new CompletableFuture<JourneyRecording.Event>();
            recorder.start(request(), SecretStore.Values.empty(), event -> { if (event.state() == JourneyRecording.State.CLOSED) finished.complete(event); });
            assertEquals(JourneyRecording.Field.BROWSER_EXECUTABLE, finished.get(3, TimeUnit.SECONDS).problem().field());
        }
    }
    private static JourneyRecording.Request request() {
        var journey = CoordinatorFixtures.journey("recording");
        var identity = new JourneyDefinition.Identity(JourneyDefinition.Scope.PROJECT, journey.id(), 1);
        return new JourneyRecording.Request(identity, new JourneyRecording.Stamp(identity.key(), 1, UUID.randomUUID()), BrowserSetup.from(journey));
    }

    @Test void linkageFailureClosesTheDialogAndDoesNotReserveRecordingForever() throws Exception {
        try (var recorder = new BrowserJourneyRecorder((request, values, visibility, deadline, cancelled, stage) -> {
            stage.accept(AuthenticationStage.STARTING_DRIVER);
            throw new NoClassDefFoundError("PRIVATE_VENDOR_OUTPUT");
        }, BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {}, 1000)) {
            for (int attempt = 0; attempt < 2; attempt++) {
                var finished = new CompletableFuture<JourneyRecording.Event>();
                var states = new CopyOnWriteArrayList<JourneyRecording.State>();
                var values = SecretStore.Values.empty();
                recorder.start(request(), values, event -> {
                    states.add(event.state());
                    if (event.state() == JourneyRecording.State.CLOSED) finished.complete(event);
                });
                var result = finished.get(3, TimeUnit.SECONDS);
                assertTrue(states.contains(JourneyRecording.State.STARTING_DRIVER));
                assertNotNull(result.problem()); assertTrue(result.problem().message().contains("Reload the complete extension JAR"));
                assertFalse(result.problem().message().contains("PRIVATE_VENDOR_OUTPUT"));
                assertThrows(IllegalStateException.class, values::pin);
            }
        }
    }

    @Test void preparationHasItsOwnBudgetAndReportsTheBlockedStage() throws Exception {
        var states = new CopyOnWriteArrayList<JourneyRecording.State>();
        var finished = new CompletableFuture<JourneyRecording.Event>();
        try (var recorder = new BrowserJourneyRecorder((request, values, visibility, deadline, cancelled, stage) -> {
            // The driver must retain a long interactive budget while its cancellation predicate bounds preparation.
            assertTrue(deadline - System.nanoTime() > TimeUnit.MINUTES.toNanos(1));
            stage.accept(AuthenticationStage.EXTRACTING_BROWSER);
            stage.accept(AuthenticationStage.STARTING_BROWSER);
            while (!cancelled.getAsBoolean()) java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
            throw new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CANCELLED, "Controlled cancellation.");
        }, BrowserSessionLauncher.Visibility.HEADLESS, (context, control) -> {}, 50)) {
            recorder.start(request(), SecretStore.Values.empty(), event -> {
                states.add(event.state()); if (event.state() == JourneyRecording.State.CLOSED) finished.complete(event);
            });
            var result = finished.get(3, TimeUnit.SECONDS);
            assertTrue(states.contains(JourneyRecording.State.EXTRACTING_BROWSER));
            assertTrue(states.contains(JourneyRecording.State.STARTING_BROWSER));
            assertNotNull(result.problem()); assertTrue(result.problem().message().contains("Browser preparation timed out"));
            assertTrue(result.problem().message().contains("desktop session"));
        }
    }
}

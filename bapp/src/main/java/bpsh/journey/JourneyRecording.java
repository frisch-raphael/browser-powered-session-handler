package bpsh.journey;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;

/** Framework-free recording port; candidates and their separately owned secrets remain unsaved until Apply. */
public interface JourneyRecording extends AutoCloseable {
    /** Bounds interactive recording independently of ordinary authentication deadlines. */
    final class Limits {
        private Limits() {}
        public static final long LIFETIME_MS = 30 * 60_000L, PREPARATION_MS = 60_000;
        public static final int PUMP_MS = 100, STOP_MS = 5000, STEPS = 256, PAGES = 16, FRAME_DEPTH = 16;
        public static final int QUEUED_EVENTS = 256, EVENT_BYTES = 64 * 1024, RETAINED_BYTES = 4 * 1024 * 1024;
        public static final int SELECTOR_BYTES = 4096, FILL_BYTES = 16 * 1024, OPTIONS = 256, SOURCE_KEY_BYTES = 128;
        public static final int METADATA_NODES = 16_384, METADATA_FIELDS = 4096, METADATA_RECORDS = 4096;
        /** Counts encoded data without allocating a second password representation. */
        public static int utf8Length(CharSequence text) {
            int bytes = 0;
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (Character.isHighSurrogate(c) && i + 1 < text.length() && Character.isLowSurrogate(text.charAt(i + 1))) { bytes += 4; i++; }
                else bytes += c < 128 || Character.isSurrogate(c) ? 1 : c < 2048 ? 2 : 3;
            }
            return bytes;
        }
    }

    /** Safe progress states contain no values, URLs or selectors. */
    enum State {
        PREPARING, WAITING_FOR_BROWSER, VERIFYING_BROWSER, EXTRACTING_BROWSER,
        STARTING_DRIVER, STARTING_BROWSER, OPENING_LOGIN, RECORDING, STOPPING, REVIEW, CLOSED
    }
    /** Identifies a known setup input without a UI component or vendor exception. */
    enum Field { GENERAL, LOGIN_URL, PROXY_URL, CLIENT_CERTIFICATE, PIN, MIDDLEWARE, SECURITY_DEVICE, TRUSTED_CA, HTTP_AUTHENTICATION, HTTP_PASSWORD, BROWSER_EXECUTABLE }
    /** Safe, application-owned failure guidance only. */
    record Problem(Field field, String message) {
        public Problem { Objects.requireNonNull(field); Objects.requireNonNull(message); }
    }
    /** Captures the exact editor and persisted revision which a result may replace. */
    record Stamp(JourneyKey journey, long editorEpoch, UUID storageRevision, long storageEpoch) {
        public Stamp { Objects.requireNonNull(journey); Objects.requireNonNull(storageRevision); }
        public Stamp(JourneyKey journey, long editorEpoch, UUID storageRevision) { this(journey, editorEpoch, storageRevision, 0); }
    }
    /** Contains validated setup and ownership, never the PIN or the previous sequence's secrets. */
    record Request(JourneyDefinition.Identity identity, Stamp stamp, BrowserSetup setup) {
        public Request {
            Objects.requireNonNull(identity); Objects.requireNonNull(stamp); Objects.requireNonNull(setup);
            if (!identity.key().equals(stamp.journey())) throw new IllegalArgumentException("Recording ownership differs from the editor.");
        }
        @Override public String toString() { return "RecordingRequest[journey=" + identity.key() + "]"; }
    }
    /** One editable action and its observed target; entered values are excluded from diagnostics. */
    record Candidate(AuthStep.Definition step, String pageRef, List<String> frames, boolean passwordUnclassified) {
        public Candidate { Objects.requireNonNull(step); Objects.requireNonNull(pageRef); frames = List.copyOf(frames); }
        @Override public String toString() { return "RecordingCandidate[id=" + step.id() + ", type=" + step.type() + "]"; }
    }
    /** Observed opener relationship and eligible earlier actions; the user resolves an ambiguous opening step. */
    record Popup(UUID declarationId, String pageRef, String opener, List<UUID> openingSteps, UUID suggestedStep) {
        public Popup { Objects.requireNonNull(declarationId); Objects.requireNonNull(pageRef); Objects.requireNonNull(opener); openingSteps = List.copyOf(openingSteps); }
    }

    /** Frozen review data owns its secret snapshot; closing it discards only the captured candidates. */
    final class Result implements AutoCloseable {
        private final Stamp stamp;
        private final List<Candidate> candidates;
        private final List<Popup> popups;
        private final List<String> problems;
        private final SecretStore.Values secrets;
        private final Runnable released;
        private boolean closed;

        /** Adopts a separately owned snapshot; the producer must not use it after publication. */
        public Result(Stamp stamp, List<Candidate> candidates, List<Popup> popups, List<String> problems,
                SecretStore.Values secrets, Runnable released) {
            this.stamp = Objects.requireNonNull(stamp); this.candidates = List.copyOf(candidates); this.popups = List.copyOf(popups);
            this.problems = List.copyOf(problems); this.secrets = Objects.requireNonNull(secrets); this.released = Objects.requireNonNull(released);
        }
        public Stamp stamp() { return stamp; }
        public List<Candidate> candidates() { return candidates; }
        public List<Popup> popups() { return popups; }
        public List<String> problems() { return problems; }
        public boolean complete() { return problems.isEmpty(); }
        /** @return Independently closable values for populating the review, without transferring result ownership. */
        public synchronized SecretStore.Values copySecrets() {
            if (closed) throw new IllegalStateException("The recording review is closed."); return secrets.copy();
        }
        /** Wipes the producer snapshot after the native review has acquired its own field ownership. */
        public synchronized void releaseCapturedSecrets() { secrets.close(); }
        @Override public void close() {
            synchronized (this) { if (closed) return; closed = true; secrets.close(); }
            released.run();
        }
        @Override public String toString() { return "RecordingResult[steps=" + candidates.size() + ", complete=" + complete() + "]"; }
    }

    /** Only REVIEW carries an owned result; terminal failures carry safe guidance. */
    record Event(State state, Result result, Problem problem) {
        public Event { Objects.requireNonNull(state); }
        @Override public String toString() { return "RecordingEvent[state=" + state + "]"; }
    }
    /** Thread-safe commands signal the owner; callers never touch Playwright handles. */
    interface Control {
        void stop();
        void cancel();
    }
    /** Adopts setup values, including on queue rejection; no authentication admission permit is acquired. */
    Control start(Request request, SecretStore.Values setupValues, Consumer<Event> observer);
    /** Revokes active recording/review and releases the dedicated worker. */
    @Override void close();
}

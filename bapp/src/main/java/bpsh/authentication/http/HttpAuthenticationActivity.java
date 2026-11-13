package bpsh.authentication.http;

import bpsh.journey.JourneyCatalog;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import java.net.URI;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/** Bounded session-only HTTP observations. Inspection never opens a connection or reads a secret. */
public final class HttpAuthenticationActivity implements AutoCloseable {
    private static final int MAX_JOURNEYS = 256;
    private final JourneyCatalog catalog;
    private final Map<JourneyKey, State> states = new LinkedHashMap<>();
    private BiConsumer<JourneyDefinition.Identity, HttpAuthenticationProgress> events = (identity, progress) -> {};
    private boolean closed;

    private static final class State {
        final JourneyCatalog.Entry entry;
        final bpsh.journey.HttpAuthentication settings;
        final Map<URI, HttpAuthenticationProgress> latest = new HashMap<>();
        State(JourneyCatalog.Entry entry,bpsh.journey.HttpAuthentication settings) { this.entry = entry; this.settings = settings; }
    }

    public HttpAuthenticationActivity(JourneyCatalog catalog) { this.catalog = Objects.requireNonNull(catalog); }

    /** Installs the extension's safe event destination without coupling core HTTP contracts to a log adapter. */
    public synchronized void events(BiConsumer<JourneyDefinition.Identity, HttpAuthenticationProgress> sink) { events = Objects.requireNonNull(sink); }

    /** Captures a generation and a clear-cache fence before asynchronous setup begins. */
    public synchronized Consumer<HttpAuthenticationProgress> observe(HttpTransportFactory.ScopeSpec spec) {
        if (closed || spec == null || spec.identity() == null || !spec.setup().httpAuthenticationEnabled()) return ignored -> {};
        prune();
        var entry = current(spec.identity());
        boolean recordingDraft = entry != null && spec.purpose() == HttpTransportFactory.Purpose.RECORDING && draftEnabled(entry);
        if (entry == null || !recordingDraft && !Objects.equals(entry.definition().httpAuthentication(), spec.setup().httpAuthentication())) return ignored -> {};
        State state = states.computeIfAbsent(entry.identity().key(), ignored -> new State(entry,spec.setup().httpAuthentication()));
        if (!Objects.equals(state.settings,spec.setup().httpAuthentication())) return ignored -> {};
        while (states.size() > MAX_JOURNEYS) states.remove(states.keySet().iterator().next());
        return progress -> record(state, progress);
    }

    private void record(State state, HttpAuthenticationProgress progress) {
        synchronized (this) {
            if (closed || states.get(state.entry.identity().key()) != state || !valid(state) || progress == null) return;
            if (progress.protocol() != state.settings.protocol()) return;
            if (progress.origin() != null && !state.settings.allows(progress.origin())) return;
            var previous = state.latest.get(progress.origin());
            if (previous == null || !previous.time().isAfter(progress.time())) state.latest.put(progress.origin(), progress);
            // Reuse is a per-request fact, including ordinary redirects; inspection keeps it without a lifecycle event.
            if (progress.stage() == HttpAuthenticationProgress.Stage.CONNECTION_REUSED) return;
            // Serialize event publication with Clear cache so a retired scope cannot append late events.
            try { events.accept(state.entry.identity(), progress); } catch (RuntimeException ignored) { /* Inspection cannot fail an exchange. */ }
        }
    }

    /** Latest facts belong only to the exact current saved identity and are never a live-connection claim. */
    public synchronized List<HttpAuthenticationProgress> snapshot(JourneyDefinition.Identity identity) {
        prune();
        var state = states.get(identity.key());
        if (closed || state == null || !state.entry.identity().equals(identity)) return List.of();
        return state.latest.values().stream().sorted(Comparator.comparing(p -> p.origin() == null ? "" : p.origin().toString())).toList();
    }

    /** Validated recording setup remains inspectable while unrelated capture settings are unfinished. */
    public synchronized bpsh.journey.HttpAuthentication settings(JourneyDefinition.Identity identity) {
        prune();var state = states.get(identity.key());
        return !closed && state != null && state.entry.identity().equals(identity) ? state.settings : null;
    }

    /** Discards inspection facts and prevents in-flight scopes from restoring them after an explicit clear. */
    public synchronized void clear(JourneyDefinition.Identity identity) { states.remove(identity.key()); }

    private JourneyCatalog.Entry current(JourneyDefinition.Identity identity) {
        var snapshot = catalog.snapshot();
        return snapshot.isCurrent(identity) ? snapshot.entries().get(identity.key()) : null;
    }
    private boolean valid(State state) {
        var entry = current(state.entry.identity());
        return entry != null && (entry.definition().httpAuthenticationEnabled() || draftEnabled(entry)) && state.entry.sameHttpAuthentication(entry);
    }
    private static boolean draftEnabled(JourneyCatalog.Entry entry) {
        return entry.definition().draft() != null && entry.definition().draft().flags().get("httpAuthentication");
    }
    private void prune() { states.values().removeIf(state -> !valid(state)); }

    @Override public synchronized void close() { closed = true; states.clear(); events = (identity, progress) -> {}; }
}

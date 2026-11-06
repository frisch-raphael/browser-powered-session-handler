import java.time.Instant;
import java.util.ArrayDeque;
import java.util.List;

/** Bounded session-only history keyed by stable journey identity; accepts sanitized metadata, never credentials or requests. */
final class JourneyEventLog implements AutoCloseable {
    static final int PER_JOURNEY = 200, TOTAL = 4000, MESSAGE_LIMIT = 4096;
    /** User-facing event severity. */
    enum Level { INFO, WARNING, ERROR }
    /** Immutable safe display data; sequence preserves ordering when timestamps coincide. */
    record Event(long sequence, Instant time, Level level, String message, StepTarget step) {}
    /** Exact saved generation and stable action, without selector or input data. */
    record StepTarget(JourneyDefinition.Identity journey, java.util.UUID id) {}
    /** Keeps ownership separate from user-controlled aliases, including after alias reassignment. */
    private record Owned(SecretStore.Key key, Event event) {}
    private final ArrayDeque<Owned> events = new ArrayDeque<>();
    private long revision, sequence;
    private boolean closed;

    /**
     * Appends only safe constant/typed descriptions; adjacent repeated warnings are coalesced for five seconds.
     * @param key Stable scope/UUID owner.
     * @param time Event observation time.
     * @param level User-facing severity.
     * @param message Already sanitized problem/action; no raw exception, URL, body, token, PIN or selector.
     */
    synchronized void append(SecretStore.Key key, Instant time, Level level, String message) {
        append(key, time, level, message, null);
    }
    /** @param key Stable owner. @param time Observation time. @param level Severity. @param message Sanitized description. @param step Optional exact failed action. */
    synchronized void append(SecretStore.Key key, Instant time, Level level, String message, StepTarget step) {
        if (closed || key == null) return;
        String safe = message.length() > MESSAGE_LIMIT ? message.substring(0, MESSAGE_LIMIT) + "…" : message;
        var previous = events.descendingIterator(); int count = 0; Owned oldest = null;
        while (previous.hasNext()) {
            Owned value = previous.next(); if (!value.key().equals(key)) continue;
            if (count++ == 0 && value.event().level() == level && value.event().message().equals(safe) && java.util.Objects.equals(value.event().step(), step)
                    && !time.isBefore(value.event().time()) && time.isBefore(value.event().time().plusSeconds(5))) return;
            oldest = value;
        }
        if (count >= PER_JOURNEY) events.remove(oldest);
        events.addLast(new Owned(key, new Event(++sequence, time, level, safe, step)));
        while (events.size() > TOTAL) events.removeFirst(); revision++;
    }
    /** @param key Selected stable owner. @return Ordered immutable history belonging only to this journey. */
    synchronized List<Event> snapshot(SecretStore.Key key) { return events.stream().filter(value -> value.key().equals(key)).map(Owned::event).toList(); }
    /** @return Change counter allowing the Swing view to skip unchanged snapshots. */
    synchronized long revision() { return revision; }
    /** @param key Explicitly selected journey whose in-memory history is cleared. */
    synchronized void clear(SecretStore.Key key) { if (events.removeIf(value -> value.key().equals(key))) revision++; }
    /** Releases all session history and rejects late worker events after unload. */
    @Override public synchronized void close() { closed = true; events.clear(); revision++; }
}

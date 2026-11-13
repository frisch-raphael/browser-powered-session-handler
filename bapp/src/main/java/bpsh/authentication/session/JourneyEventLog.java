package bpsh.authentication.session;

import bpsh.journey.JourneyDefinition;
import bpsh.journey.JourneyKey;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

/** Bounded session-only history keyed by stable journey identity; accepts sanitized metadata, never credentials or requests. */
public final class JourneyEventLog implements AutoCloseable {
    public static final int PER_JOURNEY = 200, TOTAL = 4000, MESSAGE_LIMIT = 4096;
    /** User-facing event severity. */
    public enum Level { INFO, WARNING, ERROR }
    /** Immutable safe display data; sequence preserves ordering when timestamps coincide. */
    public record Event(long sequence, Instant time, Level level, String message, StepTarget step, long occurrences, Instant lastTime) {}
    /** Exact saved generation and stable action, without selector or input data. */
    public record StepTarget(JourneyDefinition.Identity journey, java.util.UUID id) {}
    /** Keeps ownership separate from user-controlled aliases, including after alias reassignment. */
    private record Owned(JourneyKey key, Event event) {}
    private final LinkedList<Owned> events = new LinkedList<>();
    private long revision, sequence;
    private boolean closed;

    /**
     * Appends safe descriptions; retained matching warnings/errors share one row with occurrence metadata.
     * @param key Stable scope/UUID owner.
     * @param time Event observation time.
     * @param level User-facing severity.
     * @param message Already sanitized problem/action; no raw exception, URL, body, token, PIN or selector.
     */
    public synchronized void append(JourneyKey key, Instant time, Level level, String message) {
        append(key, time, level, message, null);
    }
    /** @param key Stable owner. @param time Observation time. @param level Severity. @param message Sanitized description. @param step Optional exact failed action. */
    public synchronized void append(JourneyKey key, Instant time, Level level, String message, StepTarget step) {
        if (closed || key == null) return;
        String safe = message.length() > MESSAGE_LIMIT ? message.substring(0, MESSAGE_LIMIT) + "…" : message;
        var previous = events.listIterator(events.size()); int count = 0; Owned oldest = null;
        while (previous.hasPrevious()) {
            Owned value = previous.previous(); if (!value.key().equals(key)) continue;
            count++;
            var event = value.event();
            if (event.level() == level && event.message().equals(safe) && java.util.Objects.equals(event.step(), step)) {
                if (level != Level.INFO) {
                    previous.set(new Owned(key, new Event(event.sequence(), event.time(), level, safe, step,
                            event.occurrences() == Long.MAX_VALUE ? Long.MAX_VALUE : event.occurrences() + 1,
                            time.isAfter(event.lastTime()) ? time : event.lastTime())));
                    revision++; return;
                }
                if (count == 1 && !time.isBefore(event.time()) && time.isBefore(event.time().plusSeconds(5))) return;
            }
            oldest = value;
        }
        if (count >= PER_JOURNEY) events.remove(oldest);
        events.addLast(new Owned(key, new Event(++sequence, time, level, safe, step, 1, time)));
        while (events.size() > TOTAL) events.removeFirst(); revision++;
    }
    /** @param key Selected stable owner. @return Ordered immutable history belonging only to this journey. */
    public synchronized List<Event> snapshot(JourneyKey key) { return events.stream().filter(value -> value.key().equals(key)).map(Owned::event).toList(); }
    /** @return Change counter allowing the Swing view to skip unchanged snapshots. */
    public synchronized long revision() { return revision; }
    /** @param key Explicitly selected journey whose in-memory history is cleared. */
    public synchronized void clear(JourneyKey key) { if (events.removeIf(value -> value.key().equals(key))) revision++; }
    /** Releases all session history and rejects late worker events after unload. */
    @Override public synchronized void close() { closed = true; events.clear(); revision++; }
}

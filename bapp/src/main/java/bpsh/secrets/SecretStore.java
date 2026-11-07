package bpsh.secrets;

import bpsh.model.JourneyKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Owns mutable session secrets separately from journey definitions and tokens.
 *
 * Operations are synchronized. The store clones incoming values and returns independent snapshots
 * that callers must close. Owned character arrays are wiped on replacement/close; Java strings
 * created by JSON or browser APIs cannot be securely erased by this store.
 */
public final class SecretStore implements AutoCloseable {


    /**
     * Owns an independent set of PIN and secure-step character buffers.
     *
     * Null means missing; an empty array is a supplied value. Step UUIDs preserve associations across
     * reordering. Array accessors return copies that callers must wipe; closing this snapshot only
     * wipes its own buffers, not previously returned copies.
     */
    public static final class Values implements AutoCloseable {
        private char[] pin;
        private final Map<UUID, char[]> steps = new HashMap<>();
        private boolean closed;

        /**
         * Clones supplied buffers without taking ownership of the caller's arrays.
         *
         * @param pin mTLS PIN, or null when missing.
         * @param stepValues Secure-step UUIDs mapped to supplied values; keys and arrays must be nonnull.
         */
        public Values(char[] pin, Map<UUID, char[]> stepValues) {
            this.pin = cloneOrNull(pin);
            stepValues.forEach((key, value) -> steps.put(Objects.requireNonNull(key), Objects.requireNonNull(value).clone()));
        }
        /**
         * Creates an open snapshot with every secret missing.
         *
         * @return An independently closable empty value set.
         */
        public static Values empty() { return new Values(null, Map.of()); }
        /**
         * Copies an optional buffer while distinguishing missing from supplied empty values.
         *
         * @param value Borrowed buffer, or null.
         * @return A caller-owned copy, or null; never the original array.
         */
        private static char[] cloneOrNull(char[] value) { return value == null ? null : value.clone(); }
        /**
         * Guards buffer access while the calling operation holds the Values monitor.
         *
         * @throws IllegalStateException If close has already wiped this snapshot.
         */
        private void checkOpen() { if (closed) throw new IllegalStateException("Secret snapshot is closed."); }
        /**
         * Copies the PIN without exposing the owned buffer.
         *
         * @return Caller-owned characters to wipe, or null when missing.
         * @throws IllegalStateException If this snapshot is closed.
         */
        public synchronized char[] pin() { checkOpen(); return cloneOrNull(pin); }
        /**
         * Lists secure-step associations without disclosing their values.
         *
         * @return An immutable copy of the associated UUIDs.
         * @throws IllegalStateException If this snapshot is closed.
         */
        public synchronized Set<UUID> stepIds() { checkOpen(); return Set.copyOf(steps.keySet()); }
        /**
         * Copies the value associated with one secure step.
         *
         * @param id Stable step UUID in this journey.
         * @return Caller-owned characters to wipe, or null for an absent association.
         * @throws IllegalStateException If this snapshot is closed.
         */
        public synchronized char[] stepValue(UUID id) { checkOpen(); return cloneOrNull(steps.get(id)); }
        /**
         * Tests for absence of every optional buffer and secure-step association.
         *
         * @return True only for missing values; supplied empty arrays still count as values.
         * @throws IllegalStateException If this snapshot is closed.
         */
        public synchronized boolean isEmpty() { checkOpen(); return pin == null && steps.isEmpty(); }
        /**
         * Clones all buffers into a snapshot with an independent lifetime.
         *
         * @return A separately owned value set that the caller must close.
         * @throws IllegalStateException If this snapshot is closed.
         */
        public synchronized Values copy() { checkOpen(); return new Values(pin, steps); }
        /**
         * Rebinds imported values to freshly allocated destination step UUIDs.
         *
         * The PIN is copied unchanged. Every existing secure-step association must have
         * a destination; the source snapshot is neither modified nor consumed.
         *
         * @param ids Source-to-destination step UUID mapping from a validated import.
         * @return A separately owned snapshot using destination step UUIDs.
         * @throws IllegalArgumentException If a secure step lacks a destination mapping.
         * @throws IllegalStateException If this snapshot is closed.
         */
        public synchronized Values remapSteps(Map<UUID, UUID> ids) {
            checkOpen();
            Map<UUID, char[]> remapped = new HashMap<>();
            steps.forEach((id, value) -> {
                UUID mapped = ids.get(id);
                if (mapped == null) throw new IllegalArgumentException("A secure step has no destination identity.");
                remapped.put(mapped, value);
            });
            return new Values(pin, remapped);
        }
        /**
         * Builds a replacement snapshot without one step association.
         *
         * @param id Step UUID to forget; an absent association is harmless.
         * @return A new owned value set; the original still needs to be closed by its owner.
         * @throws IllegalStateException If this snapshot is closed.
         */
        private synchronized Values withoutStep(UUID id) {
            checkOpen();
            Map<UUID, char[]> retained = new HashMap<>(steps);
            retained.remove(id);
            return new Values(pin, retained);
        }
        /**
         * Filters secrets to those still owned by an edited definition.
         *
         * Deleted/retyped secure steps and removed mTLS configuration must not leave dangling
         * values. Filtering produces a copy so failed saves cannot mutate the active session.
         *
         * @param secureStepIds UUIDs that remain secure inputs after the edit.
         * @param includePin Whether mTLS configuration remains present.
         * @return An independently owned, filtered value set.
         * @throws IllegalStateException If this snapshot is closed.
         */
        public synchronized Values retain(Set<UUID> secureStepIds, boolean includePin) {
            checkOpen();
            Map<UUID, char[]> retained = new HashMap<>();
            steps.forEach((id, value) -> { if (secureStepIds.contains(id)) retained.put(id, value); });
            return new Values(includePin ? pin : null, retained);
        }
        /**
         * Compares effective values to decide whether a configuration generation must advance.
         *
         * Only store-owned snapshots may reach this method. The store serializes comparisons, preventing
         * lock inversion while both Values monitors are held. This configuration comparison is not a
         * constant-time authentication primitive.
         *
         * @param other Open, store-owned replacement snapshot.
         * @return True when optional buffers and all step associations have equal content.
         * @throws IllegalStateException If either snapshot is closed.
         */
        private synchronized boolean sameAs(Values other) {
            checkOpen();
            // Only store-owned snapshots reach this comparison; their ownership prevents lock inversion.
            synchronized (other) {
                other.checkOpen();
                if (!Arrays.equals(pin, other.pin)
                        || !steps.keySet().equals(other.steps.keySet())) return false;
                for (UUID key : steps.keySet()) if (!Arrays.equals(steps.get(key), other.steps.get(key))) return false;
                return true;
            }
        }
        /**
         * Wipes owned buffers and rejects future reads; repeated closes are harmless.
         *
         * Previously returned copies remain the responsibility of their callers.
         */
        @Override public synchronized void close() {
            if (closed) return;
            if (pin != null) Arrays.fill(pin, '\0');
            steps.values().forEach(value -> Arrays.fill(value, '\0'));
            steps.clear(); pin = null; closed = true;
        }
        /**
         * Returns a fixed redacted label, including after close.
         *
         * @return Diagnostics containing no secret content or association details.
         */
        @Override public String toString() { return "SecretValues[redacted]"; }
    }

    private final Map<JourneyKey, Values> entries = new HashMap<>();
    private boolean closed;
    /**
     * Guards operations that would access or create buffers after store shutdown.
     *
     * The calling operation holds the store monitor.
     *
     * @throws IllegalStateException If the store is closed.
     */
    private void checkOpen() { if (closed) throw new IllegalStateException("Secret store is closed."); }
    /**
     * Copies a journey's values without transferring the store's ownership.
     *
     * @param key Scoped journey whose values are requested.
     * @return Caller-owned snapshot to close; empty when the key has no entry.
     * @throws IllegalStateException If the store is closed.
     */
    public synchronized Values snapshot(JourneyKey key) {
        checkOpen();
        Values value = entries.get(key);
        return value == null ? Values.empty() : value.copy();
    }
    /**
     * Replaces a journey's values with owned copies and wipes the superseded buffers.
     *
     * The caller retains ownership of the supplied snapshot and may close it immediately afterward.
     * Even an equal replacement is copied independently.
     *
     * @param key Scoped journey receiving the values.
     * @param values Open snapshot to copy, including an empty snapshot to clear effective values.
     * @return Whether effective content changed; an absent entry and an empty replacement are equal.
     * @throws IllegalStateException If the store or supplied snapshot is closed.
     */
    public synchronized boolean put(JourneyKey key, Values values) {
        checkOpen();
        Values replacement = values.copy();
        Values previous = entries.get(key);
        boolean changed = previous == null ? !replacement.isEmpty() : !previous.sameAs(replacement);
        entries.put(key, replacement);
        if (previous != null) previous.close();
        return changed;
    }
    /**
     * Forgets a journey and wipes any stored buffers.
     *
     * Missing entries and cleanup after shutdown are harmless.
     *
     * @param key Scoped journey whose session values must be discarded.
     */
    public synchronized void remove(JourneyKey key) {
        Values previous = entries.remove(key);
        if (previous != null) previous.close();
    }
    /**
     * Forgets one step association while preserving the journey's remaining secrets.
     *
     * @param key Scoped journey owning the step.
     * @param stepId Removed or retyped secure-step UUID.
     * @throws IllegalStateException If the store is closed.
     */
    public synchronized void removeStep(JourneyKey key, UUID stepId) {
        checkOpen();
        Values previous = entries.get(key);
        if (previous == null) return;
        Values replacement = previous.withoutStep(stepId);
        entries.put(key, replacement); previous.close();
    }
    /**
     * Wipes all stored values and rejects future reads/replacements.
     *
     * Snapshots already returned to callers remain their responsibility. Repeated closes are harmless.
     */
    @Override public synchronized void close() {
        if (closed) return;
        entries.values().forEach(Values::close);
        entries.clear(); closed = true;
    }
}

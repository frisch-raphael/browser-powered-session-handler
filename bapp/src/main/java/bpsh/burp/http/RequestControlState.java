package bpsh.burp.http;

import bpsh.request.RequestSettings;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/** Publishes controls and their compiled matching plan in one atomic replacement. */
public final class RequestControlState {
    /** @param controls Immutable source. @param matcher Compiled plan for exactly that source. */
    public record Applied(RequestSettings.Controls controls, RequestRuleMatcher matcher) {
        /** Prevents source and plan from being assembled from different publications. */
        public Applied {
            Objects.requireNonNull(controls); Objects.requireNonNull(matcher);
            if (controls != matcher.controls()) throw new IllegalArgumentException("Controls and matching plan must share the exact source publication.");
        }
    }
    private final AtomicReference<Applied> applied;

    /** @param controls Initial validated controls; compilation finishes before state becomes visible. */
    public RequestControlState(RequestSettings.Controls controls) { applied = new AtomicReference<>(prepare(controls)); }

    /** @param controls Proposed controls. @return Validated publication without changing live state. */
    public Applied prepare(RequestSettings.Controls controls) { return new Applied(controls, RequestRuleMatcher.compile(controls)); }

    /** @param prepared Previously compiled publication whose persistence has succeeded. */
    public void publish(Applied prepared) { applied.set(Objects.requireNonNull(prepared)); }

    /** @return One consistent source and plan publication. */
    public Applied snapshot() { return applied.get(); }
}

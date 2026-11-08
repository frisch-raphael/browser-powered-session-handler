package bpsh.authentication;

/** Scheduling/admission input port. Authentication does not consume host tools or injection rules. */
public interface AuthenticationPolicy {
    /** @return Shared caller wait budget in milliseconds. */
    int requestWaitTimeoutMs();
    /** @return Individual attempt budget in milliseconds. */
    int attemptTimeoutMs();
    /** @return Shared cycle budget in milliseconds. */
    int cycleTimeoutMs();
    /** @return Global admitted waiter limit, or null for unlimited. */
    Integer maxWaitingRequestsGlobal();
    /** @return Per-journey admitted waiter limit, or null for unlimited. */
    Integer maxWaitingRequestsPerJourney();
}

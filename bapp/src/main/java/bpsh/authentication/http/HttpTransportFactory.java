package bpsh.authentication.http;

import bpsh.journey.BrowserSetup;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import java.util.UUID;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/** Shared asynchronous setup and resource ownership boundary for direct, test and browser scopes. */
public interface HttpTransportFactory extends AutoCloseable {
    enum Purpose { DIRECT, TEST, BROWSER, RECORDING }
    record ScopeSpec(UUID scopeId,Purpose purpose,JourneyDefinition.Identity identity,long invalidationEpoch,
                     BrowserSetup setup,boolean explicitRecovery) {
        public ScopeSpec {
            Objects.requireNonNull(scopeId);Objects.requireNonNull(purpose);Objects.requireNonNull(setup);
            if(identity==null && purpose!=Purpose.RECORDING)throw new IllegalArgumentException("A saved HTTP identity is required.");
        }
    }
    /** Copies secrets before returning; the caller may immediately close its snapshot. */
    CompletableFuture<HttpAuthenticationService> open(ScopeSpec spec,SecretStore.Values secrets,long deadlineNanos);
    HttpMessageBody.Allocator bodies();
    @Override void close();
}

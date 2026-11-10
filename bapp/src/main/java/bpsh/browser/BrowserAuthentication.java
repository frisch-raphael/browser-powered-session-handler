package bpsh.browser;

import bpsh.authentication.AuthenticationPolicy;
import bpsh.journey.JourneyCatalog;
import bpsh.authentication.credentials.AuthenticationResult;
import bpsh.authentication.AuthenticationFailure;
import bpsh.authentication.AuthenticationStage;
import bpsh.transport.tls.Pkcs11IdentityManager;
import bpsh.journey.SecretStore;
import bpsh.authentication.session.AuthenticationCoordinator;
import java.util.function.BooleanSupplier;

/** Wires the real browser and native PIN gate to the independently testable session policy. */
public final class BrowserAuthentication {
    private BrowserAuthentication() {}
    public static AuthenticationCoordinator coordinator(JourneyCatalog registry, SecretStore secrets, BrowserFlowRunner runner,
            Pkcs11IdentityManager identities, AuthenticationPolicy controls) {
        return new AuthenticationCoordinator(registry, controls, new AuthenticationCoordinator.Attempt() {
            @Override public AuthenticationResult run(JourneyCatalog.Entry entry, boolean recovery, long deadline,
                    BooleanSupplier cancelled) throws AuthenticationFailure {
                return run(entry, recovery, deadline, cancelled, stage -> {});
            }
            @Override public AuthenticationResult run(JourneyCatalog.Entry entry, boolean recovery, long deadline,
                    BooleanSupplier cancelled, java.util.function.Consumer<AuthenticationStage> observer) throws AuthenticationFailure {
                try (var values = secrets.snapshot(entry.identity().key())) {
                    return runner.run(entry.identity(), entry.definition(), values, recovery, deadline, cancelled, observer);
                }
            }
        }, entry -> {
            if (entry.definition().mtls() == null) return null;
            var status = identities.status(entry.definition().mtls());
            var cause = status.paused() != null ? status.paused() : status.operationOutstanding() ? AuthenticationFailure.Cause.PIN_IN_PROGRESS : null;
            return cause == null ? null : new AuthenticationFailure(AuthenticationFailure.Phase.PIN, cause,
                    "Automatic PIN attempts are paused for this security device.", "").atInput(AuthenticationFailure.Input.SECURITY_DEVICE);
        });
        }
}

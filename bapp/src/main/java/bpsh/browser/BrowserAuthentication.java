package bpsh.browser;

import bpsh.config.Config;
import bpsh.config.JourneyRegistry;
import bpsh.credentials.AuthenticationResult;
import bpsh.model.AuthenticationFailure;
import bpsh.model.AuthenticationStage;
import bpsh.mtls.Pkcs11IdentityManager;
import bpsh.secrets.SecretStore;
import bpsh.session.AuthenticationCoordinator;
import java.util.function.BooleanSupplier;

/** Wires the real browser and native PIN gate to the independently testable session policy. */
public final class BrowserAuthentication {
    private BrowserAuthentication() {}
    public static AuthenticationCoordinator coordinator(JourneyRegistry registry, SecretStore secrets, BrowserFlowRunner runner,
            Pkcs11IdentityManager identities, Config.Controls controls) {
        return new AuthenticationCoordinator(registry, controls, new AuthenticationCoordinator.Attempt() {
            @Override public AuthenticationResult run(JourneyRegistry.Entry entry, boolean recovery, long deadline,
                    BooleanSupplier cancelled) throws AuthenticationFailure {
                return run(entry, recovery, deadline, cancelled, stage -> {});
            }
            @Override public AuthenticationResult run(JourneyRegistry.Entry entry, boolean recovery, long deadline,
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

package bpsh.runtime;

import bpsh.model.AuthenticationFailure;

/** Test-only observations at the runtime boundary; production implementation details stay private. */
public final class RuntimeFixtures {
    private RuntimeFixtures() {}

    public static AuthenticationFailure unsupportedPlatform() {
        try {
            BrowserRuntimeManager.parseManifest(new byte[0], "unsupported-platform", BrowserRuntimeManager.Limits.standard());
            throw new AssertionError("An unsupported target must fail before parsing or reading assets.");
        } catch (AuthenticationFailure failure) {
            return failure;
        }
    }
}

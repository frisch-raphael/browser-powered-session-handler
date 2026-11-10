package bpsh.authentication.http;

import bpsh.authentication.AuthenticationFailure;
import java.io.IOException;

/** Safe delivery outcome for host presentation; vendor exception text is never displayed. */
public final class HttpDeliveryFailure extends IOException {
    private final boolean possiblySent;
    public HttpDeliveryFailure(boolean possiblySent, Throwable cause) {
        super(possiblySent ? "The HTTP request may have reached the server. Its outcome is uncertain; it was not automatically retried."
                : "The authenticated HTTP exchange failed before delivery.",cause);
        this.possiblySent=possiblySent;
    }
    public AuthenticationFailure presentation() {
        return new AuthenticationFailure(AuthenticationFailure.Phase.PROXY,AuthenticationFailure.Cause.UNKNOWN,getMessage(),
                possiblySent ? "Check the server-side result before resending a state-changing request." : "");
    }
}

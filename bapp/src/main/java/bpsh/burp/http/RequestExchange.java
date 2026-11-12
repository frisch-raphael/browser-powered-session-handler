package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard;
import java.util.Objects;

/** @param family Independent host callback namespace. @param id Message ID within that namespace. */
public record RequestExchange(AuthTrafficGuard.Family family, long id) {
    /** Requires an explicit namespace rather than inferring one from numeric IDs. */
    public RequestExchange { Objects.requireNonNull(family); }
    /** @return Safe family-qualified request label. */
    @Override public String toString() { return family + " request " + id; }
}

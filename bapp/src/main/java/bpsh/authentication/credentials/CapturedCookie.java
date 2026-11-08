package bpsh.authentication.credentials;
/** Browser-independent observation of one cookie applicable to the requested URL. */
public record CapturedCookie(String name, String value, String domain, String path, Double expires) {
    /** Credential text must never enter incidental diagnostics. */
    @Override public String toString() { return "CapturedCookie[name=" + name + "]"; }
}

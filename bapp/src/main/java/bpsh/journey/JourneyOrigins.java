package bpsh.journey;
import java.net.URI;
import java.util.Locale;
/** Exact authentication-server identity shared by authoring and native configuration. */
public final class JourneyOrigins {
    private JourneyOrigins() {}
    /** Returns a normalized HTTP(S) origin without DNS lookup or accepting embedded credentials. */
    public static URI authenticationOrigin(URI url) {
        if (url == null || url.getHost() == null || url.getRawUserInfo() != null || url.getPort() < -1 || url.getPort() == 0 || url.getPort() > 65535)
            throw new IllegalArgumentException("Invalid HTTP authentication origin.");
        String scheme = url.getScheme() == null ? "" : url.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) throw new IllegalArgumentException("Invalid HTTP authentication scheme.");
        int port = url.getPort();
        if (port == (scheme.equals("https") ? 443 : 80)) port = -1;
        try { return new URI(scheme, null, url.getHost().toLowerCase(Locale.ROOT), port, null, null, null); }
        catch (Exception error) { throw new IllegalArgumentException("Invalid HTTP authentication origin."); }
    }
    /** @return Canonical HTTPS origin, or null for an HTTP login; input is a validated login URL. */
    public static URI certificateLoginOrigin(URI url) {
        if (url == null || !"https".equalsIgnoreCase(url.getScheme())) return null;
        try { return new URI("https", null, url.getHost().toLowerCase(Locale.ROOT), url.getPort() == 443 ? -1 : url.getPort(), null, null, null); }
        catch (Exception error) { throw new IllegalArgumentException("Invalid login origin."); }
    }
}

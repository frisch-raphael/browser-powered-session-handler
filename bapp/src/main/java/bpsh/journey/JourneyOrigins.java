package bpsh.journey;
import java.net.URI;
import java.util.Locale;
/** Exact authentication-server identity shared by authoring and native configuration. */
public final class JourneyOrigins {
    private JourneyOrigins() {}
    /** @return Canonical HTTPS origin, or null for an HTTP login; input is a validated login URL. */
    public static URI certificateLoginOrigin(URI url) {
        if (url == null || !"https".equalsIgnoreCase(url.getScheme())) return null;
        try { return new URI("https", null, url.getHost().toLowerCase(Locale.ROOT), url.getPort() == 443 ? -1 : url.getPort(), null, null, null); }
        catch (Exception error) { throw new IllegalArgumentException("Invalid login origin."); }
    }
}

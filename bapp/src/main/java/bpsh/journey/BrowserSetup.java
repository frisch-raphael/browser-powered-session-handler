package bpsh.journey;

import java.net.URI;
import java.util.Objects;

/** Validated browser and certificate setup, independent of login steps and credential capture. */
public record BrowserSetup(URI authenticationUrl, JourneyDefinition.Browser browser, JourneyDefinition.Mtls mtls) {
    /** Captures setup validated by the shared codec or an already executable journey. */
    public BrowserSetup {
        Objects.requireNonNull(authenticationUrl);
        Objects.requireNonNull(browser);
    }

    /** Extracts setup without copying steps, capture rules or session secrets. */
    public static BrowserSetup from(JourneyDefinition journey) {
        return new BrowserSetup(journey.authenticationUrl(), journey.browser(), journey.mtls());
    }

    /** Excludes URLs, device details and configuration values from incidental diagnostics. */
    @Override public String toString() { return "BrowserSetup[clientCertificate=" + (mtls != null) + "]"; }
}

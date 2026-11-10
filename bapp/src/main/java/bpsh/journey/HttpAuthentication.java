package bpsh.journey;

import java.net.URI;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/** Saved destination HTTP identity settings. Passwords and live connections belong to separate owners. */
public record HttpAuthentication(Protocol protocol, String username, String domain, String workstation, Set<URI> origins, boolean enabled) {
    public HttpAuthentication(Protocol protocol, String username, String domain, String workstation, Set<URI> origins) { this(protocol, username, domain, workstation, origins, true); }
    /** Explicit response policy; NTLM2 Session is not NTLMv2. */
    public enum Protocol { BASIC, NTLM_V1, NTLM_V2;
        @Override public String toString() { return switch(this) { case BASIC -> "Basic"; case NTLM_V1 -> "NTLMv1"; case NTLM_V2 -> "NTLMv2"; }; }
    }

    /** Validates executable settings and normalizes explicit origins without resolving names. */
    public HttpAuthentication {
        Objects.requireNonNull(protocol);
        if (username == null || username.isEmpty() || username.length() > 1024 || username.indexOf('\0') >= 0)
            throw new ConfigurationException("httpAuthentication.username: enter a username, up to 1024 characters.");
        domain = domain == null ? "" : domain;
        workstation = workstation == null ? "" : workstation;
        if (domain.length() > 255 || domain.indexOf('\0') >= 0)
            throw new ConfigurationException("httpAuthentication.domain: use a domain up to 255 characters without null characters.");
        if (workstation.length() > 255 || workstation.indexOf('\0') >= 0)
            throw new ConfigurationException("httpAuthentication.workstation: use a workstation up to 255 characters without null characters.");
        if (protocol == Protocol.BASIC && username.indexOf(':') >= 0)
            throw new ConfigurationException("httpAuthentication.username: a Basic authentication username cannot contain a colon.");
        if (origins == null || origins.isEmpty() || origins.size() > 64)
            throw new ConfigurationException("httpAuthentication.origins: choose between 1 and 64 exact server addresses.");
        origins = origins.stream().map(origin -> {
            if (origin == null || origin.getRawQuery() != null || origin.getRawFragment() != null ||
                    (origin.getRawPath() != null && !origin.getRawPath().isEmpty() && !origin.getRawPath().equals("/")))
                throw new ConfigurationException("httpAuthentication.origins: server addresses cannot include a page path, query or fragment.");
            return JourneyOrigins.authenticationOrigin(origin);
        }).collect(Collectors.toUnmodifiableSet());
    }

    /** Checks the full scheme/host/port permission, never a suffix or redirect-derived permission. */
    public boolean allows(URI uri) { return origins.contains(JourneyOrigins.authenticationOrigin(uri)); }

    /** Avoids exposing account and destination configuration in incidental diagnostics. */
    @Override public String toString() { return "HttpAuthentication[protocol=" + protocol + ", origins=" + origins.size() + "]"; }
}

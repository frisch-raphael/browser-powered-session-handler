package bpsh.authentication.http;

import bpsh.journey.HttpAuthentication;
import bpsh.journey.JourneyDefinition;
import java.net.URI;
import java.time.Instant;
import java.util.Objects;

/** Immutable observation of a completed exchange, never a transferable authenticated connection. */
public record HttpAuthenticationEvidence(HttpAuthentication.Protocol protocol,Status status,URI origin,
        JourneyDefinition.Identity observedIdentity,long epoch,Instant observedAt,int httpStatus,boolean applicationAuthorizationConflict) {
    public enum Status { UNCONFIRMED, ACCEPTED, REJECTED }
    /** Test and non-HTTP adapters may carry a protocol result without transport attribution. */
    public HttpAuthenticationEvidence(HttpAuthentication.Protocol protocol,Status status) {
        this(protocol,status,null,null,0,Instant.EPOCH,0,false);
    }
    public HttpAuthenticationEvidence {
        Objects.requireNonNull(status);Objects.requireNonNull(observedAt);
        if(status==Status.ACCEPTED && protocol==null || epoch<0 || httpStatus!=0 && (httpStatus<100 || httpStatus>599))
            throw new IllegalArgumentException("Invalid HTTP authentication observation.");
    }
    public HttpAuthenticationEvidence attributed(JourneyDefinition.Identity identity,long epoch) {
        return new HttpAuthenticationEvidence(protocol,status,origin,identity,epoch,observedAt,httpStatus,applicationAuthorizationConflict);
    }
}

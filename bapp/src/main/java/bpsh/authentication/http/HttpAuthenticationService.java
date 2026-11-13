package bpsh.authentication.http;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/** One owned identity/attempt scope, shared by browser ingress and direct-request adapters. */
public interface HttpAuthenticationService extends AutoCloseable {
    interface Delivery extends AutoCloseable {
        CompletableFuture<Response> exchange(Request request);
        @Override void close();
    }
    /** Explicit admission is acquired before transport-owned body allocation. */
    Delivery admit(long deadlineNanos) throws java.io.IOException;
    boolean isOpen();
    /** Fails closed for adapters that do not expose their active delivery ownership. */
    default boolean isIdle() {return false;}
    /** Header values may contain credentials and must never appear in diagnostics. */
    record Header(String name, String value) {
        public Header {
            Objects.requireNonNull(name); Objects.requireNonNull(value);
            if (!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+") || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0 || value.chars().anyMatch(c -> c < 32 && c != 9 || c == 127))
                throw new IllegalArgumentException("Invalid HTTP header.");
        }
        @Override public String toString() { return "Header[redacted]"; }
    }

    enum AuthorizationPolicy { REPLACE_SELECTED, PRESERVE_APPLICATION }
    /** Whether this application request may negotiate authentication or only use already established state. */
    enum ChallengePolicy { CHALLENGE, ESTABLISHED_ONLY }

    /** Immutable bounded application request; the transport never follows redirects implicitly. */
    record Request(URI uri, String method, List<Header> headers, HttpMessageBody body, AuthorizationPolicy authorizationPolicy, ChallengePolicy challengePolicy) {
        public Request(URI uri,String method,List<Header> headers,HttpMessageBody body) {
            this(uri,method,headers,body,AuthorizationPolicy.REPLACE_SELECTED,ChallengePolicy.CHALLENGE);
        }
        public Request(URI uri,String method,List<Header> headers,HttpMessageBody body,AuthorizationPolicy authorizationPolicy) {
            this(uri,method,headers,body,authorizationPolicy,ChallengePolicy.CHALLENGE);
        }
        public static final int MAX_BODY_BYTES = 8 * 1024 * 1024;
        public Request {
            Objects.requireNonNull(uri); Objects.requireNonNull(method); Objects.requireNonNull(body); Objects.requireNonNull(authorizationPolicy); Objects.requireNonNull(challengePolicy);
            if (!method.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+") || body.length() > MAX_BODY_BYTES)
                throw new IllegalArgumentException("Unsupported HTTP request.");
            headers = List.copyOf(headers);
        }
        /** @param replacements New headers only. @return Same request semantics and body with replacement headers. */
        public Request withHeaders(List<Header> replacements) {return new Request(uri,method,replacements,body,authorizationPolicy,challengePolicy);}
        public int bodyLength() { return body.length(); }
        @Override public String toString() { return "HttpRequest[redacted]"; }
    }

    /** Complete response bytes and safe evidence; an over-limit response is a failure, never a truncated success. */
    record Response(int status, List<Header> headers, HttpMessageBody body, HttpAuthenticationEvidence authentication) implements AutoCloseable {
        public Response {
            if (status < 100 || status > 599) throw new IllegalArgumentException("Invalid HTTP status.");
            headers = List.copyOf(headers); Objects.requireNonNull(authentication);
        }
        @Override public void close() {body.close();}
        @Override public String toString() { return "HttpResponse[status=" + status + "]"; }
    }

    default List<HttpAuthenticationEvidence> observations() {return List.of();}

    /** Safe optional destination failure observed by the scope's TLS owner. */
    default bpsh.authentication.AuthenticationFailure failure() {return null;}

    /** Stops admission and aborts this scope's connections and pending work. */
    @Override void close();
}

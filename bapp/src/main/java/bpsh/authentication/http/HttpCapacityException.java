package bpsh.authentication.http;

/** A transient refusal before delivery admission; no application request has been sent. */
public final class HttpCapacityException extends java.io.IOException {
    public HttpCapacityException() {super("HTTP authentication delivery capacity is exhausted.");}
}

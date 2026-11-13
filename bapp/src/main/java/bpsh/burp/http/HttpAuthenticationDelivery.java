package bpsh.burp.http;

import bpsh.journey.JourneyCatalog;
import bpsh.authentication.AuthenticationFailure;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static bpsh.burp.http.SessionRequestProcessor.*;

/** Delivers one explicit HTTP identity request and materializes its actual response. */
public final class HttpAuthenticationDelivery {
    private final JourneyCatalog registry;
    private final NativeTagResolver resolver;
    private final bpsh.authentication.http.HttpIdentityManager httpIdentities;
    /** @param response Actual server response. @param annotations Safe host notes. */
    record Delivery(burp.api.montoya.http.message.responses.HttpResponse response, Annotations annotations) {}
    /** Wires the existing shared HTTP identity owner and dependent capture resolver. */
    HttpAuthenticationDelivery(JourneyCatalog registry, NativeTagResolver resolver,
                               bpsh.authentication.http.HttpIdentityManager httpIdentities) {
        this.registry=registry;this.resolver=resolver;this.httpIdentities=httpIdentities;
    }
    /** Resolves dependent captures, preserves exact origins and returns the actual response once. */
    Delivery deliver(HttpRequestToBeSent original, HttpAuthenticationDirective.Selection directive, int timeoutMs, RequestCapacity.Lease admission)
            throws AuthenticationFailure, ExecutionException, InterruptedException {
        if (httpIdentities == null) throw configuration("HTTP authentication is unavailable.", "Reload the current extension build.");
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        JourneyCatalog.Entry entry;
        try { entry = registry.snapshot().resolve(directive.alias()); }
        catch (IllegalStateException unavailable) { throw configuration("The HTTP authentication journey is missing or ambiguous.", "Choose one available saved journey alias."); }
        if (entry.definition().draft()!=null) throw configuration("This journey has incomplete settings.","Complete the journey settings and save before using request authentication.");
        if (!entry.definition().transportAuthenticationEnabled()) throw configuration("Request authentication is not enabled for this journey.", "Enable HTTP authentication or a client certificate and save the journey.");
        admission.bind(List.of(entry.identity().key()));
        var selection = httpIdentities.select(entry);
        try (var captures = resolver.resolve(entry.definition().httpAuthenticationEnabled() ? directive.request() : directive.applicationAuthorizationRequest(), null, false)) {
            NativeTagResolver.Resolved resolved;
            try { resolved = captures.future().get(Math.max(1,deadline-System.nanoTime()), java.util.concurrent.TimeUnit.NANOSECONDS); }
            catch(java.util.concurrent.TimeoutException timeout) { throw new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,
                    AuthenticationFailure.Cause.TIMEOUT,"The tagged request timed out while waiting for dependent credentials. No HTTP-auth request was sent."); }
            byte[] complete = resolved.commit();
            return deliverResolved(original,original.annotations(),selection,complete,deadline,admission,resolved::validate,()->{},bpsh.authentication.http.HttpAuthenticationService.ChallengePolicy.CHALLENGE);
        }
    }

    /** Final publication validation belongs to the capture/replay owner. */
    @FunctionalInterface interface Validation {void check() throws AuthenticationFailure;}

    /** Uses the same framing, origin, admission and native delivery for explicit and automatic identity selection. */
    Delivery deliverResolved(HttpRequest original,Annotations notes,bpsh.authentication.http.HttpIdentityManager.Selection selection,
                             byte[] complete,long deadline,RequestCapacity.Lease admission,Validation validate,Runnable onDispatch,bpsh.authentication.http.HttpAuthenticationService.ChallengePolicy challengePolicy)
            throws AuthenticationFailure,ExecutionException,InterruptedException {
        var entry=selection.entry();
        if(httpIdentities==null)throw configuration("HTTP authentication is unavailable.","Reload the current extension build.");
        admission.bind(List.of(entry.identity().key()));
        try {
            HttpRequest request = HttpRequest.httpRequest(original.httpService(), ByteArray.byteArray(complete));
            java.net.URI target = java.net.URI.create(request.url());
            var service = request.httpService();
            java.net.URI actual;
            try { actual = new java.net.URI(service.secure() ? "https" : "http", null, service.host(), service.port(), null, null, null); }
            catch (java.net.URISyntaxException invalid) { throw configuration("Invalid tagged request destination.", "Correct the target server."); }
            if (!bpsh.journey.JourneyOrigins.authenticationOrigin(target).equals(bpsh.journey.JourneyOrigins.authenticationOrigin(actual)))
                throw configuration("The tagged request URL does not match its target server.", "Use the same scheme, host and port.");
            try {
                String host=request.headerValue("Host");
                var declared=java.net.URI.create(actual.getScheme()+"://"+host.trim());
                if(declared.getUserInfo()!=null || declared.getRawPath()!=null && !declared.getRawPath().isEmpty() || declared.getRawQuery()!=null || declared.getRawFragment()!=null ||
                        !bpsh.journey.JourneyOrigins.authenticationOrigin(declared).equals(bpsh.journey.JourneyOrigins.authenticationOrigin(actual)))
                    throw new IllegalArgumentException();
            } catch(IllegalArgumentException|NullPointerException invalid) {throw configuration("The Host header does not match the tagged request destination.","Use the same host and port.");}
            var headers = new java.util.ArrayList<bpsh.authentication.http.HttpAuthenticationService.Header>();
            for (var header : request.headers()) headers.add(new bpsh.authentication.http.HttpAuthenticationService.Header(header.name(), header.value()));
            boolean dispatched=false;
            bpsh.authentication.http.HttpAuthenticationService.Delivery deliveryLease;
            while(true) {
                validate.check();
                long left=deadline-System.nanoTime();
                if(left<=0)throw new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,AuthenticationFailure.Cause.TIMEOUT,
                        "The request deadline expired while waiting for native HTTP authentication capacity.","Retry after active requests finish.");
                var opening=httpIdentities.admit(selection,deadline);
                try {deliveryLease=opening.get();break;}
                catch(InterruptedException interrupted) {
                    opening.thenAccept(bpsh.authentication.http.HttpAuthenticationService.Delivery::close);
                    opening.cancel(true);throw interrupted;
                } catch(ExecutionException failure) {
                    if(!(failure.getCause() instanceof bpsh.authentication.http.HttpCapacityException) ||
                            challengePolicy!=bpsh.authentication.http.HttpAuthenticationService.ChallengePolicy.CHALLENGE)throw failure;
                    java.util.concurrent.TimeUnit.NANOSECONDS.sleep(Math.min(left,50_000_000L));
                }
            }
            try(var admitted=deliveryLease;
                var builder=httpIdentities.bodies().builder(bpsh.authentication.http.HttpAuthenticationService.Request.MAX_BODY_BYTES)) {
                int offset=0;
                for(int index=0;index+3<complete.length;index++)if(complete[index]==13 && complete[index+1]==10 && complete[index+2]==13 && complete[index+3]==10) {offset=index+4;break;}
                if(offset==0)throw configuration("Invalid tagged request body framing.","Correct the HTTP headers.");
                builder.append(java.nio.ByteBuffer.wrap(complete,offset,complete.length-offset));
                try(var ownedBody=builder.finish()) {
            var outbound = new bpsh.authentication.http.HttpAuthenticationService.Request(target, request.method(), headers, ownedBody,
                    bpsh.authentication.http.HttpAuthenticationService.AuthorizationPolicy.REPLACE_SELECTED,challengePolicy);
            validate.check();dispatched=true;onDispatch.run();
            var delivery = admitted.exchange(outbound);
            bpsh.authentication.http.HttpAuthenticationService.Response response;
            try { response = delivery.get(); }
            catch (InterruptedException interrupted) {
                delivery.cancel(true); Thread.currentThread().interrupt();
                throw new AuthenticationFailure(AuthenticationFailure.Phase.PROXY, AuthenticationFailure.Cause.CANCELLED,
                        "HTTP authentication was interrupted; the request may have reached the server.",
                        "Check the server-side result before resending a state-changing request.");
            }
            catch (ExecutionException failed) {
                if(failed.getCause() instanceof bpsh.authentication.http.HttpDeliveryFailure safe) throw safe.presentation();
                if(failed.getCause() instanceof java.util.concurrent.TimeoutException) throw new AuthenticationFailure(
                        AuthenticationFailure.Phase.PROXY,AuthenticationFailure.Cause.TIMEOUT,
                        "The HTTP request timed out; delivery could not be confirmed.",
                        "Check the server-side result before resending a state-changing request.");
                throw new bpsh.authentication.http.HttpDeliveryFailure(true, failed).presentation();
            }
            try(response;var wire=HttpAuthenticationResponse.wire(httpIdentities.bodies(),request.method(),response)) {

            String observation = !entry.definition().httpAuthenticationEnabled() ? "Request sent with this journey's client-certificate settings. Server response kept." : switch(response.authentication().status()) {
                case ACCEPTED -> "The server accepted " + switch (response.authentication().protocol()) { case BASIC -> "Basic"; case NTLM_V1 -> "NTLMv1"; case NTLM_V2 -> "NTLMv2"; } + " HTTP authentication. Server response kept.";
                case REJECTED -> "The server rejected HTTP authentication. Server response kept.";
                case UNCONFIRMED -> "The server response was kept; HTTP authentication could not be confirmed.";
            };
            observation = "Journey " + entry.definition().canonicalAlias() + ": " + observation;
            observation += " HTTP " + response.status() + ".";
            if(!registry.snapshot().isCurrent(entry.identity())) observation += " The journey changed after dispatch.";
            appendNote(notes, observation);
            return new Delivery(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(ByteArray.byteArray(wire.borrowed())), notes);
            }
                }
            } catch(java.io.IOException capacity) {throw new AuthenticationFailure(AuthenticationFailure.Phase.QUEUE,AuthenticationFailure.Cause.CAPACITY,
                    dispatched?"The HTTP response could not fit within the transport buffer limit. The request may already have been applied.":"The HTTP request could not fit within the transport buffer limit.",
                    dispatched?"Check the server-side result before resending.":"");}
            catch (RuntimeException error) {
                if (dispatched) throw new bpsh.authentication.http.HttpDeliveryFailure(true, error).presentation();
                throw error;
            }
        }
        catch(AuthenticationFailure failure){throw failure.journey()==null?failure.forJourney(entry.identity()):failure;}
    }


    /** @param notes Existing user notes. @param message Safe outcome. */
    private static void appendNote(Annotations notes,String message) { SessionRequestProcessor.appendNote(notes,message); }
}

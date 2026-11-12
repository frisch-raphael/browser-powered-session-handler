# Burp request handling

## Overview

Adapts global/Proxy hooks to credential acquisition, tag expansion, automatic injection and attributed recovery replay.

## Interface

- [Diagnostics](./Diagnostics.java): Produces actionable request outcomes while suppressing repeated safe cycle warnings for five seconds.
- [SessionHandling](./SessionHandling.java): Composes shared processing, thin adapters and owned replay lifecycle.
- [SessionRequestProcessor](./SessionRequestProcessor.java): Owns atomic ordinary/tagged preparation and safe failure policy.
- [GlobalHttpSessionAdapter](./GlobalHttpSessionAdapter.java): Delivers direct identities and processes non-Proxy traffic.
- [ProxyHttpSessionAdapter](./ProxyHttpSessionAdapter.java): Uses final interception edits and actual incoming listener metadata.
- [HttpAuthenticationDelivery](./HttpAuthenticationDelivery.java): Materializes the actual response for explicit HTTP identity delivery.
- [RecoveryReplayDelivery](./RecoveryReplayDelivery.java): Owns bounded one-time application replays without rematching listener rules.
- [RequestExchange](./RequestExchange.java): Keeps callback families and their numeric IDs distinct.
- [RequestRuleMatcher](./RequestRuleMatcher.java): Compiles one immutable URL/port matching plan.
- [RequestControlState](./RequestControlState.java): Publishes source controls and their matching plan atomically after persistence.
- [ProxyListeners](./ProxyListeners.java): Exports existing listener settings and parses actual incoming ports without inference.
- [RequestCapacity](./RequestCapacity.java): Shares callback admission and conservative request-copy reservations.
- [HttpAuthenticationDirective](./HttpAuthenticationDirective.java): Consumes one BPSP-HTTP-AUTHENT journey selection and validates direct delivery before dispatch.
- [HttpAuthenticationResponse](./HttpAuthenticationResponse.java): Materializes a bounded, owned response for the originating Burp tool.
- [NativeTagParser](./NativeTagParser.java): Parses only bounded native references/wrappers; token output is data and is never parsed again.
- [NativeTagResolver](./NativeTagResolver.java): Builds atomic byte-preserving request replacements before any Burp hook commits or records provenance.
- [SessionRecovery](./SessionRecovery.java): Coordinates attributed, single-use recovery replays with bounded retention and linear-time RE2 matching.

## Invariants

NativeTagResolver.java:Resolved.commit rechecks publication before insertion. SessionRecovery.java consumes attribution once and never replays a replay. Diagnostics.java accepts already sanitized failures. RequestExchange includes the callback family; numeric IDs are never joined across families. The Proxy adapter processes ordinary browser traffic after user interception edits, while global handling owns explicit HTTP identity delivery. Successful Proxy output is never expanded again. Control syntax cannot be created by captured credential data. Recovery records and pending replay plans share the 10,000-record/five-minute limit; replay templates retain their separate 4 MiB per-request and 32 MiB aggregate byte limits.

Failed tagged Proxy processing requests native DROP on a best-effort basis. The
tested Burp host may still forward the original unresolved request; this is an
[accepted limitation](../../../../../../docs/designs/session-handling-by-url-and-proxy-port.md#proxy-failure-policy-native-drop-is-best-effort).
No stop header, diagnostic-ticket bridge or second credential pass is used.
Global-owned requests retain their native global drop behavior.

HTTP identity selection captures the journey generation and epoch before waiting
for explicit token references. It removes all competing Authorization headers,
admits transport work before copying a body, and returns the actual server response
through Montoya spoofing. Failed delivery never falls back to sending the original
request. Automatic Wait for login/Send immediately policies do not govern this tag.

## Side Effects

Replaces/annotates outgoing requests, retains bounded replay templates and sends authorized replays through the injected transport.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).

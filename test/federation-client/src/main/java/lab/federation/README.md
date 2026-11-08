# Federation application Java package

## Overview

Run-owned Spring client and resource roles use maintained OIDC, SAML and JWT implementations with dedicated TLS trust.

## Interface

- [`FederationApplication.java:FederationApplication.Settings`](./FederationApplication.java): validates run/case/generation identity, named HTTPS origins and required private settings; main accepts --settings PATH.
- [`FederationClientEndpoints.java:FederationClientEndpoints`](./FederationClientEndpoints.java): /spa-config, /spa, /spa/callback, POST /session, /me, POST /logout-client, /combined, /backend-complete, /saml-complete and the case-scoped simulated token-error route.
- [`FederationEndpoints.java:FederationEndpoints.identity`](./FederationEndpoints.java): resource role GET /api/me returns safe validated token identity.
- [`FederationControl.java:FederationControl`](./FederationControl.java): authenticated versioned stop, snapshot, federation-control and gate-release operations on a separate loopback listener; awaitClosed waits for terminal cleanup.
- [`FederationSecurity.java:FederationSecurity.providerDecoder`](./FederationSecurity.java); [`FederationSecurity.java:FederationSecurity.accessTokenValidator`](./FederationSecurity.java): scoped RS256 provider key retrieval and API access-token claims policy.
- [`FederationOAuth.java:FederationOAuth.security`](./FederationOAuth.java): package-private maintained backend OIDC, S256 authorization and client filter chain.
- [`FederationSaml.java:FederationSaml.registrations`](./FederationSaml.java); [`FederationSaml.java:FederationSaml.authentication`](./FederationSaml.java): package-private owned metadata and maintained OpenSAML validation.
- [`FederationProtocol.java:FederationProtocol.arm`](./FederationProtocol.java): package-private code-expired and client-publication-hold controls for their exact prepared cases.

## Invariants

- Settings and material remain bounded, closed-field and run-directory owned; client/resource/provider ports are distinct named HTTPS endpoints. [`FederationApplication.java:FederationApplication.readSettings`](./FederationApplication.java); [`FederationApplication.java:FederationApplication.ownedInput`](./FederationApplication.java)
- Resource access is bearer-only and stateless; access tokens require expiry, issued-at, subject, authlab-api audience and Bearer claim type. [`FederationSecurity.java:FederationSecurity.resourceChain`](./FederationSecurity.java); [`FederationSecurity.java:FederationSecurity.accessTokenValidator`](./FederationSecurity.java)
- LAB_CLIENT is an opaque 90-second session cookie; /combined requires the exact associated validated token bytes, subject and provider session. [`FederationClientEndpoints.java:FederationClientEndpoints.store`](./FederationClientEndpoints.java); [`FederationClientEndpoints.java:FederationClientEndpoints.selected`](./FederationClientEndpoints.java); [`FederationClientEndpoints.java:FederationClientEndpoints.combined`](./FederationClientEndpoints.java)
- Backend login publishes its cookie only after separate API acceptance; SAML publishes no OAuth token. [`FederationClientEndpoints.java:FederationClientEndpoints.backendCompleted`](./FederationClientEndpoints.java); [`FederationClientEndpoints.java:FederationClientEndpoints.samlCompleted`](./FederationClientEndpoints.java)
- Readiness follows ApplicationReadyEvent; control mutation requires the private bearer key and current generation. Held protocol gates have a five-second bound and release on context closure. [`FederationControl.java:FederationControl.onApplicationEvent`](./FederationControl.java); [`FederationControl.java:FederationControl.handle`](./FederationControl.java); [`FederationProtocol.java:FederationProtocol.checkpoint`](./FederationProtocol.java)

## Side Effects

- Starts HTTPS application and private HTTP control listeners, writes private readiness records and closes the application on authenticated Stop. [`FederationApplication.java:FederationApplication.main`](./FederationApplication.java); [`FederationControl.java:FederationControl.publish`](./FederationControl.java); [`FederationControl.java:FederationControl.close`](./FederationControl.java)
- Uses run-local CA trust for provider metadata/keys, code exchange, user info and protected API requests. [`FederationApplication.java:FederationApplication.trust`](./FederationApplication.java); [`FederationOAuth.java:FederationOAuth.requests`](./FederationOAuth.java); [`FederationSaml.java:FederationSaml.registrations`](./FederationSaml.java)
- Maintains bounded in-memory client sessions, sets/clears secure HttpOnly cookies and emits safe protocol events. [`FederationClientEndpoints.java:FederationClientEndpoints.store`](./FederationClientEndpoints.java); [`FederationClientEndpoints.java:FederationClientEndpoints.logoutClient`](./FederationClientEndpoints.java); [`FederationProtocol.java:FederationProtocol.event`](./FederationProtocol.java)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp :federation-client:test --offline
```

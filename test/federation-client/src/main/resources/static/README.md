# Federation browser client

## Overview

Official prepared Keycloak adapter drives the browser fixture; application proofs compare client/API credentials.

## Interface

- [`spa.js:adapter.init`](./spa.js): loads /spa-config, selects browser or cookie-verifier client and starts S256 authorization; optional broker hint selects upstream-saml.
- [`spa.js:fail`](./spa.js): renders a fixed sign-in failure stage.
- [`spa.html:login-status`](./spa.html): login/client/API/combined proof markers consumed by the module.

## Invariants

- Client/API subject, tokenId and providerSessionId must agree; /combined must return the same issuanceId. [`spa.js:client`](./spa.js); [`spa.js:resource`](./spa.js); [`spa.js:pair`](./spa.js)
- Upstream cookie verification requires configured upstreamUrl and a nonempty userinfo subject. [`spa.js:upstream`](./spa.js); [`spa.js:verified`](./spa.js)

## Side Effects

- Writes sessionStorage selection and DOM proof markers; adapter authorization navigates to the provider and fetches session/API/combined or userinfo routes. [`spa.js:selectedClient`](./spa.js); [`spa.js:adapter.init`](./spa.js)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp authLabFederationTest --offline
```

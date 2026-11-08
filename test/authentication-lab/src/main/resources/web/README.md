# Controlled browser pages

## Overview

Browser-side behavior for the canonical fixture application.

## Interface

- [`fixture.js:start`](./fixture.js): binds login, fresh-state, popup/frame, CORS and worker UI flows using body data attributes.
- [`service-worker.js:fetch listener`](./service-worker.js): forwards only the /surface/sw/token fixture request to the generation-bearing upstream token route.
- [`login.html:body[data-case-root]`](./login.html): server-filled page template; LoginFlows.page supplies root, generation, content and script URL.

## Invariants

- All helper URLs carry the current case generation; popup/frame completion requires the expected same-origin message source. [`fixture.js:url`](./fixture.js); [`fixture.js:start`](./fixture.js)
- Fresh-state observations complete before the login form is revealed; page telemetry contains surface/stage values. [`fixture.js:start`](./fixture.js); [`fixture.js:marker`](./fixture.js)

## Side Effects

- Mutates DOM markers, local/session storage and service-worker registrations; submits application HTTP requests. [`fixture.js:start`](./fixture.js)
- Worker install/activation calls skipWaiting and clients.claim; selected fetches are served via fetch(upstream.href). [`service-worker.js:install listener`](./service-worker.js); [`service-worker.js:activate listener`](./service-worker.js); [`service-worker.js:fetch listener`](./service-worker.js)

## Verification

From the repository root, with Java 21:

```powershell
.\bapp\gradlew.bat -p bapp authLabBrowserTest --offline
```

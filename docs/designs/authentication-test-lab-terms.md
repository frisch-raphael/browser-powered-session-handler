# Authentication test lab: terms and examples

> Integrated into main on 2026-11-07. This document preserves the reviewed design and historical phase terminology. Current commands and implementation status are in [the lab guide](../../test/authentication-lab/README.md). Production capture now defaults to this checkout; reviewed owner selection is portable, while exact source manifests and evidence are generated per invocation.

This explains the [implementation contracts](authentication-test-lab-contracts.md). The examples illustrate the proposed tests; they are not claims that the implementation already exists or passes. You do not need to read this whole file first: follow the relevant section when a term is unclear.

## Start with one complete example

Suppose a saved journey should obtain a cookie named `session`.

1. The test application serves a working login page and accepts the fixture user's login, but deliberately omits that cookie.
2. The extension's real browser code performs the saved journey and tries to extract `session`.
3. The automated test checks the extension's actual result and message. They must explain that the selected cookie was not found. A headline saying “Connection failed” must fail this test, even if a detail below it mentions the cookie.
4. A separate condition makes the server refuse the connection. That must produce a connection-related message. Returning the same generic message for both conditions cannot pass.
5. A small Burp check confirms that the loaded extension actually displays the result supplied by that code. It does not repeat every lower-level message combination.

The same distinction applies to success: extracting a cookie is one fact; using that cookie at a protected page and receiving the expected identity is another.

## Tests and what they prove

**Requirement.** Something we want the system to do. Example: “When the selected cookie is absent, identify the missing cookie rather than a connection failure.” The catalog's 980 entries are requirements/assessments, not 980 new test methods.

**Test case or scenario.** A specified situation with inputs, actions and an expected result. Example: log in as `user`, remove the expected cookie from the response, then inspect the extension's result.

**Variant and group.** A variant is one named case within a family; a group collects related cases. Example: `CORE.diagnostics` is the diagnostic family; `missing-cookie` and `connection-refused` are two variants.

**Test assertion.** A check inside a test that fails if a fact is wrong. Example: verify that the returned account is `user`, rather than accepting any HTTP 200. One test execution can contain several assertions. A SAML assertion is a different meaning of the word, explained later.

**Fixture or controlled target.** A test application, user, certificate or prepared state whose behavior we control. Example: our Java login application can deliberately leave out a cookie. It supplies the situation being tested; it does not replace the extension's authentication code.

**Independent expected result, sometimes called an oracle.** The answer used to judge the test, worked out separately from the code being checked. Example: the test deliberately supplies `user2`'s credentials, so it expects `user2`; it does not ask the server's acceptance function what answer to expect. Otherwise the same mistake could make both sides agree.

**Positive control.** A known-valid comparison that must succeed. Example: a correctly signed, correctly addressed SAML response must be accepted before we rely on a negative SAML check.

**Negative control.** A deliberately invalid comparison that must be rejected. Example: omit one required cookie and require denial. A server that rejects everything does not pass just because the invalid request was rejected; its positive control must also succeed.

**Fault injection.** Deliberately introduce a specific problem. Example: close the login listener before connecting, hold a token response, or omit a cookie. This gives us a known cause against which to check the result and message.

**Test layer and owning layer.** Where a check runs, and which layer is responsible for proving that fact. The word “owner” here means responsibility, not a person or access-control role.

| Layer | Concrete example | Fact it establishes |
| --- | --- | --- |
| Fixture check | Send known credentials directly to our test application. | The target accepts/rejects the declared input correctly. |
| Component test | Call the extension's actual request-transforming code with prepared inputs. | Its transformation is correct without needing a running Burp process. |
| Real-runner test | Run the extension's actual browser journey against the Java application. | Navigation, extraction and use of the result work together. |
| Actual-host check | Load the extension in Burp and send a Repeater request. | Burp calls the extension correctly and sends/displays the intended result. |

**Production code, real runner and seam.** Production code is code that will be shipped in the extension. The real runner is that code's browser-journey implementation. A seam is a callable boundary through which a test can exercise it. Example: call the real extractor through its API rather than copying extraction rules into a test script. Missing callable boundaries remain explicit production dependencies.

**Integration or operational test.** A check that runs cooperating pieces and observes their behavior. Example: the real runner logs in, obtains a bearer token and calls the protected API. It is broader than checking a string-formatting function alone.

**Harness and executor.** The harness is the supporting code that prepares, runs and cleans up tests. An executor is the particular code that runs a selected check. Example: JUnit starts the case, the real browser runs the journey, then the harness closes its server and browser.

**Witness, witness ledger and test binding.** A witness identifies the real assertion and input that establish a requirement. The ledger records those links. A test binding connects the requirement to the actual test method and parameter that will run. Example: `CORE.diagnostics.missing-cookie` must point to a real diagnostic test with the matching input, not merely a promising method name. P2 verifies the actual method; no method name is invented here.

**Execution ID and deduplication.** An execution ID identifies one actual test run with its relevant inputs. Deduplication means running it once even if several selections need its result. Example: selecting both `baseline` and `diagnostics` should not run the exact same missing-cookie check twice solely because it belongs to both.

**Propagation witness.** Evidence, owned by a separate browser/transport requirement, that information survives from where the failure occurred to where it is reported. Example: the real browser receives a response without the cookie, and the resulting production message still says “cookie missing.” A formatter-only test cannot establish that the browser supplied the right failure information.

## Choosing tests and understanding their data

**Catalog.** The machine-readable list describing the requirements, inputs, prerequisites and expected observations. Example: `catalog.json` points to `browser.json` and `registry.json`, which contain the selected browser and diagnostic requirements.

**Profile.** A named selection of requirements to run. Example: `diagnostics` selects message checks; `federation` selects the OAuth/OIDC/SAML cases. A profile is not a saved browser profile or a reused cookie jar.

**Baseline or smoke test.** A small first check intended to catch obvious breakage quickly. Example: the proposed 12-entry baseline includes bearer login, cookie login, a cookie-dependent redirect, repeated-tag selection and two contrasting error messages. It does not establish that the whole suite passes.

**Revised contract/profile.** The behavior requiring the agreed changes beyond the predecessor's design. Example: one journey publishes both a cookie and bearer, or a rejected original request is replayed after recovery. The `revised` profile selects those cases; it cannot silently pass while those capabilities are missing.

**Matrix, axis and domain.** A matrix lists the combinations to test. An axis is one choice that varies; its domain is the allowed choices. Example: location has four values—header, path, query and text body—and reference count has three—1, 2 and 3.

**Cartesian product or full combination set.** Every combination of the stated axes. Example: 4 locations × 4 encodings × 3 reference counts gives 48 combinations. It does not mean every imaginable browser/provider configuration.

**Predicate and union.** A predicate is the rule deciding which requirements belong to a selection. A union combines selections without repeating the same member. Example: “all IDs starting with BROW.” selects the browser group; selecting baseline plus browser includes their shared browser cases once.

**Requirement ID prefixes.** `FIX` identifies fixture checks; `BROW` browser cases; `CORE` production component behavior; `RUN` selected real-runner recovery cases; `FED` federation; `TLS` transport; `H01`–`H06` actual Burp families; `CAP` capability assessments. These are labels for this lab, not new authentication protocols.

**Contract, schema, record and closed field set.** A contract states how pieces agree to behave. A data schema states allowed fields/types. A record is one item following that format. A closed field set rejects fields outside that list. Example: `budgetMs` is allowed in a requirement; an accidental `budgetMilliseconds` is rejected rather than silently ignored. This lab format is separate from the extension's native saved-journey format.

**Enum.** A fixed list of allowed labels. Example: an outcome can be `PASS` or `FAIL`, but not an unrecognized value such as `PROBABLY_OK`.

**JSON and JSON Lines.** JSON represents structured data using fields, lists, numbers and strings. JSON Lines stores one JSON record on each line. Example: `report.jsonl` can contain a run-start record, several case results and a final completion record, each on its own line.

**Field notation.** `name:string` means a text field called name; `positive integer` means 1, 2, 3, etc.; `null` means explicitly no value. `List<String>` means a list of text values; `Duration` means a time interval; `UUID` is a randomly generated identifier. These describe data/types, not extra user settings.

**Revision, source hash and parameter key.** A revision identifies a particular version; a source hash is a fingerprint of exact file bytes; a parameter key identifies the input used by a parameterized test. Example: when a test file changes after the audit, its old hash no longer matches, so its binding must be rechecked rather than accepted as current coverage.

**Capability and prerequisite.** A capability is behavior or infrastructure a case needs; a prerequisite is something that must be available first. Example: a real SAML case needs the provider, HTTPS trust and the relevant production runner. A component-only message check may need none of Docker, HTTPS or Burp.

**Blocked versus failed versus not run.** BLOCKED means a prerequisite is missing; FAIL means the check ran and contradicted its expectation; NOT_RUN means the selected check has not been performed. Example: missing replay support is BLOCKED; two replays when only one is allowed is FAIL; an unperformed manual Burp check is NOT_RUN. None is PASS.

**Unsupported versus unassessed.** Unsupported is an evidence-backed capability conclusion; unassessed means we have not established it yet. Example: listing WebAuthn as a candidate does not mean it is supported or unsupported before its assessment.

## Authentication outputs and recovery

**Authentication and authorization.** Authentication establishes who the service recognizes; authorization decides what that identity may do. Example: an application may recognize `user` but deny its admin page. A permission denial alone does not prove a lost session.

**Credential, token, bearer and cookie.** A credential is material used to establish access. Here a bearer token is sent in an Authorization header, and cookies are sent in the Cookie header. Example: a protected endpoint can require both a bearer and `LAB_C1`. “Bearer” means possession is enough for its use; it does not imply the value must be a JWT.

**Opaque token and JWT.** An opaque token is treated as an uninterpreted value. A JWT has structured claims. Example: the controlled target may look up an opaque token in its registry, whereas the resource validates an issuer-signed JWT. Decoding JWT text alone does not verify its signature or grant access.

**Journey, extraction, selection and injection.** A journey is the saved sequence of login actions. Extraction obtains an output; selection chooses the intended output when several exist; injection places it into an outgoing request. Example: complete login, extract the client cookie rather than an IdP decoy, and insert that cookie once into the intended request.

**B, C1, C2 and output role.** These identify the bearer, first cookie and second cookie in the controlled lab. “Role” here describes the credential's place, not an account permission such as admin. Example: supplying C1's value where C2 is required must be detected.

**Issuance and s0–s5.** An issuance is the credential set created by one login. The proposed labels s0/s1 are two logins as user, s2/s3 as user2, and s4/s5 as admin. Example: B from s0 and C1 from s1 belong to the same account but different logins; a strict same-issuance endpoint rejects that mixture. These labels are not the credential values sent over HTTP.

**Credential binding.** A required relationship between credentials. This differs from a test binding. Example: the proposed combined SPA endpoint associates its client cookie with the exact access token used to create that client session; another token for the same account is not interchangeable there. This is a chosen test-application rule, not a claim that all OAuth applications behave that way.

**Atomic publication and atomic request change.** Atomic means all required parts become usable together, or none do. Example: obtaining the bearer while the required cookie is missing must not publish a complete combined result. If one explicit tag cannot resolve, the request must not leave with only the other tags substituted.

**Protected use or protected-access proof.** Actually submit the obtained outputs to a service requiring them and check the identity it recognizes. Example: the API returns user2 when given user2's bearer. Merely finding a cookie after login does not prove this.

**Recovery episode, attempt and retry.** An episode is one shared effort to recover a journey; an attempt is one authentication run within it; a retry is a later attempt. Example: after accepted credentials are revoked, attempt 1 fails with a qualifying temporary network problem and attempt 2 succeeds. The agreed maximum is three attempts total in that episode, including attempt 1—at most two retries. Concurrent callers share that budget. Initial credential acquisition is recorded separately from later recovery.

**Original request and replay.** The original is the request that encountered the configured session-loss response. A replay resends that request after successful recovery with the replacement credentials. Example: eight originals share one recovery and each may receive at most one replay. An original timeout alone does not authorize replay.

**Paused journey.** Automatic acquisition stops for that affected journey after the declared failure. This does not mean all Burp traffic is blocked. With no usable credentials, ordinary traffic follows the unchanged-forwarding warning path; unresolved explicit tags stop their entire request. Explicit Test authentication can start a new bounded cycle; Save does not start a browser or clear pause.

**Native.** This word has two uses here. A native journey/tag is handled by the BApp itself, without the Python API. Native PKCS#11 middleware is machine-installed code used to talk to a token/device. Example: a native tag does not by itself require a smart card.

## Running, controlling and cleaning up a case

**Invocation, run and case.** An invocation is one command such as the Gradle lab task. A run is the environment owned by one executing test process. A case is one selected situation inside it. Example: one command can start two test JVMs, each with a separate run and its own controlled servers.

**LabRun and CaseLease.** Proposed Java objects representing that ownership. LabRun owns the overall environment; CaseLease owns a case's state/resources until close. Example: a try-with-resources block closes the case's held gates and resources even if an assertion fails. A “lease” here is not a payment or a user permission prompt.

**Generation, retired result and stale result.** A generation identifies one prepared version of a run/case. Retired means that version has ended. A stale result arrives from an old version. Example: reset retires generation 4; a delayed callback from generation 4 cannot overwrite generation 5's successful result.

**Checkpoint, gate, arm and release.** A checkpoint is an observable stage; a gate deliberately holds work there. To arm a fault is to prepare it; to release a gate is to let it continue. Example: hold a callback just before code exchange, wait until the test observes it, then release it after the chosen condition. This avoids guessing timing with arbitrary sleeps.

**Snapshot and counter.** A snapshot reads current observations without changing the case. A counter records how many events occurred. Example: a snapshot can report three received requests but zero completed actions. It must not invent browser counts from login requests.

**Budget, deadline and monotonic time.** A budget is the allowed time for startup, work or cleanup; a deadline is when the wait must end. Monotonic time measures elapsed time without wall-clock changes moving the deadline backward. Example: a two-second checkpoint wait still ends after two elapsed seconds even if the computer clock is adjusted.

**Fixture clock.** A clock controlled by the test application for its own expiry decisions. Example: advance it to expire a fixture token immediately. That does not advance Chromium's cookie clock or Keycloak's real clock.

**Idempotent.** Repeating the operation has the same effect as doing it once. Example: releasing an already-released active gate succeeds without releasing a different gate or creating another login.

**Quiescence and cleanup acknowledgment.** Confirmation that the case's work has stopped and its owned resources have settled. Example: no active login worker, retry timer or child browser remains after cancellation. An HTTP handler returning is not enough to establish this.

**Resource ownership and private run descriptor.** Ownership means the harness can prove which processes, files and containers it created. The descriptor is the private file recording them and the control connection. Example: stop the browser process whose creation time and launch record match this run; never kill every Chrome process. A process ID can be reused, so the ID alone is insufficient.

**Control listener and control key.** A separate local interface used by the test driver to prepare/reset/release the application. The key authorizes those controls. Example: a login request can remain stalled while the independent control listener accepts the release command. The browser-under-test must not obtain that key through its normal application pages.

**Loopback and listener.** Loopback addresses, such as 127.0.0.1, lead back to this computer. A listener is a server waiting on an address/port. Example: the lab's reset endpoint listens locally and is separate from the login listener.

**Safe identifier, redaction and sanitized output.** A safe identifier names the account/case/issuance without exposing a credential. Redaction removes sensitive values; sanitized output has been prepared for safe display/reporting. Example: report “user, issuance s0, cookie C1 missing,” without recording a password, raw cookie, PIN or authorization code.

**Completion record and incomplete evidence.** A final report entry confirms that execution and cleanup finished. Example: if the process crashes after a case result but before completion, the run is interrupted, not an overall pass. A null observation means unavailable, not zero.

## HTTP, browsers and certificates

**Endpoint, route, method and callback.** An endpoint/route is an application address; the method says the requested operation. A callback is the address an authentication service returns to. Example: the browser comes back to `/spa/callback` with an authorization code, while `POST /session` creates the client session.

**HTTP status.** The response's numeric outcome indicator. In the proposed controlled targets, 200 means accepted, 400 malformed/forbidden input shape, and 401 missing or unacceptable authentication material. Other applications may use different conventions; the pentester's configured session-loss condition still controls recovery.

**Redirect hop and 303/307.** A hop is one redirect in a chain. The proposed 303 case must continue as GET; the 307 case preserves POST and its body. Example: a missing intermediate cookie must stop the chain rather than allowing the final route to issue credentials anyway.

**Origin versus site.** An origin is the scheme, host and port together. A site is the browser's broader grouping used by rules such as SameSite. Example: two localhost ports are different origins but do not establish a cross-site test; the lab uses distinct named HTTPS sites for that. `IntegrationFixtures.Origin` is also the name of a Java helper, not the definition of a browser site.

**Cookie tuple and selector.** The tuple identifies a cookie by its name/domain/path. A selector says which cookie we want. Example: two cookies both named session at `/` and `/account` can coexist; a name-only selection may be ambiguous.

**Cookie attributes.** Domain/host-only and Path restrict where the browser sends a cookie. Secure restricts sending to secure connections; HttpOnly prevents page JavaScript from reading it; SameSite controls sending in relevant cross-site situations. Example: the SAML POST callback needs a cookie policy that preserves its legitimate transaction state. HttpOnly does not mean the extension's browser-cookie API cannot inspect the cookie.

**CSRF value.** A value linking a submitted form to its intended transaction. Example: the fixture requires both its hidden form value and matching cookie; knowing the form's action URL alone is insufficient.

**Ingress, routed request and completed action.** These are three different observations: bytes reached the listener, an HTTP request reached a route, and an application action completed. Example: a malformed request can send bytes without reaching a route; a rejected POST can reach a route without performing its action.

**Ingress sentinel.** The dedicated listener used to detect any application bytes for a request that should not be sent. Example: a failed explicit tag must produce zero HTTP application bytes there, even if a normal HTTP server would reject those bytes before routing. A TLS handshake is recorded separately.

**TLS, HTTPS, mTLS, CA and trust.** TLS protects a connection; HTTPS is HTTP over TLS. Ordinary server authentication uses a trusted server certificate. mTLS also requests a client certificate. A certificate authority (CA) signs certificates that configured clients can trust. Example: the prepared lab CA signs local server certificates; mTLS cases additionally prove which client certificate the server saw. Neither case should be made to pass by globally ignoring certificate errors.

**Fingerprint and SHA-256 digest.** A digest is a fingerprint of bytes used for comparison. Example: hash a JAR to identify exactly which artifact was tested, or compare the presented certificate's fingerprint with the expected certificate. A file digest by itself is not a digital signature or a login token.

**Self-traffic marker.** The attempt-owned User-Agent suffix used to identify the extension's own proxied authentication traffic. Example: recognize that login request before automatic authentication handling so it does not start another login recursively; handle stripping and responses according to the preserved contract.

## OAuth, OIDC and federation

**Federation.** A login crossing application and identity-service boundaries. Example: the client redirects the browser to Keycloak, then receives the authentication result and creates its own session.

**Identity provider (IdP), client and resource server.** The IdP performs identity-service functions; the client is the application starting the flow; the resource server accepts access tokens for an API. Example: Keycloak is the IdP, the Spring/browser app is the client, and `/api/me` belongs to the resource server. The IdP's cookie and the client's cookie serve different applications.

**OAuth 2.0 and OpenID Connect (OIDC).** OAuth defines ways to obtain/use authorization to access resources. OIDC adds an identity layer. Example: an OIDC login can provide an ID token describing the authenticated user and an access token for an API; those tokens are not interchangeable.

**Authorization code and code exchange.** The code is short-lived material returned through the browser; exchange submits it to the provider to obtain tokens. Example: `/spa/callback` receives a code, then the client exchanges it. A code itself is not the API access token.

**Public and confidential client.** A public client cannot rely on keeping a client secret private, such as browser JavaScript. A confidential client can keep a secret on its backend. Example: browser-client uses PKCE; backend-client keeps its client secret in private server state.

**PKCE, S256 and verifier.** PKCE links the code exchange to the client instance that began authorization. It starts with a verifier and sends a derived challenge; S256 uses SHA-256 for that derivation. Example: after a valid code is issued, exchange with the wrong verifier must fail. The verifier is a secret transaction value, not a user password.

**State and correlation.** State is a transaction value the client checks on return; correlation means matching the reply to the transaction it belongs to. Example: a callback carrying another login transaction's state must not complete the current login.

**Access token, ID token and refresh token.** An access token is intended for the API; an ID token supplies identity information to the client; a refresh token is used at the provider to obtain replacement tokens. Example: sending an ID token to our API must fail even though a valid API access token succeeds. Listing that control does not promise that the extension implements refresh-grant handling.

**Issuer, subject and audience.** Issuer identifies who issued the token; subject identifies the user/entity; audience identifies its intended recipient. Example: a genuinely signed token for authlab-other-api should not be accepted by authlab-api merely because its signature and subject are valid.

**SPA and backend-only exchange.** A single-page application (SPA) runs client code in the browser, so its exchange can be visible in browser traffic. A backend exchange happens on the server. Example: the extension can obtain the SPA's browser-visible output, but should not claim to extract a backend-only token that the browser never receives.

**SSO and selected IdP-cookie proof.** Single sign-on lets an existing identity-service session support another login without re-entering credentials. The selected-cookie proof tests whether that explicitly extracted cookie is sufficient. Example: a separate verifier supplies only the chosen IdP cookie during authorization with prompt=none, meaning no interactive login prompt is allowed; a missing-cookie comparison must fail or require login. A later production journey still starts with fresh browser state.

**Realm and seed.** A realm is an isolated Keycloak configuration containing users/clients; a seed is the prepared initial configuration loaded for the test. Example: import the downstream realm with three fixture users and exact callback URLs so the run starts predictably.

**Broker, upstream, downstream and identity link.** A broker passes login to another identity provider. Here downstream is the provider contacted by the client; upstream is the second provider it delegates to. An identity link says which upstream user corresponds to which downstream user. Example: app → downstream Keycloak → upstream SAML provider → downstream → app. That remains one production journey.

**Metadata and relying-party registration.** Metadata describes protocol endpoints, identifiers and verification keys. A registration configures the client to use/trust those details. Example: the SAML client learns the provider's public verification key; the separate control-only registration instead trusts the fixture key for the isolated message tests.

**Interoperability versus isolated validator control.** Interoperability checks that real implementations work together. A validator control checks how a particular receiving implementation accepts/rejects prepared input. Example: real Keycloak → Spring login establishes interoperability; a locally signed wrong-recipient message isolates Spring's validation. The latter cannot substitute for the former.

## SAML message testing

**SAML and service provider (SP).** SAML is a protocol for exchanging signed authentication information. The SP is the application consuming that result, roughly the client role in the login. Example: Keycloak authenticates the user and the Spring SP establishes its client session cookie. SAML login does not automatically produce an OAuth access token.

**SAML assertion.** The part of a SAML message making claims about authentication/identity, recipient, audience and validity. Example: it can identify user and constrain use to the intended SP for a short interval. This is a protocol object; a test assertion is the check written in the test code.

**ACS and InResponseTo.** The Assertion Consumer Service (ACS) is the SP callback accepting the SAML response. InResponseTo identifies the authentication request it answers. Example: a response for request A must not complete an unrelated request B.

**RelayState.** The transaction-associated value returned along the SAML flow, used here to preserve the intended return location. Example: after login, return to `/me?view=details`, not an unrelated page chosen by an untrusted request parameter.

**Digital signature, signing key and trusted key.** A signature lets a receiver check that signed material came from a holder of the corresponding signing key and was not changed afterward. Example: modifying a signed recipient breaks the signature unless the changed message is signed again with an accepted key. A valid signature does not establish that recipient, expiry and correlation are correct; those need separate checks.

**OpenSAML and signed test message.** OpenSAML is the SAML library used to construct/sign the proposed control messages. Example: build a correctly signed assertion whose recipient alone is wrong, so the test can check recipient validation instead of merely discovering a broken signature. Real positive logins still use Keycloak.

**Control-only key and registration.** A key trusted only by the isolated test registration. Example: the wrong-recipient control message can be cryptographically valid for that test without pretending Keycloak produced it. This does not add a second public identity-provider service.

**Recipient, Destination and audience.** These constrain different parts of where the message/assertion is intended to be used: the subject-confirmation recipient, the response destination and the intended relying party. Example: keep Destination and audience correct while changing only the signed recipient to test that specific condition.

**Validity interval and clock skew.** The interval limits when a message is acceptable; clock skew is the small allowed difference between participants' clocks. Example: with a two-second allowance, make an expired control old enough to remain expired despite that allowance. Otherwise a nominal expiry test could still be valid.

**Mutant or altered test message.** A deliberately changed message. Example: start from one that is accepted, change only recipient, then sign it correctly again. This document uses “altered test message” in explanations.

**Replay control and assertion cache.** A replay control submits already-used material again. An assertion cache is one possible mechanism remembering prior IDs. Example: observing denial of the second submission establishes rejection of that replay, but does not prove whether the receiver used a cache or consumed request correlation. The report must not claim the internal mechanism without evidence.

## Java tooling, shared code and the EGM review

**JDK, JVM and child JVM.** The JDK supplies Java development tools/libraries; a JVM is a running Java process; a child JVM is a separate process started by the test owner. Example: the federation client runs separately so its Spring dependencies/settings do not replace the extension's dependencies in the test process.

**Gradle, wrapper, JUnit and artifact.** Gradle builds/selects tasks; the checked-in wrapper chooses its declared Gradle version; JUnit runs Java tests; an artifact is a built output such as the extension JAR. Example: `.\bapp\gradlew.bat -p bapp authLab` is a planned root-level command; an actual-host check records the hash of the exact JAR loaded into Burp.

**BOM — Bill of Materials.** A version list selecting compatible versions of related libraries. Example: the JUnit BOM aligns its test API, engine and platform modules instead of letting them resolve independently.

**Dependency pin.** A fixed version/fingerprint for a library or image. Example: the proposal names a Keycloak version and image digest so two runs do not silently choose different provider builds. Metadata matching is not proof that those components have compiled or interoperated.

**Spring Boot, Spring Security, Keycloak and OpenSAML.** These are different pieces: Boot starts/configures the Java app; Spring Security supplies authentication/protocol handling; Keycloak is the real identity provider; OpenSAML supplies SAML message operations. Example: the lab uses these maintained libraries/services instead of writing its own general federation implementation.

**PKCS#11 and SoftHSM.** PKCS#11 is the interface for cryptographic tokens such as smart cards. SoftHSM is a software token used for repeatable tests. Example: a SoftHSM mTLS result can establish the software-token case; it does not establish that the user's physical card works.

**Predecessor and P2 audit.** The predecessor is the work being developed in java-playwright. The P2 audit rechecks its actual integrated code/tests before extending them. Example: if its retry test already uses three attempts by then, we reuse it instead of “fixing” an obsolete four-attempt observation.

**Canonical implementation, facade and delegation.** Canonical means the single shared implementation we choose to keep. A facade preserves an existing calling interface; delegation has it call the shared code. Example: P1 builds the lab server; after the P2 audit, an existing Origin test helper can call that server's shared machinery instead of retaining a second copy.

**P0–P5 versus EGM stages.** P0–P5 are proposed future implementation phases: P0 setup/catalog, P1 controlled targets, P2 predecessor integration/audit, P3 federation/transport, P4 revised recovery and Burp acceptance, P5 documentation cutover. EGM Stages 5–9 are reviews of the documents happening now. Example: reaching EGM Stage 9 does not mean P4 has been implemented.

**EGM, fresh reviewer and round.** EGM is the Elephant–Goldfish Model: the drafting assistant retains context, while a fresh reviewer reads explicit documents without the drafting conversation. A round is one set of those reviews plus resolution. Example: three reviewers independently examine the detailed plan, then their duplicate findings are combined.

**Implementation readiness, zero-decision rule and severity.** Readiness asks whether the plan specifies enough to implement without inventing important behavior. The zero-decision rule concerns those design choices, not every variable name. Example: deciding whether two cookies may come from different logins must already be documented. A Blocker prevents proceeding, a Major is a substantial gap to resolve, and a Nit is a minor correction. These document findings are not claims of existing runtime bugs. The review loop needs two consecutive rounds without unresolved Blocker/Major findings; it is not a requirement for zero editorial nits.

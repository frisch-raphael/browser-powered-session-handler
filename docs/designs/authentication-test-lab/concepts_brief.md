# Authentication test lab

* **Author:** rfrisch
* **Date:** 2026-11-04
* **Status:** Author-reviewed design finalized as [authentication-test-lab.md](../../designs/authentication-test-lab.md), pending independent EGM review. Later proxy-scope/reuse instructions are incorporated. The existing-code audit is preliminary and must be rerun at P2. No implementation authorization.
* **Related design:** Read-only source: sibling `java-playwright/docs/designs/bapp-owned-authentication.md`, SHA-256 `B3B6BF5C67886178178B0AACD62F48EA02C12231EE64FF874D60935201D8B5DE`. A hash-identical [repository-local snapshot](sources/bapp-owned-authentication-baseline.md) now preserves that baseline; see [provenance](sources/README.md). This does not imply production implementation in this checkout.
* **Review evidence:** First Goldfish brainstorm report (historical reference): six completed independent lenses, no concept-level blockers; proposed refinements remain unapproved.
* **Follow-up review:** Second-round report (historical reference): six completed independent lenses, no concept-level blockers; remaining concept refinements are documented as parent proposals, not user decisions.
* **Current assistant proposal:** [Delivery and acceptance structure](delivery_proposal.md) supplied the drafting input. Subsequent author decisions are recorded below and in the formal draft (historical reference); unreviewed technical refinements remain proposals.

## Subsequent author decisions during formal drafting

* Assign each assertion to the lowest layer that can establish it using actual production code where extension behavior is claimed. Do not repeat the full lower-layer matrix through Burp. Retain representative integration checks and assertions that depend on the real host.
* Use Java applications and Java/JUnit operational tests, with Gradle owning execution and Keycloak containers supplying real federation. New controlled apps replace the need for Python lab services; preserve existing fixture assets until replacement parity is established.
* Keep acceptance logic independent from production logic. Provide standalone application launch for manual Burp checks, alongside direct lifecycle control from JUnit.
* Exclude all configured upstream proxy-authentication tests, including successful authentication, bad credentials, challenge handling and configuration rejection. Internal authentication on the extension-owned mTLS proxy remains in scope. Retain ordinary proxy routing, CONNECT and no-direct-fallback checks.
* Reuse tests already implemented in the `java-playwright` branch. Map existing assertions to catalog requirements before adding cases; extend only missing assertions instead of recreating covered behavior.
* The sibling implementation is still in progress. Treat the current audit as preliminary and rerun the complete audit at P2 against the actual revision being integrated, before adding or changing production tests, adapters or bindings. Do not keep auditing the live branch during design or treat old gap findings as final.
* The author explicitly overrode the EGM restriction against assistant architecture recommendations. Proposed mechanisms still receive the normal section review.

These decisions resolve the earlier open framework/execution direction. The later [existing-test audit](existing_test_audit.md) identifies actual sibling tests to reuse and gaps to extend; the formal plan (historical reference) and [matrix](implementation_cases.md) carry the updated scope. The two earlier Goldfish rounds did not review this later Java architecture or source-based reuse plan.

## Overview

Prepare local test applications for the BApp-owned authentication replacement. Existing scenarios are spread across multiple apps. The user wants broad coverage of authentication journeys, tagged credentials and automatic injection, with a clear way to establish whether the extension obtained and used the intended credentials.

The primary success check is a protected request that accepts the obtained credentials and confirms the intended identity. Fixture access controls are test instruments: the purpose is to detect extension failures, such as duplicated tokens, identity substitution, lost cookies and incomplete journeys.

## Analysis

Successful login or token extraction alone does not establish that a protected application accepts the result. Fixtures must distinguish the requested identity and credential from whatever the extension actually sends. Distinct journeys must not silently acquire or inject another journey's token. Repeated references to one journey must use a consistent token snapshot within a request.

"Every possible authentication scenario" is the coverage ambition. It is not yet a finite acceptance matrix or a claim that all combinations can be exhausted. Define the supported dimensions, required combinations, failure cases and evidence during clarification and review.

Redirect tests must require the intermediate state they claim to exercise. Merely passing through several redirects does not prove that a journey preserved required cookies.

The previously inspected replacement design selects one automatic-injection journey and either bearer or cookie injection. Automatic bearer AND cookie is a new requested capability; testing it must expose that gap rather than silently treating the existing contract as sufficient.

The author clarified that their examples are starting points and asked the assistant to discover additional checks. [Proposed coverage](coverage_candidates.md) adds independently identified cases, expected evidence, combination strategy and capability boundaries. It remains an assistant proposal for EGM review, not an approved implementation scope. It includes intermediate-cookie replacement, same-account/different-session mixing, wrong token type/audience, backend-only exchange, actual SAML flows, atomic multi-output publication, stale responses, replay fidelity, browser-count evidence, proxy self-traffic and lifecycle checks.

## Goals vs. Non-Goals

### Agreed goals

* Prepare runnable local authentication targets before validating the replacement extension.
* Cover tagged requests and automatic injection without tags.
* Cover one, two and three tags, repeated references and distinct journeys; check for unwanted token duplication and identity substitution.
* Exercise matching and mixed-user credentials to verify which credentials the extension supplied, rather than make fixture segregation the product under test.
* Cover authentication requiring bearer and cookie together, including automatic injection.
* Cover single and multiple redirects, with cookies required between redirects.
* Verify protected-resource access using obtained credentials, not extraction alone.
* Exercise recovery failures, concurrent requests and recursive login traffic so reauthentication cannot produce a browser storm or an endless loop.

### Boundaries

* Continue through EGM clarification, readiness confirmation, Goldfish review and design drafting before more implementation.
* Do not treat the prematurely written `test/auth-lab/lab.py` and `test_lab.py` as an approved architecture or completed deliverables.
* Do not claim fixture-only tests establish real BApp, Burp, packaged-browser or hardware-token behavior.
* Keycloak and its official container image are selected for real protocol scenarios. Client/fixture frameworks, exact deployment topology, migration of existing apps and the finite coverage matrix remain undecided.

## Alternatives Weighed

* **Never replay a request after session-loss detection:** superseded by the author's decision. Automatic session maintenance should recover and replay once when the configured session-loss rule matches.
* **A separate per-journey replay opt-in:** not selected. The author assigns accurate session-loss configuration to the pentester; automatic session maintenance can already be disabled.
* **Assume every status/error indicates session loss:** not selected. Recovery follows the configured session-loss condition; network timeouts alone do not authorize replay.
* **Start implementing a shared Python lab immediately:** premature assistant action, not an author-approved design decision. No framework decision follows from those partial files.
* **Combine credentials supplied by independent journeys for automatic authentication:** rejected by the author. One journey must follow the complete authentication flow and obtain its required outputs. A flow crossing application and identity-provider origins is still one journey.
* **Hand-write an OAuth/SAML identity provider for interoperability coverage:** not selected. The author accepted Keycloak's maintained implementation for actual protocol flows; controlled fixtures remain useful for precise failure injection.
* **Separate Save and test and Retry buttons:** superseded by the author's UI decision. Use Save and Test authentication; explicit testing also retries a paused journey.

## Key Decisions & Staging for Next Steps

### Agreed provider and lab components

The author accepted Keycloak for the real OAuth 2.0/OpenID Connect and SAML scenarios, using its official `quay.io/keycloak/keycloak` container image. Docker is acceptable for this provider-backed part of the developer test lab. This is test infrastructure, not a dependency added to the deployed Burp extension. The exact image version/digest must be pinned during design; using an unpinned `latest` tag is not a selected reproducibility policy.

The selected direction comprises:

* Keycloak preconfigured with test users and OIDC/SAML clients, loaded through a version-controlled realm import rather than repeated manual console setup.
* Small client applications exercising authorization-code login, client-session cookies and SAML login.
* Protected verification endpoints demonstrating that selected cookies/tokens actually authenticate the intended identity.
* Separate controlled fixtures for deliberately broken redirects, missing cookies, temporary network failures and recovery-loop checks.

Complex brokered federation can use an additional Keycloak realm or instance. The number of processes/realms, hostname and HTTPS topology, client libraries, reset mechanism and full startup command remain design choices; provider selection does not establish those details. Ordinary controlled fixtures need not require Docker. A container image supplies the provider, not the client applications or acceptance oracles.

Official capability/setup evidence consulted before selection:

* [Docker quickstart](https://www.keycloak.org/getting-started/getting-started-docker).
* [Supported OAuth/OIDC/SAML protocols and application integration](https://www.keycloak.org/securing-apps/overview).
* [Container setup and startup realm import](https://www.keycloak.org/server/containers).
* [Identity brokering with OIDC/SAML providers](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker).

### Agreed combined authentication and SSO coverage

Do not assemble the automatic bearer-and-cookie credential set from independent journeys. Exercise one complete browser journey spanning the client application and authentication server. The requested scenario redirects from the client application to the authentication server, authenticates there, establishes an authentication-server cookie, returns to the client with an authorization code, establishes the client application's own session cookie, and exchanges the code for an access token. The precise ordering and location of that exchange must match the chosen client architecture; they are not yet specified.

Verify that the authentication-server cookie actually enables SSO, that the client cookie actually grants its intended application access, and that the access token actually grants its intended protected-resource access. Cookie presence or a successful token response alone is insufficient. Keep the identities and login/session ownership associated with those artifacts observable without exposing their values in logs.

The author also requests complex OAuth and SAML scenarios. The described authorization-code exchange is an OAuth-family scenario; a separate SAML scenario needs its own assertion/consumer flow. Keycloak is selected for real protocol interoperability; exact protocol profiles, client implementations and test cases remain to be designed.

The author confirmed that later journey runs must not reuse the prior browser's SSO cookies. Keep the earlier replacement design's fresh browser context for each attempt. The requested SSO-cookie test instead treats the authentication-server cookie as a selectable extracted token: when the user configures that cookie as an output, its value must actually authenticate the expected identity when supplied to the appropriate authentication-server endpoint. Cookie presence in the browser is insufficient. This does not authorize importing cached output cookies into a subsequent authentication browser context.

The lab must distinguish three independently testable output choices from a complete SSO flow: the authentication-server cookie, the client-application session cookie and the API access token. Each must be checked against its intended accepting service. Support the previously requested same-journey bearer-and-cookie combination as well; do not assume every output is required on every destination.

The rejection of independent-journey composition concerns a combined authentication credential set. It does not silently remove the earlier requirement to test multiple tags and distinct saved identities; clarify any overlap during drafting.

### Agreed recovery and replay policy

When automatic session maintenance is enabled and its configured session-loss rule matches, reauthenticate and replay the affected original request at most once. The pentester is responsible for selecting a rule that identifies a lost session and requests rejected before their intended action occurred. Do not add an independent replay opt-in.

* Concurrent affected requests share authentication work for a journey rather than each opening a browser.
* Each original request has at most one replay; a replay cannot recursively replay itself.
* If replacement credentials are also rejected, pause further automatic recovery for the affected journey instead of opening more browsers.
* Owned authentication traffic must not recursively trigger session recovery.
* Keep the initial response and replay observable in Burp so maintenance does not hide evidence.
* A network timeout or lost connection alone does not authorize replay.

### Agreed paused-journey visibility

The author requires a clear indication when a journey has failed and is paused, including that requests depending on it through automatic handling or tags will not authenticate as expected. This establishes the shared journey-level pause across both request paths: new ordinary traffic or tag evaluation must not bypass it by launching another login.

The indication must identify the affected journey, distinguish paused from actively authenticating/retrying, explain the known failure without exposing credentials, and explain how the tester can explicitly recover using Test authentication. It must remain discoverable after the initial failure rather than depend on a transient message or a log the tester might miss. Exact UI layout and status wording remain proposals for drafting; the two actions are agreed below.

Request feedback must distinguish the consequences: with no usable credentials, the ordinary automatic-injection failure path sends the unchanged request with a warning, while an unresolved explicit-tag request is stopped rather than sent with missing or partial substitutions. Show the actual outcome, not an ambiguous universal "request failed" message. Already-sent requests retain their observed original/replay responses; pausing cannot retroactively unsend them.

Candidate acceptance checks include visible journey status after exhausted temporary-network attempts or a rejected recovery replay; affected ordinary/tagged request outcomes; continued traffic producing no extra login; other journeys remaining usable; and an explicit recovery action updating the status. Missing or malformed tags should report the reference/request error rather than falsely mark an otherwise healthy unrelated journey as paused.

Recommended presentation for discussion: a status in the journey list plus persistent failure details for the selected journey, showing safe phase/cause, attempt count, impact on automatic requests and tags, and a Test authentication action. Avoid a blocking popup for every affected request. The placement and presentation are recommendations; the following action semantics are author decisions.

### Agreed save and explicit-test actions

The author selected two separate actions instead of a combined Save and test button:

* **Save** validates and saves journey settings without starting authentication. Saving alone does not clear a failure pause or launch a browser.
* **Test authentication** runs the saved journey explicitly. It is also the action for retrying a paused journey, so a separate Retry button is unnecessary. It permits another bounded authentication cycle and updates the visible status/result; it does not disable the retry limits or permit concurrent duplicate cycles.

Neither action silently resends previously failed Burp requests. Successful extraction is reported as successful authentication/extraction, not as proof that every protected application accepts the result. Protected-resource checks supply that separate evidence.

Candidate checks include Save producing zero login attempts; Test authentication using the saved definition; explicit testing of a paused journey; a failed explicit test returning to a clear paused/error state; and previously failed requests not being replayed merely because Save or Test was pressed. Behavior of dirty editor fields and detailed protected-success/rearming rules remain for drafting.

### Agreed temporary-network-failure allowance

The author selected at most **three authentication attempts total**, including the initial attempt, when failures are positively classified as temporary network failures. This permits at most two retries, not three retries after an initial attempt. During recovery they remain attempts within the same shared recovery episode, not separate recovery episodes or a separate allowance per waiting request.

* Attempts for the same journey run sequentially. Close the previous attempt's owned browser resources before its retry, following the fresh-context rule.
* Concurrent callers join the shared episode and cannot multiply its three-attempt allowance.
* Stop retrying as soon as a complete replacement credential result is obtained. If it is then rejected by the protected application, pause recovery; that rejection does not grant more network attempts.
* Exhausting all three temporary-network attempts does not permit an automatic fourth attempt in the same episode. Without replacement credentials, do not replay the original application request.
* Authentication rejection, missing setup/secrets and other non-temporary outcomes do not qualify for this allowance. Cancellation/unload and the applicable deadlines still stop work; three is a maximum, not a requirement to finish all attempts.

The proposed fixtures should exercise success on attempt two, success on attempt three, three consecutive network failures and concurrent callers sharing that limit. Counts must cover actual attempts and browser cleanup, with continued traffic/timers checked for an unintended fourth attempt. Precise temporary-failure classification and retry delays remain part of the production-design amendment; the author chose the count, not a new backoff schedule.

This changes the earlier replacement design's explicit no-replay contract. Hook feasibility, request/response presentation and attribution require design review and real-Burp verification. The original request template and intended identities must survive recovery; implementation details are not selected here.

### Author addition: user-visible diagnostic accuracy (2026-11-05)

The author requires the displayed outcome to agree with what actually happened. A completed response without the selected cookie must report the missing cookie/extraction failure, rather than “Connection failed.” Extend this principle to summary/details/status, request warnings and actual visible UI output, with correct journey/output/attempt/revision attribution and no exposed secrets. Preserve uncertainty where the cause is not established. Cancellation, exhausted recovery, extraction-only success, confirmed protected access and stale results need distinct, coherent presentation.

The amended [design](../../designs/authentication-test-lab.md#user-visible-diagnostic-accuracy) and [18-case diagnostic contract](../../designs/authentication-test-lab-cases.md#user-visible-diagnostic-contract) specify the proposed bounded coverage and expected meaning. Reuse existing production diagnostic/editor tests and already-owned failure-propagation cases after the mandatory fresh P2 audit. Actual Burp checks establish representative display wiring; the semantic matrix stays below the host. This author addition changes the reviewed document and still needs independent EGM review; it does not claim current implementation support or passing tests.

### Questions still to resolve

* Where does the authorization-code exchange happen, and which resulting credentials are visible to the browser for extraction? How should multiple outputs from one journey be selected by tags and applied automatically?
* Which authentication-server endpoint should demonstrate that an explicitly extracted SSO cookie works, and what evidence establishes the expected identity without another credential submission?
* What constitutes confirmed recovery success and rearms the one-recovery allowance after successful use? Explicit Test authentication is the agreed way to retry a paused journey; Save alone does not resume it.
* What retry delays and precise temporary-network-failure classification should accompany the agreed initial attempt plus at most two retries? The old baseline's three retries after the initial attempt is superseded for this agreed allowance.
* How should recovery attribute failure and coordinate refresh when a request combines credentials from multiple journeys?
* Which browser flows, extraction types, credential placements, encodings, proxy/TLS/mTLS paths and failure combinations form the required matrix?
* The delivery proposal recommends shared recipes for manual checks and automation where each evidence producer exists, with separate real-Burp/UI evidence and separate baseline/revised-contract smoke profiles. The author still needs to align on this proposed delivery/staging boundary and its dirty-editor guard; detailed automation mechanisms belong in the formal design.
* How should the existing apps be retained, consolidated or replaced, and what startup/setup constraints apply?

### Analysis from the first Goldfish review

The concept survives the initial review, but the candidate inventory is not yet a runnable acceptance matrix. The reviewers recommend the following refinements; they are not new author decisions:

* Keep controlled fault/identity fixtures and maintained OAuth/OIDC/SAML implementations as complementary backends under a common catalog, with separate setup and observation adapters.
* Assign invariants to the cheapest authoritative test layer, calculate combination/runtime budgets, and propose a small smoke profile plus focused and broader integration profiles. Preserve explicit exclusions rather than claiming sampled coverage is exhaustive.
* Make required evidence complete and correlated. Distinguish origin ingress, routed requests and successful actions, and require actual browser-resource evidence through a declared observation boundary.
* Use isolated run/case controls, independently responsive gates, explicit clock ownership and repeatable initial/reset state. Advancing a fixture clock is not evidence that a production scheduler or browser expiry changed.
* Independently validate acceptance oracles and their negative controls. A shared recipe generator must not supply both a mistaken rule and the test that declares it successful.
* Make production-contract prerequisites explicit: multi-output selection, automatic combined injection and replay change the approved single-output/no-replay design. Resolve native-format compatibility and host replay feasibility before generating new import examples.
* Reconcile fixture versions before reuse. This worktree contains the older mTLS static-token server, not the enhanced issuer/resource implementation described by the approved sibling design. The partial lab must not be treated as a usable integration baseline.
* Preserve route/account/selector semantics and previous-release examples until their native replacements pass. Keep scenario intent separate from native serialization and provider implementation details.
* Include retained replay data and outstanding request memory in controlled load measurements. Do not replace the approved Unlimited waiter defaults with invented finite defaults.

The first and follow-up reports contain the risks, evidence and recommendations behind these points. The delivery proposal turns them into a candidate structure without promoting them to author decisions. Follow-up refinement separates baseline smoke from new-feature acceptance, deduplicates only equivalent executions, proposes a Save-first guard for dirty editor fields, and includes native managed project/library compatibility alongside exports. Obtain author alignment before finalizing the brief or starting egm-draft. Keep these artifacts separate from the authentication replacement's existing concept/design documents, and keep all future writes in the `test-suite` worktree.

# Proposed delivery and acceptance structure

* **Author:** rfrisch
* **Date:** 2026-11-04
* **Status:** Reviewed assistant proposal awaiting author alignment. No implementation authorization.
* **Inputs:** [Working brief](concepts_brief.md), [coverage candidates](coverage_candidates.md), first review (historical reference), follow-up review (historical reference).

## Read first: what needs your review

**Already agreed:** Keycloak for real OAuth/OIDC/SAML scenarios; combined credentials from one journey; fresh browser contexts; at most three total attempts for temporary network failures; one replay per original request; visible paused journeys; separate Save and Test authentication actions. These are retained requirements, not new choices in this proposal.

**The proposed delivery choices to review are:**

1. **One entry point and scenario catalog**, usable for manual Burp checks and repeatable automation. Each scenario supplies its journey, protected request and expected evidence.
2. **Separate runnable profiles**, so a quick baseline check can finish without claiming that missing combined-output/replay features work. See [Proposed profiles](#proposed-profiles).
3. **Exhaust small controlled combinations; select meaningful end-to-end combinations.** Cover all required behaviors without running every possible cross-product through a browser and every Burp tool. See [Combination strategy](#combination-strategy).
4. **Judge actual protected access and complete evidence.** Check identity/session relationships, actual browser counts, request ingress, actions and replays. A fixture pass alone cannot establish an extension/Burp pass. See [Minimum scenario recipe and result](#minimum-scenario-recipe-and-result) and the [worked example](#worked-recovery-recipe).
5. **Require Save before testing edited settings.** The proposed guard disables Test while edits are unsaved, avoiding a misleading success for older settings. This refinement still needs your agreement.
6. **Stage delivery and preserve working fixtures/data.** Prepare the lab while the production contract is amended, and retire old drivers only after equivalent new coverage passes. See [Staging and preservation proposal](#staging-and-preservation-proposal).

> **Important dependency:** The approved authentication design does not yet include the newly agreed multi-output and replay behavior. Those tests must remain explicitly pending until the production amendment and host checks exist. See [Production-design dependencies](#production-design-dependencies).

**Left for formal design:** exact frameworks, image/version pins, hostname/HTTPS topology, startup commands, native multi-output schema, replay mechanism, recovery-success/rearming rules and retry classification/delays. Approving this direction does not approve implementation or silently settle those details.

## What the tester receives

**One documented lab entry point** should discover available components, show prerequisite failures and start the components needed by the selected profile. A catalog should link each named scenario to its **login URL, selected journey outputs, protected verification request, expected result and evidence**. Startup and reset should be explicit operations; merely restarting Keycloak is not a reliable clean reset.

The same scenario definitions should support manual Burp testing and repeatable automated checks where the required integration exists. Do not require desktop GUI automation to run fixture and browser checks. Native request-hook and UI results require their own actual-extension/Burp evidence; an HTTP script that inserts a token itself cannot stand in for either.

Basic controlled fixtures should run directly. The real-provider profile uses the selected Keycloak container with preconfigured users/clients. Client applications and protected resources remain separate responsibilities even if their startup is coordinated. A second provider realm/instance is proposed for the brokered-flow cases, not for every smoke run. Exact packaging, language/library versions, hostnames and HTTPS setup belong in the formal design.

No existing API runtime is required to execute the future BApp. Developer fixture dependencies are declared separately from the packaged-extension deployment test.

## Proposed profiles

> **Review focus:** This table is the proposed organization of the lab. Profiles group checks for convenience; they do not remove the detailed cases in the coverage inventory.

These are selections from the coverage inventory, not a new reduction of the author's coverage ambition. Every selected profile lists its mandatory cases and prerequisites. A full run reports all profile outcomes without turning a blocked prerequisite into a pass.

| Profile | Purpose and minimum representative coverage | Main evidence |
| --- | --- | --- |
| Fixture contracts | Establish that test targets themselves enforce identity, credential type, session ownership and expiry. Exhaust the bounded credential-subset/substitution dimensions and check all fault controls independently. | Target ingress, routed requests, protected acceptance/action counts; safe account/session/issuance identifiers. |
| Baseline smoke | Establish that the selected available baseline components work: form login, bearer access and cookie access as separate cases, a repeated reference to one supported output, and a cookie-dependent redirect chain. Run only the declared evidence layers for which this profile is selected; it does not stand in for the later revised contract. | Conclude whether those baseline components work, and explicitly identify fixture-only, browser, extension and Burp evidence. Do not report an extension pass when only the fixtures ran. |
| Revised-contract smoke | After the production amendment is implemented, add two/three outputs from one journey, automatic bearer-plus-cookie injection, one successful recovery/replay and a visible paused-journey case. | A separately selected profile with explicit capability prerequisites. Missing revised behavior blocks this profile; a baseline smoke pass does not satisfy it. |
| Browser journeys | Exercise direct/multi-page/JavaScript journeys, mandatory cookie checkpoints, cross-origin and genuinely cross-site navigation, early/late output issuance, selected extraction modes and fresh contexts. | Actual browser behavior and the real production runner when available; protected-resource verification. |
| Real federation | Use Keycloak for OIDC authorization code with PKCE and actual SAML browser SSO. Include a browser-visible token client and a backend-only exchange client; independently verify IdP cookie, client cookie and API access token where those outputs exist. Add one brokered chain. | Provider/client protocol events plus actual protected acceptance; no fabricated extraction of a backend-only token. |
| Credential selection and transport | Exercise repeated references, separate identities in declared test slots, same-journey required output subsets, same-user/different-login substitution, supported locations/encoding wrappers, invalid references and atomic stopping. | Exact expected versus received output/identity/session relationships. Explicit-tag failures require zero protected-origin ingress. |
| Recovery and load | Exercise one shared recovery, three total attempts for temporary network failure, one replay per original, repeated rejection/paused state, explicit Test authentication, ongoing traffic, late responses, timers, cancellation, limits and unload. | Real attempt/browser/context/process evidence, correlated original/replay traces, pending request/retained-byte measurements and post-completion resources. |
| Burp host and UI | Exercise every supported Burp HTTP tool, tagged versus ordinary outcomes, editable repeated templates, original/replay visibility, self-traffic through the proxy and the visible paused journey/Save/Test controls. | Actual supported Burp host and extension; manual or automated execution clearly identified. |
| TLS/proxy/mTLS | Exercise trust failures, explicit HTTP/CONNECT proxy paths, no direct fallback, PKCS#11 identity selection and token-to-resource use, same-CN identities and cleanup. | Real TLS/proxy/provider path. SoftHSM and physical-device results are distinct. |
| Packaged deployment | Load the actual platform JAR offline, verify asset extraction/cache reuse, no Python/system Node requirement, and cleanup across reload/unload. | Actual packaged artifact and claimed platform, not developer-runtime success. |

Profiles are overlapping views of stable scenario IDs. Distinguish a scenario's intent from its required executions against different backends, tools and evidence layers. Deduplicate only equivalent executions with the same relevant case contract, backend/configuration, tool and required evidence; never suppress a real-browser or Burp-tool execution because a fixture execution of that scenario already passed. Unless a case explicitly requires repetition, adding a second profile containing an equivalent execution need not run it twice. Optional physical-device support can be unselected; a selected mandatory browser/provider requirement cannot be silently skipped.

## Combination strategy

> **Review focus:** We need broad coverage without an unmanageable run time. The proposal exhausts small credential/identity combinations cheaply and uses selected browser/provider/Burp combinations for integration evidence.

The inexpensive controlled fixture layer should exhaust a declared small domain: **three accounts, at least two logins for the same account, and a fixture that produces a bearer plus two application cookies**. Test **every nonempty required subset**, every missing member and declared account/session substitutions. This validates the acceptance oracle and provides data for production component tests; it is not evidence of browser or BApp behavior by itself.

Actual browser journeys should cover each flow family and applicable extraction mode. They should include same-journey combined-output publication and repeated references, without multiplying every failure across every provider, wrapper and Burp tool. Preserve explicitly chosen higher-order checks for the interactions most likely to break: brokered redirects with cookies and multiple outputs; concurrent rejection with late responses and refresh; proxy self-traffic during interception; cancellation/unload while a retry is scheduled.

The formal matrix must enumerate case IDs, applicability, expected results and exclusions and calculate case counts and estimated runtime. No runtime budget is claimed measured yet. A protocol case should justify which extension behavior it exercises; exhaustive provider-security conformance is not this lab's purpose.

Do not universally apply the synthetic same-session rules to IdP/client/API cookies across services. Real-provider cases declare the accepting service and what its public interfaces can actually prove. A chosen IdP cookie can be explicitly verified without seeding the next production authentication browser context.

## Minimum scenario recipe and result

Each recipe should define:

* Stable case ID and contract revision; required extension capabilities, fixture/provider version and evidence layers.
* Participating origins and the expected accepting service for each selected output.
* Fresh run/case state, initial login/token state and explicit preparation/reset instructions.
* Journey configuration and request template; expected identities, credential roles and any same-session requirement.
* Ordered actions and observable synchronization points for the scenario, including faults and controlled releases.
* Expected counts for origin ingress, protected actions, authentication attempts, browser resources, original requests and replays, as applicable.
* Observation boundaries and cleanup conditions, with bounded waits and independently responsive controls.

A result should distinguish capability classification, execution outcome and demonstrated evidence layer. It reports **expected versus observed facts**, the earliest known failure and any missing evidence. **Required truncated/incomplete or wrong-run evidence prevents a full pass.** No particular schema, UI framework or tracing product is selected at this stage.

> **New UI proposal to review:** **Disable Test authentication while the selected journey has unsaved changes**, and explain that Save is required first. Associate results with the saved definition/revision actually exercised. If fields change during or after a test, show that those visible edits have not been tested; a stale completion must not label them successful. This is a proposed refinement, not an earlier user decision.

Controls must be isolated by run/case. A fixture clock controls fixture expiry only; it does not advance the production coordinator's monotonic deadlines, browser cookie expiry or Keycloak's clock. Use actual-browser/provider timing where required and deterministic production component clocks where supported. Cleanup retires delayed work so it cannot affect the next case.

## Worked recovery recipe

This example illustrates already selected recovery limits. Exact host hooks and recovery-success classification still require a production amendment.

1. Establish Alice's credentials through the selected journey; use a protected request to prove the expected identity. Record completion of that initial acquisition separately from the recovery being tested.
2. Invalidate the fixture's accepted credential generation. The next original protected request reaches ingress, matches the configured session-loss rule and performs zero fixture actions.
3. Hold that response or the recovery login at declared checkpoints, so additional concurrent rejected requests join the same recovery episode rather than accidentally arriving after it has completed.
4. For the temporary-network variant, fail the first two login attempts and allow the third. Expect **three total sequential recovery attempts, shared across callers**; every previous attempt releases its owned browser resources before retrying. A separate variant fails all three and observes **no fourth automatic attempt** in the episode.
5. When recovery obtains the required complete credential set, **replay each affected original at most once**. For a controlled batch where every original was rejected before release, each original has exactly one replay. The accepting fixture returns the expected identity and performs each permitted action once.
6. In the repeated-rejection variant, reject the replacement set. Observe the journey's **paused indication** and the original/replay responses in Burp. **Continuing traffic, tags and timers must not start more login browsers.** New ordinary/tagged requests show their different agreed failure outcomes.
7. Save an edit and confirm zero new login attempts and no automatic pause reset. Invoke Test authentication explicitly to exercise another bounded cycle. Previously failed requests are not resent just because the tester pressed this action.
8. End at an acknowledged quiescent state and inspect actual owned resource counts. Counting only fixture login hits or checking immediately before a queued timer runs is insufficient.

Use safe correlation identifiers across attempts, issued output sets, selected request slots and replays. Count malformed requests at the ingress boundary, not just in successful resource handlers. Keep passwords, PINs, raw tokens/codes/assertions, reserved markers and credential-bearing URLs out of diagnostic logs.

## Production-design dependencies

> **Review focus:** The following table separates the existing approved design from the changes we agreed during this brainstorm. It prevents the lab from declaring a missing production feature passed by substituting a weaker check.

The selected Keycloak approach can be designed and fixtures prepared without pretending the current BApp implements the new behaviors. Keep these dependencies explicit:

| Contract | Baseline design | Current agreed direction | Consequence for the lab |
| --- | --- | --- | --- |
| Outputs and automatic injection | One extraction; bearer or cookie injection | Same journey supplies required combined credentials; IdP cookie, client cookie and access token independently selectable | New selector/multi-output/native-format contract before importable examples are finalized. Do not compose the automatic set from independent journeys. |
| Lost-session recovery | Invalidate for future demand; no automatic replay | One shared recovery and at most one replay per original when maintenance is enabled and its rule matches | Real-Burp feasibility and original/replay representation must be established before calling these cases accepted. |
| Temporary network failures | Initial attempt plus up to three retries | At most three total sequential attempts, including the initial attempt | Update count expectations and classification/backoff policy; no hidden per-caller or fourth-attempt allowance. |
| Paused journey | Earlier cooldown/retry rules | Visible failed/paused state affecting automatic handling and tags; explicit Test authentication retries it | Test pause bypass, feedback, resource counts and explicit reset. No automatic reset from Save alone. |
| Editor actions | Earlier Save and test plus Retry controls | Save and Test authentication; no separate Save and test/Retry button | Test persistence versus login as distinct actions and verify no implicit resend of old requests. |

The exact meaning of confirmed recovery success/rearming, failure classification and retry delays, multi-output destination rules, dirty-editor behavior and native export compatibility remain explicit questions for the production amendment. This proposal does not silently answer them. Missing capabilities are reported as blocked/pending for the relevant profile rather than weakening the expected result to fit the old code.

Compatibility work must cover managed project data and the shared user library as well as import/export files. The production amendment must state which native-format transitions and mixed-version access are supported, preserve existing files/data on unsupported loads or failed writes, and define rollback after saving the revised format. Add corresponding production storage/integration cases where the versions exist. Do not invent an automatic legacy-API importer, assume an old reader can ignore new outputs, or choose a schema migration mechanism in the lab. The current native baseline is still a design/development dependency; this requirement does not assert that its format has already shipped to users.

## Staging and preservation proposal

> **Review focus:** Agreeing to this sequence lets fixture preparation proceed in its own stage while keeping new native examples and acceptance checks dependent on the corresponding production contracts. Existing working assets remain preserved until replacements are demonstrated.

1. Establish a versioned source/preservation map for existing fixtures and the approved sibling design. Keep certificate data, user token stores and environments unchanged. The mTLS implementation in `test-suite` is older than the implementation described in the sibling design; do not import or merge it blindly. Define native project/library/export compatibility and failure preservation in the production amendment before cutover examples depend on it.
2. Design the catalog, protected acceptance oracles and run-isolated controls. Strengthen or port useful existing routes/forms, retaining distinct semantics for old independent-cookie and new strict same-session cases. Independently test the oracles and negative controls.
3. Add the Keycloak-backed client/provider/resource setups and real-browser checks. Pin versions and automate initial realm provisioning and repeatable reset. Distinguish protocol-backed evidence from synthetic acceptance.
4. After the production contracts and real-Burp replay slice are settled, provide native examples and production/host integration checks. Expand concurrency, failure and lifecycle combinations through named profiles.
5. Retire obsolete API/Hackvertor-specific drivers/examples only after equivalent native coverage passes. Preserve a clear compatible previous-release snapshot and rollback path; do not invent a permanent dual production runtime.

The exact startup CLI, dependency versions, profile manifests and framework/file layout are design-stage work. The prematurely written lab remains unapproved; do not extend it just because its files already exist.

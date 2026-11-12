# Burp Browser with isolated BPSH sessions

Status: proposed design; awaiting user approval. The user selected Burp Browser exclusively, with no fallback, on 2026-11-12. That selection approves the delivery approach, not this design or the existing prototype.

## Intent and success

Reuse the executable installed with Burp to remove Chromium distributions from the extension JAR. Burp's whole-file extension loading has exhausted a 2 GiB heap with the large universal artifact. Compression has not qualified a sufficient repair. Keep one development JAR for Windows x64, Linux x64 and Intel macOS, containing the Java extension and verified native drivers for those targets.

The user's authenticated Burp browser must remain independent. A login, recording, cancellation, failure or extension reload must neither inherit its authentication nor change its state or lifetime. Authentication continues to belong to the Java extension and its existing shared HTTP-authentication/mTLS transport.

Success requires a substantially smaller actual JAR, real journeys and recording using installed Burp Browser, demonstrated account/storage isolation, owned cleanup, and loading/reload qualification of that exact JAR. A blank-page launch or structurally valid foreign-platform resource does not establish those results.

## Approaches and accepted choice

| Approach | Tradeoff | Decision |
| --- | --- | --- |
| Installed Burp Browser only, bundled universal drivers | Removes browser payloads; browser availability and update compatibility become explicit prerequisites | Selected by the user |
| Installed Burp Browser with bundled Chromium fallback | Keeps a pinned alternative but retains the large distribution and its loading cost | Rejected by the user |

There is no system Chrome/Edge fallback, runtime browser download, attachment to a running browser, or automatic downgrade to another installed Burp edition. Reusing a browser executable does not reuse Burp's browser profile, proxy configuration, command-line switches or browser extensions.

## Requirements and boundaries

- Every authentication attempt, recovery attempt and recording launches an owned browser process with a fresh temporary profile and a fresh nonpersistent context. Separate attempts never share browser state. Deliberate token/cookie caching remains in the existing Java journey cache.
- Never attach through CDP or a debugging port, inspect/copy/clear a user's profile, enumerate browser processes to adopt or kill them, or terminate by executable name. Discovery examines installation metadata/files only.
- Keep Chromium sandboxing enabled, per-attempt proxy and trust behavior, traffic provenance, secrets redaction, cancellation/deadlines and existing Windows job ownership. Do not alter security settings to make qualification pass.
- Missing browsers block browser-based login/recording with actionable guidance. Extension loading, editing, existing cached credential use and direct HTTP-only authentication remain available without a browser.
- Unsupported architectures remain unsupported. No new ARM claim, remote-browser support, video recording, browser installer, or general browser-management feature is introduced.
- Work remains in this worktree; no main edits, merge or push. Generated payloads and JARs remain ignored.

## Discovery and selection

Add an installed-browser resolver in `bpsh.browser.runtime`, independent of Swing and Montoya. The composition root supplies current-host installation hints and per-user selection through narrow boundaries. Filesystem enumeration runs on workers within the original setup deadline and cancellation budget.

Resolution order:

1. An explicit per-user Burp Browser executable selection, if configured. It is authoritative: missing/invalid paths report an error rather than silently trying another installation.
2. The installation containing the running Burp application, when identified from current-process launcher/JAR/runtime locations. Inspect known sibling/ancestor `burpbrowser` layouts, not arbitrary recursive parent searches. A globally installed Java runtime alone does not identify Burp's installation.
3. Known Burp installation/browser-cache roots for this platform when the active installation cannot be established. Deduplicate canonical roots. A unique installation may be selected; multiple installations require an explicit selection. If the active installation is established but its browser is missing, report that prerequisite rather than taking a different edition's browser.

Known layouts include Windows per-user and system BurpSuiteDesktop/Pro/Community installs; Linux installer locations and `~/.BurpSuite/burpbrowser`; and Intel macOS application bundles containing either `Burp Browser.app` or `Chromium.app`. Custom VM/install locations are supported through active-installation hints or explicit selection. Keep the candidate roots bounded and fixture-testable. Do not use PATH, shell expansion, registry commands, broad disk scans or live-profile contents as browser discovery.

Within the selected installation, recognize the direct executable layout and numeric version directories. Prefer the numerically newest complete version directory, with deterministic handling of duplicate layouts. Validate an absolute canonical regular executable at a recognized Burp browser location; a file named `chrome` alone is insufficient. Explicit selection permits a custom installation root but must match a supported `burpbrowser`/application-bundle layout. State precisely that this is layout validation, not cryptographic attestation of the installed browser.

Resolve again at the start of every attempt; do not cache the external executable in the verified driver handle. Capture an immutable selection for that attempt. An update/removal during launch fails the attempt safely and does not trigger a credential submission to a different binary. A subsequent explicit action resolves again. Do not retry another binary after launch/protocol failure, and do not invent a Chromium-version compatibility guarantee.

## Per-user settings and errors

Builder proposal: add a small Burp Browser group to the existing Settings page. Automatic detection is the default. A native executable picker supports custom or ambiguous installs, and a Use automatic action clears the override. Show the selected/detected location and a plain explanation that login and recording use separate temporary sessions. Persist the override in Montoya user preferences, never in journeys, project exports or the shared library. Changing it affects subsequent attempts; already running sessions retain their captured selection.

Discovery, validation and status refresh must not block the EDT. Render filesystem paths as literal data and preserve plain accessible descriptions. Use existing native styling and tooltip contracts; add no browser-based configuration interface.

Associate missing/invalid/ambiguous browser selection and confirmed launch prerequisites with this Settings group. Explicit Test login, Retry or recording reveals that page and focuses the executable control; background failures record the result without stealing focus. Never open an error popup for these located failures. Distinguish missing browser, non-executable file, ambiguous installation, confirmed sandbox failure, startup timeout and unclassified launch/protocol failure. Unknown failures must not claim an incompatible browser version without positive evidence. Guidance can suggest updating Burp/BPSH or selecting the intended installation. An invalid explicit selection must remain visible for correction.

## Runtime ownership and isolation

Separate verified driver preparation from installed-browser selection. `BrowserRuntimeManager` retains bounded offline driver extraction/cache validation; an immutable driver-ready handle contains only bundled selectors. The launcher resolves the installed browser and supplies its path through Playwright's `setExecutablePath`. Remove the experimental alternative factory and bundled-browser branch once the production path replaces them.

Continue using the owned Node process and pipe-based Playwright connection, not the globally cached public Playwright factory. Playwright's ordinary `launch` supplies a unique temporary user-data directory under the attempt-owned temporary root; the launcher then creates a new nonpersistent context. Verify that the pinned driver actually supplies that owned profile argument, rather than relying only on context-cookie assertions. There is no production `launchPersistentContext` with a caller-supplied profile, `storageState` import or context reuse. A persistent context exists only as a synthetic control in tests.

Keep the existing shared browser launcher for journeys and recording, including fresh HTTP/mTLS transport scope creation and its proxy. Burp's existing browser proxy/profile settings are irrelevant to that owned launch. Keep credential delivery confined to configured origins and existing transport ownership. Preserve recording's DOM/action capture and replay behavior.

Normal close, stop, timeout, cancellation, startup failure and extension unload close contexts/browser/driver, release transport scopes, and delete only their checked attempt-owned temporary paths. Windows jobs and owned descendant handles remain the process boundary. Cleanup never removes the installed browser or published driver caches and never searches for other processes by name. Concurrent control browsers and other attempts remain usable. Uncertain cleanup is a failed qualification, not an inferred pass.

## Universal driver-only distribution

Replace browser payload preparation with pinned Node/Playwright driver preparation for all three existing targets. The assembled JAR contains no Chromium distribution, browser updater or browser source-download mapping. Retain only helpers required by the pinned driver for supported launch/recording operations; the builder must establish that set from the pinned driver and executable tests. Video recording is outside this product. Preserve licenses, notices and corresponding-source obligations.

Use an explicit driver-only manifest format 3 and resources `META-INF/bpsh/<target>/driver-assets.json` and `driver-assets.zip.xz`. The manifest names the target, pinned Java/JS/Node versions, Node/driver selectors, required helper inventory, compressed/expanded byte counts and hashes, and declared file/link inventory. It does not claim to verify the external browser and contains no bundled-browser selector/version/revision. Update the source lock, schema, producer, consumer and actual-JAR verifier together. Do not retain old manifest readers, browser-download tasks or a second packaging mode.

Reuse the existing bounded streaming XZ/ZIP codecs and private immutable cache publication. Retain exact compressed/expanded/member sizes and hashes, 128 MiB decoder memory ceiling, inventory/path/case/link/mode validation, cancellation/deadline checks and stream/temporary-file ownership tests. Use a driver-specific cache namespace so old large browser caches cannot be accepted as driver caches. Existing old published caches are left alone because another loaded extension can own them; do not migrate or sweep them.

`PLAYWRIGHT_BROWSERS_PATH` points only to an owned driver helper area; it never names Burp's installation or user profile. Keep browser downloads disabled and sanitize inherited Playwright/Node/debug/proxy overrides as today. No global environment, JVM-property or tooltip-default mutation is introduced.

Build directly to `bapp/build/libs/browser-powered-session-handler-dev.jar`. The final verifier requires exactly three driver manifest/archive pairs, bounded decoding of each pair, expected runtime/notice entries and no browser payloads or duplicate driver execution resources. Proposed size gate: less than 128 MiB for the complete universal JAR. This is a design target to verify with actual produced bytes, not a measured claim; exceeding it requires explaining the inventory and revisiting the design rather than silently raising the limit or dropping a platform.

## Verification and delivery gates

1. Unit/component tests cover resolver precedence, all supported layouts, numeric version ordering, canonical aliases, missing/invalid executables, ambiguous editions, authoritative overrides, current-installation isolation, update-between-attempt behavior, deadline/cancellation and settings persistence/error navigation. No test reads real user profiles. Existing architecture, tooltip/injection and literal-rendering guarantees remain required.
2. Preserve and adapt producer/manifest/archive security tests. Verify deterministic driver-only packing, exact modes/inventory, rejected browser content, all three final resources and a cached rebuild. Test the pinned driver ABI and helper assumptions. Unit tests may not silently start installed browsers.
3. Qualify installed Burp Browser with the existing authentication-lab/federation fixtures and real browser integration suite, including extraction, redirects/popups, DOM recording and replay, shared Basic/NTLMv1/NTLMv2 proxy identity, mTLS, cancellation and cleanup. Use existing software-token fixtures for mTLS; physical-token results remain separate. Replace the opt-in experiment suite with maintained production coverage once its assertions are qualified; do not keep a duplicate legacy suite.
4. The isolation regression keeps an owned synthetic persistent A profile/process alive while BPSH performs B login, recording, replay and another fresh attempt. Positively seed and verify A cookies, local/session storage, IndexedDB content, Cache Storage content and an active service worker. Prove fresh BPSH state on the same origins, independent server-observed A/B accounts and unchanged A state/usability after every BPSH close. Add positive witnesses that detect a deliberately reused control context, and verify owned process/profile cleanup, failure/cancellation and concurrent attempts. The existing unexecuted spike is a starting point, not evidence.
5. Resolve the existing lab binding drift using the repository's reviewed `:auth-lab:refreshBindings` process, then run acceptance in a separate invocation. Do not hand-edit fingerprints or weaken evidence checks. The current reproduction is 27 targeted tests, four failures; fixture configuration and declared source hashes are stale, and diagnostics profile source hashes are stale. Review the source closure before refreshing; an updated binding alone does not qualify behavior.
6. Complete `check`, `verifyArchitecture` (also in `check`), native documentation lint, producer checks, lab tests and the canonical development JAR before any Computer Use. Integration execution must load production classes/resources from that actual artifact. Report commands, exact JAR size/SHA-256, target/browser/driver versions and distinct outcomes; no acceptance claim for skipped gates.
7. Coordinate shared VM ownership. Transfer that exact artifact to the existing Windows and Linux VMs and compare SHA-256; directly overwrite the documented stable Windows `C:\bpsh\browser-powered-session-handler-dev.jar`. Refresh each existing Burp extension entry using Loaded off/on. At 2 GiB Burp heap, qualify five unload/reload cycles in one owned PID on each VM with the existing RSS/GC/native-loading-error harness, then a cold browser login with independent fixture evidence and real recording/error-navigation checks. Report the artifact and results, including any failed cycle. Do not use WSL, a larger heap, or a previous artifact as replacement evidence.
8. Package Intel macOS resources and verify them structurally on this host. Native Intel macOS execution requires an available Intel macOS environment and remains explicitly unverified until executed. Separately report the Linux VMware console input path, which is currently unverified; SSH/guest automation is not proof of console input.

## Maintained documentation and implementation scope

Update the user/build guides, product and interface contracts, universal packaging contract, runtime package documentation and docs index with the implemented browser prerequisite and driver-only format. This design replaces the experiment proposal; remove that superseded document rather than archiving it. Replace superseded packaging plans and browser-source assets when their implementation is removed. Retain current tests and attack/resource-loading positive controls, not obsolete browser packaging solely for historical reference.

Expected implementation areas are composition, browser runtime/resolver/launcher, the narrow Settings/preferences boundary, safe error attribution, asset lock/schema/Gradle producer and verifier, their mirrored tests, existing lab bindings and maintained documentation. Journey/authentication/request domain packages acquire no Swing, Montoya or Playwright dependencies, and package dependencies remain acyclic.

The builder chooses internal class names, filesystem adapters, concrete helper files required by the pinned driver, precise injected UI boundaries and test decomposition. Those choices must satisfy the contracts above without adding browser fallback or reducing isolation/qualification scope. Any newly discovered incompatibility that changes these contracts returns for a design decision.

## Current evidence and references

The prototype only selects an explicit installed executable while still preparing the full browser bundle. It has not executed the new isolation test or qualified a smaller JAR. The recorded full build produced a 530,340,132-byte artifact and failed four authentication-lab tests; it is not a successful delivery of this design.

- [Playwright executable selection and compatibility warning](https://playwright.dev/java/docs/api/class-browsertype#browser-type-launch-option-executable-path): an external executable is supported as an option, but arbitrary Chromium compatibility is not guaranteed.
- [PortSwigger PwnFox](https://github.com/PortSwigger/pwnfox-for-chromium#burp-browser-location): prior art for installed Burp Browser discovery and platform layouts, not proof of this extension's compatibility or isolation.
- Existing product, interface, code-structure and VM requirements remain authoritative except where this approved replacement will explicitly update the browser packaging contract.

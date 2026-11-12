# Isolated Burp Browser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace bundled Chromium with isolated installed Burp Browser sessions in one universal driver-only extension JAR.

**Architecture:** Keep bounded verified Node/Playwright resources separate from a per-attempt installed-browser resolver. The shared launcher owns each browser/profile/context; a per-user Settings group supplies an optional executable override and receives located errors. Adapt the existing authentication lab and VM harness for exact-artifact qualification.

**Tech Stack:** Java 21, Montoya 2026.4, Swing, Playwright Java 1.64.0, current pinned JavaScript driver/Node, Gradle Kotlin DSL, JUnit, existing XZ/ZIP codecs and authentication-lab fixtures.

**Spec:** [Approved design](../specs/2026-11-12-burp-browser-design.md). Read it and repository `AGENTS.md` before execution. Execution method and plan review are pending; no product implementation has started.

## Global Constraints

- Burp Browser exclusively, with no fallback. No system Chrome/Edge fallback, runtime browser download, attachment to a running browser, or automatic downgrade to another installed Burp edition.
- Every authentication attempt, recovery attempt and recording launches an owned browser process with a fresh temporary profile and a fresh nonpersistent context.
- Never attach through CDP or a debugging port, inspect/copy/clear a user's profile, enumerate browser processes to adopt or kill them, or terminate by executable name.
- Keep Chromium sandboxing enabled, per-attempt proxy and trust behavior, traffic provenance, secrets redaction, cancellation/deadlines and existing Windows job ownership. Do not alter security settings to make qualification pass.
- Keep one development JAR for Windows x64, Linux x64 and Intel macOS. Unsupported architectures remain unsupported.
- Use driver-only manifest format 3 and resources `META-INF/bpsh/<target>/driver-assets.json` and `driver-assets.zip.xz`. Preserve the 128 MiB decoder memory ceiling. Complete JAR must be less than 128 MiB; measure before claiming it.
- Build directly to `bapp/build/libs/browser-powered-session-handler-dev.jar`; no candidate JAR, committed generated payloads or JARs, main edits, merge or push.
- Run required checks and build that canonical artifact before any Computer Use. Use the existing VMs, exact-artifact checksums, Loaded off/on refresh and stable Windows `C:\bpsh\browser-powered-session-handler-dev.jar`.
- Journey/authentication/request domain packages acquire no Swing, Montoya or Playwright dependencies; keep packages acyclic. Reuse integrated lab/federation fixtures and isolated captured production acceptance.
- Never stage the inherited worktree wholesale. Inspect each task delta; stage new files and authored hunks only. Existing modified/untracked baseline is not this feature's commit scope.

## Review Focus

- Burp updates remove a selected version between attempts: next attempt rediscovers; an in-flight selection fails safely without trying a second binary. Pin in Tasks 1 and 2.
- Shared Java runtimes and side-by-side Burp editions: never mistake Java's installation for Burp or silently select another edition. Pin in Task 1.
- A delayed Settings discovery result arrives after a new selection or unload: discard it and retain the user's latest value. Pin in Task 3.
- Partial browser startup/cancellation leaves an owned child or profile behind: report failed cleanup while the independent control browser remains usable. Pin in Tasks 2 and 4.
- A VM transfer succeeds but Burp loads a stale path or memory evidence misses a cycle: qualification fails despite passing authentication. Pin in Task 6.

---

## File structure and task dependencies

- `bpsh.browser.runtime.BurpBrowserResolver` owns bounded installation/executable discovery. `BrowserExecutableSettings` owns a thread-safe raw override. Neither imports Swing or Montoya.
- Existing `BrowserRuntimeManager`, `BrowserManifestCodec`, `BrowserArchiveCodec` and `PlaywrightDriverAdapter` keep driver verification and process ownership; `BrowserSessionLauncher` composes driver readiness and the selected external executable.
- `bpsh.burp.ui.BrowserRuntimePreferences` bridges Montoya preferences to the settings model. `BurpBrowserSettingsPanel` owns only native presentation/callbacks. `UiController` owns asynchronous work, epochs and navigation.
- Rename browser asset lock/schema/Gradle producer to `driver-assets.*`; update every maintained reference rather than keeping a second mode. Keep runtime Java class names where their responsibility remains valid.
- Maintain runtime tests beside their owners, UI tests beside the UI, and real execution in existing `BrowserJourneyIntegrationTest`/PKCS#11/production overlays. Fold the unqualified `BurpBrowserIntegrationTest` into maintained coverage and remove its experimental task.
- Extend the existing lab host qualification mode for the runtime-specific reload/login evidence; do not implement an independent lab or claim the unfinished broad HOST acceptance suite.
- Tasks execute in order. Task 2 changes the format and every handle/launcher consumer together so its deliverable compiles without temporary compatibility stubs. Refresh source bindings only after the implementation/harness inputs settle.

All commands below run from this worktree in PowerShell with `$env:JAVA_HOME='C:\Program Files\Java\jdk-21'`. Use `.\bapp\gradlew.bat -p bapp`, `--offline --console=plain`; omit offline only for an explicitly needed locked developer dependency download. Poll long commands and keep the user informed. Do not run a second build against a JAR currently being read.

### Task 1: Deterministic installed Burp Browser resolution

**Files:** Create `bapp/src/main/java/bpsh/browser/runtime/{BurpBrowserResolver,BrowserExecutableSettings}.java`; create mirrored `BurpBrowserResolverTest.java`, `BrowserExecutableSettingsTest.java`; update that package's `README.md`.

**Interfaces:** `BrowserExecutableSettings` exposes `String executableOverride()` and `void setExecutableOverride(String value)` (empty means automatic; preserve invalid entered strings). `BurpBrowserResolver` exposes records `Environment(String platform, List<Path> activeInstallations, List<Path> knownInstallations)` and `Selection(Path executable, Path installation, String version, Source source)`, enum `Source { EXPLICIT, ACTIVE_INSTALLATION, KNOWN_INSTALLATION }`, constructor `(Environment environment, Supplier<String> executableOverride)`, static `Environment currentEnvironment()`, and `Selection resolve(long deadlineNanos, BooleanSupplier cancelled) throws AuthenticationFailure`. Add a package-private executability predicate seam for deterministic permission tests.

Core assertions, using test-owned executable files and the original deadline:

```java
assertEquals(explicit.toRealPath(), resolver.resolve(deadline, () -> false).executable());
settings.setExecutableOverride("invalid literal selection");
assertEquals("invalid literal selection", settings.executableOverride());
assertThrows(AuthenticationFailure.class, () -> resolver.resolve(deadline, () -> true));
```

- [ ] **Write failing tests:** `explicitMissingBrowserDoesNotFallBack`, `activeInstallWithoutBrowserDoesNotSelectOtherEdition`, `sharedJavaHomeDoesNotIdentifyBurp`, `multipleKnownInstallsRequireSelection`, `numericVersionsAndCanonicalAliases`, `supportedDirectAndVersionedLayouts`, `rejectsUnrelatedChromeAndNonExecutableFile`, `updateBetweenAttemptsIsRediscovered`, `cancelledAndExpiredDiscoveryStops`. Test-owned directories model each platform; assert exact canonical `Selection.executable()`, precedence/source and typed sanitized failures. Assert settings preserve a literal invalid value and concurrent reads observe complete snapshots.
- [ ] **Run red:** `test --tests bpsh.browser.runtime.BurpBrowserResolverTest --tests bpsh.browser.runtime.BrowserExecutableSettingsTest`. Expect missing new types initially, then genuine assertion failures if scaffolding is needed; no browser starts.
- [ ] **Implement:** use bounded known layouts/numeric immediate children and canonical root deduplication. `currentEnvironment()` examines only the current Burp process/JAR/runtime hints and explicit platform-known roots; no PATH, shell commands or live-profile reads. Resolve the override afresh once per call. Return sanitized `AuthenticationFailure` causes; Task 3 adds the UI input attribution with its matching Settings control. Validate a recognized Burp layout, not executable basename alone. Bound candidate roots/version enumeration and check the original cancellation/deadline while traversing.
- [ ] **Run green:** the two classes above plus `verifyArchitecture`; expect zero failed tests and no package cycles. Review redaction assertions so errors contain neither entered paths nor vendor exception strings.
- [ ] **Commit:** only these new classes/tests and authored package documentation hunks; message `Add isolated Burp Browser discovery`.

### Task 2: Driver-only universal distribution and owned launch

**Files:** Rename `bapp/browser-assets.lock.json` to `driver-assets.lock.json`, `bapp/src/main/resources/browser-assets.schema.json` to `driver-assets.schema.json`, `bapp/gradle/browser-assets.gradle.kts` to `driver-assets.gradle.kts`. Modify `bapp/build.gradle.kts`, `bapp/src/main/java/bpsh/browser/runtime/{BrowserRuntimeManager,BrowserManifestCodec,PlaywrightDriverAdapter}.java`, `bapp/src/test/java/bpsh/browser/runtime/{RuntimeFixtures,BrowserAssetsTest,BrowserArchiveCodecTest}.java`, `test/authentication-lab/src/main/resources/configuration-inputs.json`, `bapp/gradle/auth-lab-production.gradle.kts`. Update source/architecture/capture inventory references found by repository-wide `rg`; include exact affected paths in the task commit. `BrowserArchiveCodec.java` changes only if an actual format dependency requires it.

**Interfaces:** `BrowserRuntimeManager.Ready` provides `root()`, `helperRoot()`, `nodeExecutable()`, `driverEntryPoint()`, `bundleDigest()`; remove browser selection from the handle. Manifest format 3 has `helperRoot` instead of `browserRoot` and removes `browserName/browserVersion/browserRevision/browserExecutable`. Use `helperRoot="driver"` with the existing `driver/node[.exe]` and `driver/package/cli.js` tree. Retain required pinned helper declarations/inventory. Tasks become `prepareDriverAssets` and `verifyDriverAssetProducer`; normal `jar`/`check` depend on them. Cache root becomes `.bpsh/cache/drivers-v3/<target>/<digest>`; completion ownership stays independently validated.

Core assertions on the emitted manifest and actual completed JAR:

```java
assertEquals(3, manifest.get("formatVersion").intValue());
assertNull(manifest.get("browserExecutable"));
assertEquals("driver", manifest.get("helperRoot").textValue());
assertTrue(Files.size(artifact) < (128L << 20));
```

- [ ] **Write failing tests:** adapt tiny manifest fixtures to format 3; `driverManifestRejectsBrowserFieldsAndLegacyFormats`, `driverCacheCannotAdoptBrowserCache`, `driverOnlyProducerRejectsChromiumInventory`, `finalJarRequiresExactlyThreeDriverPairs`. Assert manifest fields/selectors, all three target identities, `< 128L << 20` final byte gate, and no old resource paths or root `driver/` execution resources. Preserve all ZIP/XZ attack, mode, link, resource-loading, stream-ownership and cancellation controls, including unsafe positive controls.
- [ ] **Run red:** `test --tests bpsh.browser.runtime.BrowserAssetsTest --tests bpsh.browser.runtime.BrowserArchiveCodecTest` against the new fixtures; record format/selector failures before consumer changes. Run the synthetic producer with its new assertions and observe rejection of old payload construction.
- [ ] **Implement the coordinated migration:** select only pinned driver/Node source subtrees from verified Maven inputs; keep Java 1.64.0, JS package 1.64.1 and Node 24.22.1 unless inspected source metadata contradicts the existing lock. Inspect the pinned launch code to identify actually required helpers, retain those, and remove Chromium/unused helper source mappings and generated-task inputs. Preserve deterministic XZ/ZIP, source/member hashes, modes, limits, licensing and atomic publication. Update producer and final-JAR verification together, reject browser distributions, remove legacy readers/task names, update isolated capture preparation to the new lock and remove browser-download cache copying. Do not hand-edit catalog bindings yet.
#### Coordinated launcher migration within Task 2

**Additional files:** Modify `bapp/src/main/java/bpsh/{Extension.java,browser/BrowserSessionLauncher.java,browser/BrowserFlowRunner.java,browser/BrowserJourneyRecorder.java,browser/runtime/PlaywrightDriverAdapter.java}`, `bapp/src/test/java/bpsh/browser/{BrowserJourneyIntegrationTest.java,BurpBrowserIntegrationTest.java,mtls/Pkcs11JourneyIntegrationTest.java}`, `bapp/src/test/java/bpsh/support/IntegrationFixtures.java`, `test/authentication-lab/production-tests/bpsh/browser/{BrowserJourneyIntegrationTest.java,FederationJourneyIntegrationTest.java,mtls/Pkcs11JourneyIntegrationTest.java}`, `bapp/{build.gradle.kts,gradle/auth-lab-production.gradle.kts,gradle/auth-lab-production.init.gradle}` as required by their existing captured-plan boundaries. Add focused launcher tests in `bapp/src/test/java/bpsh/browser/BrowserSessionLauncherTest.java` and driver tests in `browser/runtime/PlaywrightDriverAdapterTest.java`.

**Interfaces:** Add resolver injection to `BrowserSessionLauncher(BrowserRuntimeManager runtime, BurpBrowserResolver resolver, HttpTransportFactory httpTransport, AuthTrafficGuard traffic, Clock clock)` and the lifecycle-observer overload, retaining existing caller behavior without a bundled-browser branch. `PlaywrightDriverAdapter.Session.temporaryDirectory()` exposes its owned canonical temporary root for launcher checks/tests, not user-selected state. Composition owns one settings model and resolver. Integration property `-PburpBrowserExecutable=<absolute path>` becomes `bpsh.test.burpBrowserExecutable` and constructs the test resolver explicitly; production never reads a test override. Captured plans carry that test-only path through their strict schemas/launch arguments so separate JVMs do not guess.

- [ ] **Write failing tests:** `resolvesExecutableForEachAttempt`, `selectionIsStableDuringLaunch`, `neverLaunchesSecondBinaryOnFailure`, `browserEnvironmentHasOnlyOwnedHelperAndTempPaths`, `partialStartupCleanupLeavesIndependentOwnerAlone`. Assert one captured selected executable, sandbox enabled, original deadline, distinct per-attempt temporary roots and no user-data/CDP/state-import arguments. Use injected launch/selection seams for unit checks rather than starting a real browser.
- [ ] **Run red:** focused launcher/driver unit tests; assert the missing resolver path and old browser-ready contract fail before changing the launcher.
- [ ] **Implement:** acquire verified driver resources and resolve the installed executable on the worker before submitting credentials; use the existing single shared launch/transport path for journeys/recovery/recording. Preserve proxy and Windows job boundaries. Check the pinned driver's actual generated `--user-data-dir` belongs to the owned temporary root and each launch differs; inspect only owned child metadata in integration evidence. Remove `withInstalledBrowser`/the cached external-browser field. Adapt cold/cache/ABI integration probes and captured overlay constructors/resource assertions to driver-only handles. Ordinary tests remain browser-free.
- [ ] **Run green:** focused runtime/launcher/driver unit tests plus `check verifyDriverAssetProducer verifyArchitecture verifyNativeDocumentation jar`; inspect actual JAR pair inventory, byte size/hash and three successful bounded decodes, then repeat unchanged `jar` to verify cached preparation. Run `browserIntegrationTest -PburpBrowserExecutable=C:/Users/Rapha/AppData/Local/Programs/BurpSuiteDesktop/burpbrowser/156.0.8078.48/chrome.exe --tests bpsh.browser.BrowserJourneyIntegrationTest` against the canonical artifact. Expect nonzero executed tests, no all-skipped success, valid profile/protocol assertions and complete owned cleanup; any actual browser incompatibility or size overrun is a blocker, not fallback/size-limit-change authorization.
- [ ] **Commit:** reviewed format/producer/consumer/capture/launcher changes and authored tests only; message `Use verified universal drivers with isolated Burp Browser launches`.

### Task 3: Per-user Settings and located failures

**Files:** Create `bapp/src/main/java/bpsh/burp/ui/{BrowserRuntimePreferences,BurpBrowserSettingsPanel}.java` and matching tests. Modify `Extension.java`, `burp/ui/{UiController,JourneyDialogs,SwingJourneyDialogs,RememberingFileChooser}.java`, `authentication/AuthenticationFailure.java`, `journey/JourneyRecording.java`, `browser/runtime/BurpBrowserResolver.java`, `browser/{BrowserFailureClassifier,BrowserJourneyRecorder}.java`; adapt exhaustive switches and native UI tests. Read/apply `impeccable`, `ux-copy` and the Swing tooltip contract before implementing the panel/copy.

**Interfaces:** `BrowserRuntimePreferences(Preferences preferences, BrowserExecutableSettings settings)` loads raw `bpsh.browser.executable` and exposes `void select(String value)`; empty clears the preference. `BurpBrowserSettingsPanel(Consumer<String> onOverride, Runnable browse, Runnable useAutomatic)` exposes `setOverride(String)`, `showSelection(BurpBrowserResolver.Selection)`, `showFailure(String)` and `JComponent focusTarget()`; no filesystem calls. Add `JourneyDialogs.browserExecutable(Component parent): Path`. Add `JourneyRecording.Field.BROWSER_EXECUTABLE` alongside `AuthenticationFailure.Input.BROWSER_EXECUTABLE` and map the established classification in the recorder.

Core assertions in EDT tests and the existing dialog spy:

```java
runtimePreferences.select("invalid literal selection");
assertEquals("invalid literal selection", settings.executableOverride());
assertEquals("invalid literal selection", preferences.getString("bpsh.browser.executable"));
assertEquals(0, errorDialogs.size()); // after a located browser failure
```

- [ ] **Write failing tests:** `overrideIsUserLocalAndNeverExported`, `invalidOverrideStaysVisible`, `cancelledPickerDoesNotChangeSelection`, `staleDiscoveryCannotOverwriteNewSelectionOrUnloadedUi`, `explicitBrowserFailureRevealsSettingsWithoutPopup`, `backgroundBrowserFailureDoesNotStealFocus`, `browserPathIsLiteralAndAccessible`. Assert preference clear/load, captured active selection unaffected by later changes, native chooser cancellation, main Settings selection, focused executable control and zero error dialogs for located failures. Include Retry and recording paths as well as Test login; preserve generic popup behavior for unlocated errors.
- [ ] **Run red:** new panel/preferences tests and existing `AutoSaveLoginTest`/recording tests with these cases; expect assertions for absent Settings group/error mapping.
- [ ] **Implement:** reuse the existing worker/UI dispatch and unload guards with an epoch for discovery refresh. Show automatic status, executable path, Browse and Use automatic within native Settings. Keep raw paths literal/plain and errors sanitized; distinguish positive sandbox evidence/startup timeout from unknown launch failures. Map browser prerequisite failures to Settings, never by parsing display strings. Avoid coupling this local preference to project autosave/export or journey validation. Preserve tooltip formatting, caption provenance and plain accessible help.
- [ ] **Run green:** focused panel/preferences/login/recording/classifier tests plus `UiTooltipsTest UiTooltipSecurityTest`, architecture and doclint. Inspect all enum switch consumers via compilation; no new dependency cycle. Defer visible compact/wide/theme verification to Task 6 after the canonical build.
- [ ] **Commit:** only authored settings/error changes and tests; message `Configure Burp Browser and show prerequisite errors inline`.

### Task 4: Qualified isolation regression and fixture reuse

**Files:** Move the useful assertions from `bapp/src/test/java/bpsh/browser/BurpBrowserIntegrationTest.java` into existing `BrowserJourneyIntegrationTest.java`; delete that experiment class and its Gradle integration-task registration/filter. Reuse `IntegrationFixtures`/`HttpAuthenticationFixture` rather than building a second lab. Modify existing runtime cleanup tests only where assertions need the new owned-profile metadata.

**Interfaces:** Production browser integration runs through the Task 2 resolver and exact packaged artifact. Test-only helpers `seedControlState(Page)`, `snapshotControlState(Page)` and `assertEmptyState(Page)` belong to the existing integration class; snapshots include actual IndexedDB record/cache-response contents and active service-worker evidence, not just collection names/counts. The temporary persistent control profile/process is entirely test-owned.

Core assertions around a positively seeded control and fresh attempt, accompanied by server-account checks:

```java
assertThrows(AssertionError.class, () -> assertEmptyState(controlStatePage));
assertEmptyState(freshAttemptPage);
assertEquals(originalControlState, snapshotControlState(controlStatePage));
assertFalse(controlStatePage.isClosed());
```

- [ ] **Write/strengthen failing tests:** `signedInPersistentProfileStaysIsolatedFromJourneysAndRecording`, `reusedControlContextFailsIsolationWitness`, `cancelledAndFailedAttemptsCleanOnlyOwnedProfiles`, `concurrentAttemptsKeepAccountsAndProfilesSeparate`. Seed A cookie, local/session storage, IndexedDB account value, cached response and active worker; prove all positive seeds. B login, DOM recording and replay must start clean on the same relevant origins and produce B in server observations. Assert A's account/state/browser remain unchanged after each operation and a later fresh attempt starts empty. The deliberate reuse positive control must fail the same cleanliness oracle for the seeded state. Assert exact owned PID/profile termination/removal on success, failure, cancellation and unload.
- [ ] **Run red/control:** run the reused-context witness and unseeded/content-mutated fixture controls so incorrect isolation/content assertions are observed to fail; then restore the correct ownership path. Do not count a swallowed assertion as a passing product result.
- [ ] **Implement only needed production fixes** discovered by these tests, preserving the shared owner/transport algorithms; avoid weakening timing, state, cleanup or account assertions to accommodate a failing browser. Remove the old experiment document/task/class rather than retaining duplicates.
- [ ] **Run green:** full `browserIntegrationTest` with the explicit installed executable and exact canonical JAR, then `pkcs11IntegrationTest -Ppkcs11Fixture=<new owned fixture.json> -PburpBrowserExecutable=<same executable>`. Prepare each SoftHSM store using existing `test/pkcs11_fixture.py` and current lab instructions. Include existing Basic/NTLM/mTLS, popup/redirect, extraction, recording/replay, ABI and cold/cache coverage; record prerequisites/skips distinctly. Every real execution must start through the installed browser.
- [ ] **Commit:** reviewed maintained regressions and any proven fix; message `Prove Burp Browser account storage and process isolation`.

### Task 5: Bindings, isolated acceptance and maintained documentation

**Files:** Update `README.md`, `bapp/README.md`, `docs/{README.md,product.md,designs/interface.md,designs/universal-packaging.md,designs/code-structure.md}`, affected package READMEs, `test/authentication-lab/README.md`. Use the existing `:auth-lab:refreshBindings` generator for `test/authentication-lab/src/main/resources/catalog/*.json`; update capture/audit ownership inventories in their existing owners if renamed assets require it. Do not retain superseded packaging plans or obsolete browser assets as historical material.

**Interfaces:** Existing `authLab` profile collectors retain strict current-source binding and captured artifact checks. New driver lock/producer/configuration paths participate in the shared input inventory. No manually invented passing evidence or changed requirement disposition.

- [ ] **Review the stale source closure:** compare fixture `ControlledApplication`/`LabEvidence` and diagnostics owners against their declared hashes and inspect the actual source changes plus new implementation/capture inputs. The existing four failures are the red baseline; do not refresh until their causal drift and intended changes are reviewed.
- [ ] **Refresh only bindings:** run `:auth-lab:refreshBindings --offline`; inspect the generated diff for exact source/configuration fingerprints, stable requirement IDs, nullable fields and unchanged active/excluded/manual disposition. Record generated catalog files separately from inherited baseline so commits contain only reviewed changes. Do not combine this invocation with acceptance.
- [ ] **Run green in a new invocation:** `:auth-lab:test` (including the 27-test reproduction), then `authLab -PlabProfiles=baseline,revised,credentials,diagnostics,browser,recovery,http-auth -PburpBrowserExecutable=<installed executable>`; run transport with a newly prepared `-PlabPkcs11Fixture=<fixture.json>` and federation owners using the existing prepared federation runtime. Each profile must execute all selected owners in captured builds and join current-source evidence; unavailable external prerequisites remain explicit incomplete gates, not passing exclusions.
- [ ] **Replace maintained contracts:** document installed Burp Browser/no fallback, discovery/override/error behavior, driver-only format/cache/tasks/size, platform prerequisites and separate native qualification limits. Replace the old universal-packaging compression repair plan with the implemented contract. Verify references with `rg` for retired asset/task/factory names and inspect remaining legitimate references; remove obsolete ones rather than adding compatibility aliases.
- [ ] **Commit:** reviewed docs/bindings/capture-input deltas only; message `Qualify driver-only acceptance inputs and document Burp Browser prerequisites`.

### Task 6: Exact-artifact Windows/Linux VM qualification and delivery

**Files:** Extend existing `bapp/gradle/auth-lab-host.gradle.kts`, `test/authentication-lab/src/main/java/lab/auth/{LabHostInputs,LabHostCoordinator,LabHostGuest,LabHostGuiProtocol}.java` and `test/authentication-lab/src/hostGui/java/lab/auth/gui/{HostGuiDriver,HostGuiAssertions,HostGuiSelectors}.java` only as needed for the scoped runtime qualification. Add `test/authentication-lab/src/main/java/lab/auth/LabHostBrowserRuntime.java` and `test/authentication-lab/src/test/java/lab/auth/LabHostBrowserRuntimeTest.java`. Reuse `LabHostMemory`, existing heap diagnostics, existing VM transport/ownership and fixture exporter. Update strict stage schema/dispatch/tests wherever required; no second VM harness.

**Interfaces:** Add qualification-only stage `browser-runtime` to `authLabHostQualify`; never accept it as full `authLabHostTest` catalog acceptance. `LabHostBrowserRuntime` exposes `static void validate(JsonObject evidence, String expectedProductSha256, String expectedLoadedPath) throws IOException`, consumed by the existing guest/coordinator result flow. Evidence contains the exact product SHA-256, canonical loaded path, browser version, owned Burp PID/start identity, heap bytes, five per-cycle native UI Loaded off/on outcomes, complete 200 ms RSS/GC evidence, cold fixture login/recording/error-navigation observations and complete cleanup. Missing/foreign/stale evidence cannot produce PASS. User credentials/private VM helper secrets never enter that result.

Core assertions on complete synthetic evidence and stale/incomplete copies:

```java
assertDoesNotThrow(() -> LabHostBrowserRuntime.validate(currentReceipt, expectedSha, stablePath));
assertThrows(IOException.class, () -> LabHostBrowserRuntime.validate(staleReceipt, expectedSha, stablePath));
assertThrows(IOException.class, () -> LabHostBrowserRuntime.validate(fourCycleReceipt, expectedSha, stablePath));
```

- [ ] **Write failing harness tests:** `fiveCyclesRequireSamePidAndExactArtifact`, `staleStableCopyCannotPass`, `missingRssIntervalOrLoadingErrorFailsQualification`, `loginNeedsIndependentAccountAndRecordingEvidence`, `scopedRuntimeStageCannotClaimHostCatalogPass`. Reuse existing deterministic GUI/transport fakes; assert 2 GiB heap, five cycles, exact checksum/path and incomplete-cleanup failure. Existing broader host scenarios remain independently unfinished.
- [ ] **Run red then implement:** focused `:auth-lab:test --tests lab.auth.LabHostBrowserRuntimeTest` plus current host input/coordinator/protocol/GUI tests. Implement this stage with existing GUI selectors and public native UI operations, owned-process metadata and lab observations; never invoke production authentication through a test bypass or use host credential entry. Run the same tests green. Refresh bindings again if their owned source closure changed, review the diff, and rerun affected acceptance in a separate invocation.
- [ ] **Build before GUI:** run `check verifyArchitecture verifyDriverAssetProducer verifyNativeDocumentation :auth-lab:test jar`; verify zero required check failures and the actual canonical JAR's SHA-256, byte count `< 134217728`, exact three driver pairs/decodes and absence of Chromium. Rerun installed-browser integration if this task changed product/capture behavior. No `-x prepareDriverAssets`, stale JAR, copy-as-build or candidate artifact qualifies.
- [ ] **Coordinate and qualify the existing VMs:** inspect the existing ownership records/gates and claim only available VMs. Transfer the exact canonical artifact through existing private helpers without logging credentials; overwrite the stable Windows path directly and compare host/guest SHA-256 before refresh. Run `authLabHostQualify -PhostVmConfig=test/authentication-lab/build/host-runtime/host-vms.json -PhostPlatform=both -PhostStage=browser-runtime --offline`. Require five refresh cycles in one owned 2 GiB Burp PID on each VM, 200 ms memory evidence, no native loader error, cold login with server-observed identity, recording/replay and Settings inline-error/focus behavior at compact/wide sizes and Burp themes. Record exact captured paths separately; leave the stable Windows copy current. Keep sandbox enabled; report a blocked prerequisite rather than changing system policy.
- [ ] **Review and deliver:** inspect per-platform results and current artifact identity; structural Intel macOS verification is separate from unavailable native execution. Verify the actual Linux VMware console input path separately; guest automation/SSH do not prove it. Report incomplete/failed gates and exact affected path plainly. Commit only reviewed harness/documentation changes, retain current build reports under ignored build output and leave the canonical JAR ready for manual verification. No merge/push or changes to main.

## Self-review

Spec coverage: discovery/override/update behavior → Task 1; strict driver-only packaging/cache/security → Task 2; owned launch/transport/profiles/capture compatibility → Task 2; local Settings/located failure UX → Task 3; positive storage/account/cleanup controls → Task 4; existing binding failures and full selected isolated profiles/docs → Task 5; required checks, exact stable VM artifact, 2 GiB reloads, GUI evidence and platform limitations → Task 6. Review Focus items are assigned to the tests named above. The plan preserves the existing broad HOST suite's separate acceptance boundary.

Type consistency: all executable selection is `BurpBrowserResolver.Selection`; all live overrides come from `BrowserExecutableSettings`; driver readiness has no browser selector. The only new domain identities are framework-free browser input/recording field enum constants. No production component reads the integration-only executable property.

Execution starts only after the user reviews this plan and chooses native or subagent-driven execution under the requested Superpowers workflow. Internal implementation choices that do not alter the approved contract remain delegated to the implementer; a required contract change returns for a specific design decision.

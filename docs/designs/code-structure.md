# Java code structure

The extension uses feature packages under `bpsh`, with one composition root and a directed dependency graph. Production and native tests use matching directory/package paths. The Gradle `verifyArchitecture` task enforces package locations, permitted dependencies and the absence of package cycles; `check` includes that task.

```text
bapp/src/main/java/bpsh/
  Extension.java        Montoya registration, service composition and unload
  model/                Journey/step/draft values, identity, failures and progress
  secrets/              Owned session secret buffers
  events/               Bounded, credential-free journey history
  credentials/          Output capture, normalization, lifetime and use provenance
  config/               Native codecs, storage, registry, draft compilation and transfer
  io/                   Shared private-file ownership and creation permissions
  runtime/              Verified bundled assets, immutable cache and driver processes
  mtls/                 PKCS#11 discovery/selection and attempt-owned TLS proxy
  session/              Admission, shared acquisition, refresh and recovery policy
  browser/              Browser execution, failure classification and runner wiring
  diagnostics/          Safe classification and host logging
  http/                 Request tags, Burp HTTP hooks and attributed replay delivery
  ui/                   Swing forms, controller, dialogs and validation presentation

bapp/src/test/java/bpsh/                  Native tests grouped by owner
test/authentication-lab/production-tests/bpsh/  Isolated acceptance extensions
```

## Dependency ownership

`model` and `session` must not import Swing, AWT, Montoya or Playwright. Host-specific controls live in `config`, not the domain model. Acquisition results, progress and credential-use provenance are explicit contracts. `BrowserAuthentication` wires real browser execution and native PIN suppression into the coordinator's existing attempt/retry interfaces. The session policy does not construct a browser or native backend.

Configuration and credentials cannot depend on the editor or HTTP hooks. The limited JSON-path grammar and bounded recovery-pattern compilation belong below both configuration and execution. A draft owns immutable nonsecret input records; `JourneyDraftCompiler` converts those records through the strict native codec without constructing Swing components.

`ConfigManager` owns project persistence and revision checks. `NativeDocumentCodec` owns envelopes and controls, `NativeJourneyCodec` owns journey/credential/secret encoding, and `NativeJson` owns common strict field readers. `NativeJourneyFiles` owns bounded transfer I/O. Remember/export consent and secret-buffer ownership retain their existing contracts.

`BrowserManifestCodec` validates metadata and paths; `BrowserRuntimeManager` owns cache locking, extraction, verification and publication. Driver watchdogs remain in `PlaywrightDriverAdapter`. Shared creation permissions and Windows principal lookup live in `PrivateFiles`, so native export and user-library storage do not call browser-specific helpers.

`UiController` coordinates editor state and asynchronous actions. Modal presentation, form layout and validation wording have separate owners: `JourneyDialogs`/`SwingJourneyDialogs`, `JourneyForms` and `JourneyValidationMessages`. Keep their helpers package-private. Public types and members should express an actual package boundary or injectable backend contract; moving a file is not a reason to expose every implementation detail.

## Working rules

- Put a class with the feature that owns its state and behavior. Keep the package path identical to its directory. Avoid a general-purpose utility bucket.
- Reuse the strict codecs and draft compiler for imports, saved drafts and execution. Preserve native JSON field names, schema versions, storage keys, tags, cancellation and retry limits during structural changes.
- Keep browser, native, file and network work off Swing's event thread. Preserve captured generations, revision checks and bounded ownership; do not hide shared state behind a global service locator.
- Use the existing attempt/runtime/native/dialog interfaces at effect boundaries. Add an interface when a distinct implementation or ownership boundary needs it, rather than one per class.
- Retain exact source/artifact and observed-result checks in acceptance reporting. File movement does not prove a passing requirement.
- Run `verifyArchitecture`, relevant regressions and documentation lint after changing boundaries. Review dependency changes and use the smallest meaningful verification scope before the final full check.

## Acceptance source bindings

The broader lab keeps its acceptance extensions separate from normal native tests and applies them only in isolated production captures. Those sources now mirror package paths. Invocation hashing, source exclusion and JUnit selection use relative paths and fully qualified class names, including nested classes.

The Gradle launchers and Java collectors read one configuration inventory from `test/authentication-lab/src/main/resources/configuration-inputs.json`. After an intentional reviewed harness change, run from the repository root:

```powershell
.\bapp\gradlew.bat -p bapp :auth-lab:refreshBindings --offline
```

Review the catalog diff before running acceptance. This command updates source/configuration fingerprints, preserves required nullable fields and unbound requirements, and claims no passing coverage. Run acceptance in a subsequent invocation so it consumes rebuilt catalog resources. Source/configuration inputs use LF to make their checked-in bytes portable.

The acceptance overlays still extend several same-named native test classes. They are an explicit snapshot-testing boundary, not a second production implementation. Consolidating those overlapping test owners is separate work; the refactor does not claim that every repository duplication or design tradeoff has disappeared.

## Delivery compatibility

The Montoya entry point is `bpsh.Extension`. The universal JAR verifier checks that entry and rejects stale classes in the default package. Existing native documents, user libraries, request tags, browser payloads and immutable browser-cache identities retain their formats. No migration or Python runtime environment is introduced. The unsupported historical `api` sources and legacy fixture assets remain in their existing locations.

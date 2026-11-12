# Native Java extension development

The extension owns browser authentication, saved journeys, credential caching,
request tags, automatic session handling and Java PKCS#11 TLS.
User setup and request examples are in the [project README](../README.md).

## Runtime and host

The universal JAR runs inside Burp's Java 21+ JVM and bundles Node and Playwright
driver assets for Windows x64, Linux x64 and Intel macOS. Browser login and
recording require Burp's installed browser. No browser distribution, runtime
download, Python service, Hackvertor or separate Java executable is required.
Vendor PKCS#11 middleware is needed only for certificate journeys.

The compiled Montoya API is 2026.4. Startup probes the required global
request-drop and Proxy action factories before registering authentication hooks.
Burp 2026.10.1 has been used for manual checks. ARM systems are rejected before
cache preparation. Intel macOS resources are structurally verified; native macOS
execution remains unverified.

## Build

Use JDK 21 and the checked-in wrapper, dependency locks and verification metadata.
The checked-in Gradle settings allow a 2 GiB build heap. Universal driver encoding
runs sequentially with fixed XZ options. Unchanged inputs skip preparation.
From this directory:

```powershell
.\gradlew.bat check verifyDriverAssetProducer verifyNativeDocumentation jar --offline --console=plain
```

Build directly to `build/libs/browser-powered-session-handler-dev.jar`. The final
artifact must remain below 128 MiB (134,217,728 bytes). The verifier requires
exactly three format-3 driver manifest/archive pairs and streams all three
bounded XZ decodes. It rejects browser distributions, duplicate execution
resources, host/test APIs and stale signatures. Do not create a candidate JAR.

For a fresh machine, resolve the pinned Maven dependencies and prepare drivers:

```powershell
.\gradlew.bat prepareDriverAssets --console=plain
```

`driver-assets.lock.json` pins the Maven input archives, selected Node/JavaScript
subtrees, sizes and SHA-256 hashes. No browser source download or browser-download
proxy is used. `prepareDriverAssets` prepares all targets without executing foreign
binaries. `verifyDriverAssetProducer` runs 18 synthetic cases using the same
packing/validation functions. Offline builds require the locked Maven inputs in
the local dependency cache. On Linux/macOS use `./gradlew` with the same tasks.

## Runtime prerequisites and space

Install Burp Browser through the intended Burp installation. Automatic discovery
prefers identifiable active-installation roots and otherwise requires one unique
known installation. Numeric version directories select the newest complete
browser. Multiple installations, a missing active-installation browser or an
invalid explicit selection fail with Settings guidance. There is no alternate
edition/browser fallback. **Settings > Burp Browser** accepts a per-user executable
override; **Use automatic** clears it. Layout validation is not cryptographic
attestation. Resolution runs afresh for each attempt; changing Settings affects
subsequent attempts only.

The extension never attaches to a running browser, reads its profile or imports
its state. Every login/recording owns a separate sandboxed browser process,
temporary profile and context. Only owned processes and temporary data are
cleaned. Compatibility with arbitrary Chromium versions is not guaranteed.

Linux requires the installed browser's shared libraries and namespace/sandbox
permissions; visible recording also needs a working desktop/display. Ubuntu
24.04 x64 libraries include `libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64
libatspi2.0-0t64 libcairo2 libcups2t64 libdbus-1-3 libdrm2 libgbm1 libglib2.0-0t64
libnspr4 libnss3 libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 libxdamage1
libxext6 libxfixes3 libxkbcommon0 libxrandr2 libgtk-3-0t64`, plus suitable fonts.
Other distributions and installed Burp versions can need different packages.
A confirmed sandbox denial requires administrator correction; BPSH never disables
the sandbox or changes system policy.

Each target has `driver-assets.json` and `driver-assets.zip.xz` under
`META-INF/bpsh/<target>/`. Only the selected target is extracted into
`user.home/.bpsh/cache/drivers-v3/<target>/<digest>`. Plan disk space for the JAR,
expanded temporary ZIP, extracted driver and attempt profiles, plus the separate
Burp installation. The 128 MiB decoder ceiling, declared compressed/expanded byte
bounds, hashes, inventory, file modes, links, cancellation and original attempt
deadline all apply. Published caches are immutable; old browser caches are never
adopted or automatically removed. Close all users before manually removing an
unused digest directory.

## Existing verification

The default `test` task runs local unit/component tests without starting a
browser or initializing native middleware. The optional `-PburpBrowserExecutable=<absolute executable>` explicitly selects the
installed browser for integration/captured tests only; production reads user preferences.
Explicit integration tasks fail
when required prerequisites are absent:

```powershell
.\gradlew.bat browserIntegrationTest '-PburpBrowserExecutable=C:/Burp/burpbrowser/<version>/chrome.exe' --offline --console=plain
.\gradlew.bat browserIntegrationTest '-PpackagedJar=C:/artifacts/browser-powered-session-handler-dev.jar' '-PoldPackagedJar=C:/artifacts/previous.jar' --offline --console=plain
.\gradlew.bat pkcs11IntegrationTest '-Ppkcs11Fixture=build/pkcs11-fixtures/my-run/fixture.json' --offline --console=plain
```

Create a fresh owned PKCS#11 fixture using the
[software-token fixture instructions](../test/authentication-lab/README.md#disposable-software-token-transport-checks).
`verifyNativeDocumentation` checks private-member Javadoc too.
`packagedJar` tests an already delivered artifact without preparing driver
sources or rebuilding it. The integration JVM loads production classes and
driver resources from that JAR, not loose main output. The browser suite
requires fresh-home cold-start and cached-start probes with the normal
60-second attempt budget. `oldPackagedJar` additionally runs update and rollback
checks against a compatible previous JAR; if omitted, those checks are explicitly
recorded as not run. Probe reports are under `build/reports/bpsh-runtime` and
distinguish logical file bytes from physical allocation and sampled peak usage.

The authentication lab, catalog, host acceptance guide and capability gates are maintained in [the Java lab](../test/authentication-lab/README.md). Reuse its existing assertions and fixtures. Qualify each delivered artifact with its own generated test reports.

Focused native browser tests use the same Java HTTP/TLS/proxy fixtures as isolated acceptance. The lab is a test-only project dependency in normal builds; it is absent from the extension runtime and universal JAR. Requesting `:testClasses` builds the required lab classes, without running its suite or starting providers. Captured builds instead receive their immutable lab JAR through the acceptance plan. Packaging probes keep their isolated classloader free of lab classes: the parent test hosts the shared form and passes only its URL to the probe.

## Refresh in Burp

Use the development JAR from the active worktree.

Complete the required checks and build directly to the development JAR before
starting Computer Use. Then refresh the existing extension by toggling its
**Loaded** checkbox off and on. Do not remove/re-add it or create a candidate JAR.
Disposable test drafts do not need preserving before an authorized refresh.
Building, loading and manually checking the extension are separate verification
steps. Follow [root AGENTS.md](../AGENTS.md).

## Architecture

Production code lives in feature packages under `src/main/java/bpsh`; tests mirror those packages. See [the package map and dependency rules](../docs/designs/code-structure.md). `verifyArchitecture` checks package paths, permitted dependencies and cycles and runs as part of `check`.

| Component | Responsibility |
| --- | --- |
| `Extension` | Capability probe, service graph, hook registration and ordered unload |
| `UiController`, `JourneyDraft`, form panels | Swing editing, unfinished saves, execution validation and background storage |
| `ProjectStore`, `JourneyWorkspace`, `UserLibraryStore`, `SecretStore` | Native documents, scoped identities/generations, revision-checked storage and owned secret buffers |
| `BrowserRuntimeManager`, `PlaywrightDriverAdapter` | Verified platform assets, private extraction and browser/driver lifecycle |
| `BrowserFlowRunner`, `TokenExtractor` | Browser steps and complete JSON/regex/cookie output capture |
| `Pkcs11IdentityManager`, `JourneyTlsProxy` | Exact certificate selection, shared PIN state and attempt-owned TLS routing |
| `AuthenticationCoordinator`, `TokenLifetime`, `TokenSnapshot` | Coalesced acquisition, waiting limits, cancellation, expiry and refresh |
| `NativeTagParser`, `NativeTagResolver` | Bounded grammar, encoding and atomic request-local credential replacement |
| `AuthTrafficGuard`, `SessionHandling`, `SessionRequestProcessor`, `SessionRecovery` | Browser self-traffic exclusion, Burp hooks and version-specific invalidation |
| `JourneyEventLog`, `JourneyCachePanel`, `Diagnostics` | Safe history, explicit cache inspection and corrective diagnostics |

Project storage uses `bpsh_project_v3`; the User library is
`user.home/.bpsh/library-v3.json`. Browser extraction uses
`user.home/.bpsh/cache/drivers-v3`. Journey authentication configuration is separate from
project-wide ordered Session handling rules.

## Development boundaries

Keep browser, network, provider and filesystem work off Swing's event thread.
Use serialized storage work and captured editor/storage generations so late
results cannot replace newer work.

Credential text belongs only in deliberate request insertion, explicitly opened
Journey cache inspection and explicit Copy actions. Keep it out of logs, reports,
diagnostic strings and exports. PINs and secure step inputs have separate
session ownership and explicit remember/export choices.

Follow the [authentication design](../docs/designs/bapp-owned-authentication.md)
and current interface contract. Record the tested artifact/revision and keep
component, browser, SoftHSM and actual Burp evidence distinct.


## Journey autosave

Journey edits save automatically after 500 ms without changes, including
unfinished settings. Switching journeys or starting Test login flushes the latest
edits first. Plus creates a saved journey immediately. There are no Save/Save and
test controls or unsaved-changes prompts. Ctrl+S flushes or retries autosave.

Save results appear only in Event log: coalesced Info successes, Warning while a
temporary retry is pending, and Error when saving stops. Failures retain local
edits; revision conflicts never overwrite an external change. Reload selected
explicitly replaces local edits with the saved version. Secure values still
follow Remember secrets and export consent. Configuration errors are reported
when executing the journey, before browser setup.

## Authentication lab

The [Java authentication lab](../test/authentication-lab/README.md) provides controlled login applications, protected credential checks, production acceptance profiles and federation fixtures. Run the root Gradle `test` task for native regressions and use the guide for lab commands and prerequisites. Generated runs and reports stay under ignored build directories.

## Directory contract

### Interface

- [Source sets](./src/README.md): production entry point and feature package contracts.
- [build.gradle.kts:registerIntegrationTest](./build.gradle.kts) registers explicit packaged browser and native verification tasks.

### Invariants

- [gradle/architecture.gradle.kts:verifyArchitecture](./gradle/architecture.gradle.kts) enforces package paths, permitted dependencies and an acyclic graph.
- [build.gradle.kts:tasks.test](./build.gradle.kts) keeps browser and native execution outside the default unit task.

### Side Effects

Build tasks write ignored `build` outputs; explicit asset preparation can download archives. Runtime host, filesystem, browser and native effects are owned by the [composition root](./src/main/java/bpsh/README.md).

### Verification

From this directory: `.\gradlew.bat check verifyNativeDocumentation --offline`.

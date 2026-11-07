# Native Java extension development

The extension owns browser authentication, saved journeys, credential caching,
request tags, automatic session handling and Java PKCS#11 TLS.
User setup and request examples are in the [project README](../README.md).

## Runtime and host

The universal JAR runs inside Burp's Java 21+ JVM and bundles Chromium, Node and
Playwright driver assets for Windows x64, Linux x64 and Intel macOS. It does not require a Python API,
Hackvertor, a runtime browser download or a separate Java executable.
Vendor PKCS#11 middleware is needed only for certificate journeys.

The compiled Montoya API is 2026.4. Startup probes the required global
request-drop and Proxy action factories before registering authentication hooks.
Burp 2026.10.1 has been used for manual checks. ARM systems are rejected before
cache preparation. Native macOS execution has not been tested; the Mac payload
is structurally verified during packaging.

## Build

Use JDK 21 and the checked-in wrapper, dependency locks and verification metadata.
From this directory, after dependencies and source archives are prepared:

```powershell
.\gradlew.bat classes check verifyBrowserAssetProducer verifyNativeDocumentation jar --offline --console=plain
```

The development artifact is
`build/libs/browser-powered-session-handler-dev.jar` (about 740 MB).
The JAR task verifies its bundled payload and rejects host/test APIs, retired
runtime classes, duplicate entries and stale signatures.

For a fresh build environment, resolve Gradle dependencies and explicitly
prepare the locked browser sources:

```powershell
.\gradlew.bat prepareBrowserAssets --console=plain
```

The source lock is `browser-assets.lock.json`; source archives are cached under
`build/browser-sources`. Browser source downloads can use
`-PassetDownloadProxy=http://127.0.0.1:8080`. This build setting is independent
of journey proxy URLs and Gradle's Maven/wrapper download settings.
Runtime uses the verified payload embedded in the JAR.
`prepareBrowserAssets` prepares all three targets without executing foreign
binaries. The old `bundlePlatform` property is rejected. The producer's 17
synthetic checks exercise the same packing functions, with no browser downloads.

On Linux/macOS use `./gradlew` with the same tasks. On a prepared machine,
`--offline` requires every locked source archive and dependency to be cached;
missing source archives fail before a downloader can run.

## Runtime prerequisites and space

The JAR contains browser executables, not an operating system or Java runtime.
Use Java 21+ in Burp. Burp's normal installer launcher allocates up to half the
system RAM. A plain `java -jar burpsuite.jar` launch instead inherited this VM's
Java default of 25% (1.45 GiB), which failed while Burp read the large JAR;
an explicit 3 GiB test launch succeeded. This does not establish a 3 GiB minimum.
See the
[measured validation record](../docs/implementation/universal-packaging-validation.md)
for the tested setting, disk measurements and evidence limits.

Linux verification uses Ubuntu 24.04 x64. Install Chromium's shared libraries
through the OS package manager: `libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64
libatspi2.0-0t64 libcairo2 libcups2t64 libdbus-1-3 libdrm2 libgbm1 libglib2.0-0t64
libnspr4 libnss3 libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 libxdamage1
libxext6 libxfixes3 libxkbcommon0 libxrandr2 libgtk-3-0t64`, plus suitable fonts.
Other distributions may use different package names. Visible browser windows
also require a working desktop/display session. Headless login still needs the
shared libraries. Native Windows and macOS prerequisites follow the pinned
Chromium build; no claim is made for untested OS versions.

Each target has its own embedded manifest and ZIP under
`META-INF/bpsh/<target>/`. Only that target is read at runtime. Extraction uses
`user.home/.bpsh/cache/<target>/<manifest digest>`; matching previous manifests
keep their existing cache identity. Archive verification and extraction use
temporary disk space in addition to the published cache and JAR. Published old
caches are retained for rollback. To reclaim one, close all extension sessions
using it and manually remove only the obsolete digest directory. There is no
automatic published-cache eviction.

## Existing verification

The default `test` task runs local unit/component tests without starting a
browser or initializing native middleware. Explicit integration tasks fail
when required prerequisites are absent:

```powershell
.\gradlew.bat browserIntegrationTest --offline --console=plain
.\gradlew.bat browserIntegrationTest '-PpackagedJar=C:/artifacts/browser-powered-session-handler-dev.jar' '-PoldPackagedJar=C:/artifacts/previous.jar' --offline --console=plain
.\gradlew.bat pkcs11IntegrationTest '-Ppkcs11Fixture=build/pkcs11-fixtures/my-run/fixture.json' --offline --console=plain
```

Create a fresh owned PKCS#11 fixture using the
[middleware fixture instructions](../test/mTLS-app/README.md).
`verifyNativeDocumentation` checks private-member Javadoc too.
`packagedJar` tests an already delivered artifact without preparing browser
sources or rebuilding it. The integration JVM loads production classes and
browser resources from that JAR, not loose main output. The browser suite
requires fresh-home cold-start and cached-start probes with the normal
60-second attempt budget. `oldPackagedJar` additionally runs update and rollback
checks against a compatible previous JAR; if omitted, those checks are explicitly
recorded as not run. Probe reports are under `build/reports/bpsh-runtime` and
distinguish logical file bytes from physical allocation and sampled peak usage.

The authentication lab, catalog, host acceptance guide and capability gates are maintained in [the Java lab](../test/authentication-lab/README.md). Reuse its existing assertions and fixtures. [UX evidence](../docs/implementation/ux-test-matrix.md) and older checkpoints apply only to their recorded builds.

## Refresh in Burp

Use the development JAR from the active worktree.

For an already installed extension, uncheck **Loaded** and confirm unload before
replacing its JAR, then check **Loaded** again. Do not remove/re-add it.
Disposable test drafts do not need preserving before a requested refresh.
Follow [root AGENTS.md](../AGENTS.md).

Unload the existing extension before building directly to the development JAR
path, then reload it after the build succeeds. Do not create a candidate JAR to
preserve the existing JAR. Building, loading and manually checking the extension
are separate verification steps.

## Architecture

Production code lives in feature packages under `src/main/java/bpsh`; tests mirror those packages. See [the package map and dependency rules](../docs/designs/code-structure.md). `verifyArchitecture` checks package paths, permitted dependencies and cycles and runs as part of `check`.

| Component | Responsibility |
| --- | --- |
| `Extension` | Capability probe, service graph, hook registration and ordered unload |
| `UiController`, `JourneyDraft`, form panels | Swing editing, unfinished saves, execution validation and background storage |
| `ConfigManager`, `JourneyRegistry`, `UserLibraryStore`, `SecretStore` | Native documents, scoped identities/generations, revision-checked storage and owned secret buffers |
| `BrowserRuntimeManager`, `PlaywrightDriverAdapter` | Verified platform assets, private extraction and browser/driver lifecycle |
| `BrowserFlowRunner`, `TokenExtractor` | Browser steps and complete JSON/regex/cookie output capture |
| `Pkcs11IdentityManager`, `JourneyTlsProxy` | Exact certificate selection, shared PIN state and attempt-owned TLS routing |
| `AuthenticationCoordinator`, `TokenLifetime`, `TokenSnapshot` | Coalesced acquisition, waiting limits, cancellation, expiry and refresh |
| `NativeTagParser`, `NativeTagResolver` | Bounded grammar, encoding and atomic request-local credential replacement |
| `AuthTrafficGuard`, `HttpSessionHandler`, `SessionRecovery` | Browser self-traffic exclusion, Burp hooks and version-specific invalidation |
| `JourneyEventLog`, `JourneyCachePanel`, `Diagnostics` | Safe history, explicit cache inspection and corrective diagnostics |

Project storage uses `bpsh_project_v3`; the User library is
`user.home/.bpsh/library-v3.json`. Browser extraction uses
`user.home/.bpsh/cache`. Journey authentication configuration is separate from
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
and subsequent author amendments. Record the tested artifact/revision and keep
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

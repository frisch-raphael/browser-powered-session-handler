# Universal offline packaging

One development artifact, `bapp/build/libs/browser-powered-session-handler-dev.jar`, contains the Java extension and pinned Chromium/Node/Playwright payloads for Windows x64, Linux x64 and Intel macOS. Build directly to that path. Use the active worktree's JAR in Burp and unload it before replacement; never build a candidate to preserve it.

## Supported hosts and prerequisites

Burp runs the extension in its Java 21+ JVM. The extension requires the Montoya request-drop and Proxy-action capabilities checked at startup. Chromium is the selected engine. ARM targets are rejected before cache preparation. Vendor PKCS#11 middleware is needed only for certificate journeys.

The JAR supplies browser components, not an operating system, Java runtime, desktop session or Chromium shared libraries. Linux requires the libraries listed in [the build guide](../../bapp/README.md#runtime-prerequisites-and-space). Native execution on a platform requires that platform's own test results; structural payload verification alone cannot establish it.

Runtime preparation uses embedded files or a verified matching cache. It performs no browser download and does not locate Burp's or the system's browser.

## Resource layout

Each target owns exactly two resources under `META-INF/bpsh/<target>/`:

- `browser-assets.json`: target, pinned versions, paths, helpers, entry inventory, unpacked size and archive SHA-256/size.
- `browser-assets.zip`: the matching Chromium, Node, driver JavaScript and helper files.

Targets are exactly `windows-x64`, `linux-x64` and `macos-x64`. Runtime reads only the selected host's resources. Common driver JavaScript is kept within each target archive so its manifest/cache identity covers the complete executable tree. Root driver execution resources are excluded from the assembled Java runtime to avoid duplicate payloads. Third-party notices and required Java resources remain bundled.

## Source preparation and producer

`browser-assets.lock.json` pins source locations, sizes, hashes and mapping rules. Gradle dependency locks and verification metadata pin the Java/driver inputs. `prepareBrowserAssets` validates every locked source and prepares all three targets on one host without executing foreign binaries. HTTPS sources are cached in `build/browser-sources`; offline misses fail before a downloader can run.

Source preparation is an explicit developer action. The optional `assetDownloadProxy` build setting affects those downloads only. Journey proxies and Gradle wrapper/Maven networking have separate ownership.

The producer validates bounded archive inventories, selected prefixes, safe relative paths, case collisions, duplicate names, file/directory conflicts, permitted Unix entry types and symlink targets. It rejects missing target helpers, wrong Node subtrees and mismatched pinned browser/driver metadata. Deterministic writing, consumer manifest validation and an atomic target-pair publication prevent partially prepared output from becoming the selected resources.

`verifyBrowserAssetProducer` exercises the same production packing functions with seventeen synthetic cases and performs no browser downloads or native execution. Synthetic success does not replace delivered-artifact verification.

## JAR assembly and delivery

The Java runtime assembly merges required resources deterministically and includes the maintained `bpsh.Extension` entry point. The JAR verifier rejects duplicate entries, host/test APIs, stale signatures, module descriptors, default-package production classes and excluded execution payloads.

Packaging requires exactly the three manifest/archive pairs, validates every manifest with the production parser, and recomputes each archive's size and SHA-256. A missing target or digest mismatch fails the JAR task. Generated JARs, prepared browser payloads and source ZIPs stay out of Git.

Build and verification commands are maintained in [bapp/README.md](../../bapp/README.md#build). On Windows use the checked-in batch wrapper and JDK 21; on Linux/macOS use the Unix wrapper. `check` includes native tests and architecture/producer verification; documentation lint is explicit.

## Runtime validation and cache ownership

The runtime selects a supported normalized OS/architecture before cache access. It validates the bounded manifest, target inventory, paths and metadata, then verifies the selected archive's exact size/hash. Extraction uses private owned staging, bounded file sizes, safe links and target executable modes. Completion metadata and file checks qualify a cache before publication/reuse.

The selected cache lives under `user.home/.bpsh/cache/<target>/<bundle digest>`. Its identity derives from exact manifest/archive bytes. Equivalent payload bytes reuse the same cache identity. Contention, insufficient space, corruption, cancellation and unsupported hosts have distinct corrective diagnostics. Preparation stays inside the attempt's normal deadline and cancellation ownership.

Only the selected target is extracted. Runtime cleanup releases attempt-owned processes, temporary archives and staging. Published cache directories are immutable; remove an unused one only after all extension sessions using it have closed. Filesystem work, decompression and process startup stay off Swing's event thread. Never invoke a Playwright CLI entry point inside Burp.

## Artifact verification

Native unit/component tests do not start a browser or initialize middleware. The explicit browser task can qualify an existing `packagedJar`, loading production classes and browser resources from that exact JAR. Cold/cache probes use fresh owned homes and the normal attempt budget. Update/rollback probes require an explicitly supplied compatible artifact; omitted probes are recorded as not run.

Native middleware checks require a fresh owned SoftHSM fixture prepared with the current [lab instructions](../../test/authentication-lab/README.md#disposable-software-token-transport-checks). They establish software-token behavior only. Actual Burp loading, hook registration, tagged/automatic protected access, cancellation and reload require separate host observations.

Measure final JAR bytes, selected expanded cache, extraction peak and filesystem allocation separately. The JAR size is not the whole installed footprint, and a single observed startup time is not a performance guarantee. Reports identify the exact source, artifact, platform, prerequisites and skipped/unavailable checks.

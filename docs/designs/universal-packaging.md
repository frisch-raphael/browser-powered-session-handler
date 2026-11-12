# Universal offline packaging

One development artifact, `bapp/build/libs/browser-powered-session-handler-dev.jar`, contains the Java extension and pinned Chromium/Node/Playwright payloads for Windows x64, Linux x64 and Intel macOS. Build directly to that path. Use the active worktree's JAR in Burp and unload it before replacement; never build a candidate to preserve it.

## Supported hosts and prerequisites

Burp runs the extension in its Java 21+ JVM. The extension requires the Montoya request-drop and Proxy-action capabilities checked at startup. Chromium is the selected engine. ARM targets are rejected before cache preparation. Vendor PKCS#11 middleware is needed only for certificate journeys.

The JAR supplies browser components, not an operating system, Java runtime, desktop session or Chromium shared libraries. Linux requires the libraries listed in [the build guide](../../bapp/README.md#runtime-prerequisites-and-space). Native execution on a platform requires that platform's own test results; structural payload verification alone cannot establish it.

Runtime preparation uses embedded files or a verified matching cache. It performs no browser download and does not locate Burp's or the system's browser.

## Resource layout

Each target owns two resources under `META-INF/bpsh/<target>/`:

- `browser-assets.json`: target, pinned versions, paths, helpers, entry inventory, unpacked size and archive SHA-256/size.
- `browser-assets.zip.xz`: a deterministic STORED ZIP compressed with XZ, containing the matching Chromium, Node, driver JavaScript and helper files.

Targets are exactly `windows-x64`, `linux-x64` and `macos-x64`. Runtime reads only the selected host's resources. Common driver JavaScript is kept within each target archive so its manifest/cache identity covers the complete executable tree. Root driver execution resources are excluded from the assembled Java runtime. Third-party notices and required Java resources remain bundled.

### Loading-memory bound

Burp 2026.10.1 with bundled Java 26.0.2 buffers the complete extension JAR during its file-copy/materialization path: InputStream.read, ByteArrayOutputStream.write and toByteArray. A Windows 2 GiB-heap reload reproduced the native loading error. GC observed a 1,073,741,840-byte growth array and a 740,792,168-byte array matching the 740,792,146-byte product JAR, together in three GC observations. Peak simultaneously observed humongous objects were approximately 1.84 GiB. This establishes temporary whole-file overlap; old-classloader retention has not been established. Individual resource-entry size does not bound that allocation.

The repair must reduce the whole JAR's loading cost while keeping one offline universal artifact and identical executable payload bytes for all three platforms. Raising Burp's heap is insufficient as the product remedy. A larger heap also allowed Linux's test process to exhaust its unswapped 6 GiB guest.

The repair uses a deterministic STORED ZIP wrapped in one streaming XZ container. XZ for Java 1.12 is pinned in both runtime and buildscript dependency locks and verification metadata; the runtime assembler includes its license. Version 1.12 fixes the encoder defect in 1.10/1.11 ([upstream release information](https://tukaani.org/xz/java.html)). The filter chain is X86 followed by LZMA2 preset 9 with a 64 MiB dictionary. Exact binary files, links, modes and driver metadata remain unchanged. The three target resources remain offline in one universal artifact. Entry splitting cannot repair this whole-file loader allocation.

### Format 2 and bounded runtime decoding

Only manifest format 2 is accepted. Each target declares `browser-assets.zip.xz` in `archive.resource`, the compressed `archive.bytes` and SHA-256, and `archive.expandedBytes` for the reconstructed ZIP. Both byte declarations are positive and bounded by the existing 2 GiB ZIP ceiling; ordinary manifest, file, inventory, total-tree and path limits remain unchanged. No legacy archive reader/layout is retained.

Runtime opens only the selected target resource, then wraps it in a counting/hash stream that checks cancellation and the original deadline before each underlying read and never delivers more than the exact declared compressed bytes. A streaming XZ decoder has a fixed 128 MiB memory limit; a header requiring more fails before allocating that dictionary. Decoding streams to the existing private owned temporary ZIP, checks cancellation/deadline between 64 KiB writes and rejects even one decoded byte beyond `expandedBytes`. It reads through decoder EOF to verify XZ integrity, then requires exact expanded size, compressed EOF/size and SHA-256 before opening the ZIP extractor. Bad XZ headers, checks, footers, trailing non-XZ input, oversized dictionaries, truncated streams, extra expanded bytes and forged declarations fail without publishing a cache. Concatenated XZ streams are allowed only when their combined output and input satisfy those exact declarations; they cannot bypass either bound. The existing ZIP inventory, path/case/link/mode/member-hash checks retain ownership of the reconstructed archive.

The decoder owns its wrapper once construction succeeds; constructor failure closes the original resource once. All error, timeout, cancellation and publication paths close streams and remove only the invocation's existing owned archive/staging paths. The runtime never buffers an entire archive. Free-space checks use expanded ZIP bytes plus extracted-tree bytes. The completion marker remains version 1 and the cache digest domain remains `bpsh-assets-v1`: these specify ownership/digest construction independently of archive layout. New manifest/archive bytes give a new bundle identity.

### Producer, size gate and implementation boundary

The producer reuses verified source ZIPs and existing mapping/security checks. It writes sorted STORED ZIP entries with deterministic timestamps, known source sizes/CRCs and unchanged Unix modes, then streams that completed ZIP through the fixed XZ filter chain. The temporary ZIP is deleted before atomic target-pair publication and never enters the JAR. Before publication, a preparation/validation failure preserves the previous complete target pair. Publication removes the old generated target then atomically moves the validated new pair; failure during that final replacement can leave the target absent and fails the task. Never publish a partial pair or create rollback backups. A subsequent build regenerates an absent target. XZ memory is bounded by fixed options; target encoding is sequential, with a documented Gradle heap of 2 GiB rather than the usual 512 MiB. Cached unchanged rebuilds skip encoding through normal task inputs/outputs. Task inputs must include the packing script and codec classes, so format/validation changes cannot reuse stale prepared assets.

The JAR verifier checks exactly three format-2 manifest/archive pairs, recomputes every compressed length/hash, streams every XZ resource with the same 128 MiB decoder ceiling, and requires exact decoded ZIP size. Existing source/member/inventory validation remains required. Delivery evidence must additionally decode all three archives from the actual final JAR and compare every file SHA-256, link payload, executable mode and inventory with the recorded baseline JAR manifests and source archive metadata, proving unchanged executable payload bytes on foreign targets too. A final artifact at or above 512 MiB fails; the engineering target is at most 500 MiB. Count-only estimates guide selection but never qualify delivery: record the actual Java-produced JAR size/hash, encoder heap/peak RSS and selected-host cold decode duration. If the final size cannot provide the required margin, stop and report measured alternatives without dropping platforms or adding network dependency.

Maintained write boundary (repository-relative): `bapp/gradle/browser-assets.gradle.kts`, `bapp/build.gradle.kts`, `bapp/gradle.lockfile`, `bapp/settings-gradle.lockfile`, `bapp/gradle/verification-metadata.xml`, `bapp/gradle.properties`, `bapp/src/main/java/bpsh/browser/runtime/{BrowserRuntimeManager.java,BrowserManifestCodec.java,BrowserArchiveCodec.java,README.md}`, `bapp/src/main/resources/browser-assets.schema.json`, `bapp/src/test/java/bpsh/browser/runtime/{BrowserAssetsTest.java,BrowserArchiveCodecTest.java}`, `bapp/src/test/java/bpsh/browser/BrowserJourneyIntegrationTest.java`, `bapp/README.md`, and this document. `BrowserArchiveCodec.java` owns bounded XZ decoding; `BrowserArchiveCodecTest.java` tests the codec directly and the package README documents ownership. The runtime manifest schema uses format 2; the independent source-lock schema remains format 1. The external integration resource-presence assertion and capture-input fingerprints must be coordinated with their owner. Authentication remains Java. Generated artifacts stay under the active isolated worktree's ignored build output; final integration builds directly to the main worktree development JAR after applying only this scoped delta.

Buildable checkpoints:

1. Record baseline source hashes, baseline payload inventories/modes and count-only compression measurements; finish this format/dependency/bounds/file-boundary design and fresh scoped EGM design/readiness review. Resolve major findings before production edits.
2. Coordinate producer and consumer format 2, locked dependency and test fixtures in one change. Add malformed XZ/memory/expanded-boundary/stream-ownership/cancellation/deadline/owned-cleanup tests and keep ZIP attack/entry/mode tests. Producer checks cover deterministic bytes, correct modes, source failures and atomic publication. Keep the assembled JAR gate fail closed for malformed format/size/hash/decoder expansion.
3. Run native/component/architecture/producer checks, private-member documentation lint, then build directly to `bapp/build/libs/browser-powered-session-handler-dev.jar`. Verify actual artifact inventory, hashes/decoded sizes for all three targets, final size, heap/RSS, all-platform decoded-payload equality against the baseline and cold selected-host decode. Repeat an unchanged build to establish cached rebuild cost. Record exact source delta and limitations for integration.
4. Root integrates the scoped delta, refreshes owned capture bindings separately and builds the active main development JAR before any Computer Use. VM qualification below applies to that exact integrated artifact.

Qualification requires five actual unload/reload cycles in one owned PID at 2 GiB heap on BOTH VMs, 200 ms owned-RSS sampling, safe GC allocation summaries, exact artifact checksum and native loading-error checks. Then perform a cold browser login in the same fresh owned home and independently prove fixture authentication. A larger-heap pass, unit pass, WSL smoke or previous artifact report does not qualify the repair. A failed qualification remains a failure. The broader host scenario/profile acceptance remains governed by its separate plan.

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

Concurrent journeys using one runtime manager share its preparation. Each waiter
keeps its original attempt deadline and cancellation; a slow first verification
does not impose an extra ten-second failure on another journey in that manager.
Acquiring a cache file lock owned outside that preparation retains a separate
ten-second maximum, further bounded by the caller's remaining attempt time.

Only the selected target is extracted. Runtime cleanup releases attempt-owned processes, temporary archives and staging. Published cache directories are immutable; remove an unused one only after all extension sessions using it have closed. Filesystem work, decompression and process startup stay off Swing's event thread. Never invoke a Playwright CLI entry point inside Burp.

## Artifact verification

Native unit/component tests do not start a browser or initialize middleware. The explicit browser task can qualify an existing `packagedJar`, loading production classes and browser resources from that exact JAR. Cold/cache probes use fresh owned homes and the normal attempt budget. Update/rollback probes require an explicitly supplied compatible artifact; omitted probes are recorded as not run.

Native middleware checks require a fresh owned SoftHSM fixture prepared with the current [lab instructions](../../test/authentication-lab/README.md#disposable-software-token-transport-checks). They establish software-token behavior only. Actual Burp loading, hook registration, tagged/automatic protected access, cancellation and reload require separate host observations.

Measure final JAR bytes, selected expanded cache, extraction peak and filesystem allocation separately. The JAR size is not the whole installed footprint, and a single observed startup time is not a performance guarantee. Reports identify the exact source, artifact, platform, prerequisites and skipped/unavailable checks.

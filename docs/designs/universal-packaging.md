# Universal driver packaging

`bapp/build/libs/browser-powered-session-handler-dev.jar` is the single development
artifact for Windows x64, Linux x64 and Intel macOS. It includes the Java extension,
Playwright Java, verified Node executables and driver JavaScript for all three
targets. It contains no Chromium distribution. Login and recording require the
installed Burp Browser; no runtime download or browser fallback exists.

Build directly to this path. The final JAR must be smaller than 128 MiB
(134,217,728 bytes). Its size is a loading constraint, not a measurement of total
installed disk use or proof of safe native reload behavior.

## Installed browser boundary

`BurpBrowserResolver` resolves each attempt independently on a worker. A per-user
explicit executable is authoritative. Otherwise an identifiable active Burp
installation takes precedence; known installation roots are used only when that
installation cannot be identified. Several installations require an explicit
selection. A missing active browser never selects another edition. Supported
layouts use bounded directory enumeration and numeric version ordering, with
canonical deduplication and regular/executable checks. Layout recognition does not
attest installed binary provenance or guarantee arbitrary Chromium compatibility.

The launcher captures the selection once and supplies it through Playwright's
executable-path option. Each attempt owns a distinct process, temporary profile
and context with sandboxing enabled. BPSH never attaches to a live browser or
reads/imports/clears its state. Existing transport and process ownership control
cleanup, including cancellation and partial startup. No retry selects another
binary after launch or protocol failure.

## Sources and producer

`bapp/driver-assets.lock.json` pins Playwright Java 1.64.0, driver package 1.64.1
and Node 24.22.1 with Maven coordinates, archive/member SHA-256 and sizes, selected
prefixes and target mappings. Gradle locks and verification metadata pin the
build/runtime inputs. `bapp/gradle/driver-assets.gradle.kts` owns
`prepareDriverAssets` and `verifyDriverAssetProducer`. Preparation executes no
foreign binaries. Offline misses fail; there is no browser-source downloader.

The producer accepts bounded inventories, safe paths, permitted entry types,
validated links and modes. It rejects duplicate/case-colliding paths and browser
distribution entries. The pinned custom-executable launch path needs no ffmpeg or
winldd helper for BPSH's DOM recording. All three manifests therefore declare an
empty helper list. Actual launch/recording integration qualifies this assumption.

Packing uses sorted deterministic STORED ZIP entries wrapped in XZ (X86 + LZMA2,
preset 9, 64 MiB dictionary). Encoding is sequential under a 2 GiB build heap.
Validated target pairs publish atomically; failures never publish partial output.
An interrupted final replacement can leave a target absent and fails the build;
the next preparation regenerates it. Cached unchanged builds skip encoding.
No generated JAR, payload or source archive enters Git.

## Format 3 and runtime cache

Each `META-INF/bpsh/<target>/` contains exactly `driver-assets.json` and
`driver-assets.zip.xz`. Format 3 declares target identity, pinned versions,
`helperRoot=driver`, Node/driver selectors, helpers, bounded entry inventory,
compressed hash/size and expanded ZIP size. Browser selectors, legacy formats and
browser distribution paths are rejected. Driver readiness contains no installed
browser executable.

Runtime opens only the selected target. A counting/hash stream enforces the
exact declared compressed bytes, original deadline and cancellation checkpoints.
XZ decoding has a fixed 128 MiB memory ceiling and streams to an owned temporary
ZIP, enforcing the exact expanded bound and integrity/EOF before extraction.
The existing ZIP path, type, link, mode, inventory and member-hash checks remain.
Constructor failure closes the source; all paths close owned streams and clean
only their own staging/archive paths. No whole archive is buffered in memory.

Verified caches live at
`user.home/.bpsh/cache/drivers-v3/<target>/<digest>`. Exact manifest/archive bytes
define identity. Old browser caches are never adopted or automatically removed.
Published caches remain immutable. Each extension instance verifies its first
acquisition. Waiters retain their original deadline/cancellation; external lock
contention has a separate ten-second maximum bounded by remaining attempt time.
Free-space checks cover temporary expanded ZIP plus extracted driver data.
Filesystem work, decoding and process startup stay off Swing's event thread.

## Verification and delivery

The final-JAR verifier requires exactly three format-3 pairs, parses manifests
through the production codec and streams all three archive decodes with exact
length/hash checks. It rejects duplicate execution resources, browser content,
host/test APIs, stale signatures and oversized artifacts. Producer attack fixtures
and native extraction/resource-loading controls retain their unsafe positive
controls. Build commands and platform prerequisites are in
[the build guide](../../bapp/README.md).

Real integration loads production classes/resources from an explicitly identified
JAR and uses the installed browser. It covers cold/cache behavior, profiles,
account/storage isolation, recording/replay, Basic/NTLM, software-token mTLS and
cleanup. Software tokens do not qualify physical devices. Structural Intel macOS
verification does not establish native execution.

Exact-artifact VM qualification requires the existing Windows and Linux Burp
installations, checksum verification, five Loaded off/on cycles in one owned
2 GiB Burp PID, complete 200 ms RSS/GC and loader-error evidence, then cold fixture
login, recording/replay and Settings error/focus checks. A larger heap, WSL or a
previous artifact is separate evidence. The scoped `browser-runtime`
qualification cannot claim full HOST catalog acceptance. Actual Linux VMware
console input also needs separate evidence; SSH/guest Robot input does not prove
it. Record failed or unavailable gates explicitly and keep the stable Windows
`C:\bpsh\browser-powered-session-handler-dev.jar` current for manual verification.

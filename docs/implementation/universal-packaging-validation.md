# Universal offline packaging validation

Recorded on 2026-11-06 for the `install` worktree. The universal JAR loads and
completes a login in normally installed Windows and Linux Burp clients with their
factory memory settings. Windows was tested in a fresh Windows installation.
Native Intel macOS execution remains **NOT RUN** because no Mac
is available.

## Delivered artifact

| Item | Value |
| --- | --- |
| File | `bapp/build/libs/browser-powered-session-handler-dev.jar` |
| Bytes | 737,910,938 (737.9 MB; 703.7 MiB) |
| SHA-256 | `0c7c377a20d644feb011de6aa8d715d141a07157c27719879074f1d9c4ab657a` |
| Targets | Windows x64, Linux x64, Intel macOS |
| Browser | Chromium 156.0.8078.4, revision 1248 |
| Driver | Playwright Java 1.64.0, driver package 1.64.1, Node 24.22.1 |

The JAR contains exactly three scoped manifest/ZIP pairs under
`META-INF/bpsh/{windows-x64,linux-x64,macos-x64}/`. Packaging checks reject root
driver resources, ARM payloads, additional browser families, stale signatures,
duplicate entries, test classes and host API classes. Every target is assembled
and checked without executing its foreign native binaries. Only the matching
target is verified/extracted at runtime; there is no browser download or
Burp-browser path discovery.

| Target | Embedded ZIP bytes | Declared extracted regular-file bytes |
| --- | ---: | ---: |
| Windows x64 | 247,266,909 | 569,641,664 |
| Linux x64 | 235,019,415 | 566,912,207 |
| Intel macOS | 236,031,928 | 536,981,489 |

These ZIPs are already compressed. Their total is 718,318,252 bytes; the
remaining JAR content is Java code/dependencies, notices and metadata. Mac byte
counts describe bundled files, not a native Mac installation measurement.

## Scope and provenance

The app was imported from the uncommitted `java-playwright` source snapshot
captured at 2026-11-06 09:32:55 UTC, based on Git HEAD
`8accbeab2ba1beb216df3e447842f19ba130a9ff`. That sibling continued changing during
this work. Results apply to the exact JAR above, not the sibling's later builds.
No source changes or installed extension refreshes were made in that sibling.

Final source/test/build-input fingerprint:
`9d02dbd2174618f1634e2a17a7e7ffeb80d2a0d036b6b102119ae58ad2bab492`.
It hashes the ordered `path + NUL + SHA-256 + newline` records for 88 files in
`bapp/src` and the recorded Gradle/build/lock/wrapper inputs. The full manifest is
retained as `installation-inputs.json` in the private verification directory.

The author clarified that broader authentication validation belongs to the
`test-suite` worktree. Final installation checks retain the existing artifact
bootstrap and cold/cache/update/rollback owners. Exploratory authentication
fixture changes were restored; the Burp smoke test uses the existing Java lab
and native-example generator from `test-suite`. This is not full lab profile or
authentication acceptance.

## Checks

| Check | Result |
| --- | --- |
| Windows unit/component suite | 622 discovered, 0 failures, 1 POSIX-only check skipped |
| Ubuntu unit/component suite | 622 discovered, 0 failures, 1 Windows ACL check skipped; real POSIX extraction check executed |
| Producer verification | 17 cases passed on Windows and Linux; zero downloads or foreign native executions |
| Native documentation guard | Passed |
| Windows exact-JAR installation subset | 2 tests passed, 0 skipped |
| Linux exact-JAR installation subset, network blocked | 2 tests passed, 0 skipped |
| Windows previous-JAR update and rollback | Passed; previous cache and user-library sentinel retained |
| Linux previous-JAR update and rollback | NOT RUN: compatible prior Linux artifact not supplied |
| Normally installed Linux Burp: load, login, protected request, reload | Passed as described below |
| Fresh Windows installation, normal Burp: load, offline cold/cache login, protected request, reload | Passed with the app's normal 30-second browser timeout; initial five-second lab-example launch failed, as described below |
| Intel macOS native execution | NOT RUN: no Mac available |
| Physical tokens/vendor middleware/full authentication lab | Outside this installation acceptance |

The exact-JAR subset consists of
`coldAndUpgradeProbesUseNormalBudgets` and
`packagedClassloaderUsesExactResourcesWithoutSharedDriverCacheOrJvmMutation`.
Production classes and runtime assets come from the selected JAR, excluding
loose main classes/resources and duplicate production dependencies. The checks
launch its pinned Node and Chromium, authenticate against owned local origins,
exercise fresh contexts and verify that shared driver settings remain unchanged.

The Windows comparison artifact was a private frozen earlier per-Windows JAR,
SHA-256 `06a0d8781d2115237341df47a50185da3196c561e340b9ed36772a6c227f0297`.
The old cold start, new-version use, new cached use and old-version rollback all
passed. An omitted old artifact is reported as NOT RUN, never as a passed update.

Final probe runs:

* Windows: `c66a8f8c-b35f-45ee-8e13-b0be6be685ba`.
* Linux: `4421085c-23b5-4f64-a518-73d7f07cabdf`.

## Normal Linux Burp client

Environment: VMware Workstation, Ubuntu 24.04 x64, 4 virtual CPUs and 6 GiB RAM,
Xorg/Openbox desktop. The official Burp Suite 2026.10.1 Linux installer was used
with its bundled OpenJDK 26.0.2. The launcher was started without Java arguments,
configuration files or changes to `BurpSuite.vmoptions`; no `user.vmoptions`
exists. The factory setting is `-XX:MaxRAMPercentage=50`, displayed by Burp as a
2.89 GiB maximum heap in this VM.

Observed sequence:

1. Add the universal JAR through Extensions / Installed. Burp reported successful
   loading and registered one suite tab and one of each required hook.
2. Run the existing `test-suite` Java lab distribution in the guest. Its unchanged
   `ProductionLabExamples` uses the candidate JAR's serializer to generate native
   journey files. The lab JAR SHA-256 is
   `150a8d943b9de39d010803a8102a4cb4c77ce60d3cd83f2de375fa32fc01733e`.
3. Import `BROW.basic.json.json`, enter the lab's disposable password, and use
   Test login. The event log reported verification, driver startup, Chromium
   startup, signing in and **Credentials captured**.
4. Send the generated native tag through that Burp client's proxy to the lab's
   protected endpoint. It returned HTTP 200 for `user2`, issuance `s7`, role `B`.
   The issuance matched the lab's actual completed-login event. A preliminary
   request after the fixture's 60-second credential lifetime returned 401;
   explicit Test login refreshed it before this successful proof.
5. Uncheck Loaded, confirm unload, then check Loaded again. The extension loaded
   successfully with one set of hooks and the same factory memory settings.

The lab run was `82e7e2ae-a3b5-4bbe-bd74-f38582161b7b`. Lab applications,
example generation and assertions were reused without editing `test-suite`.
Browser/example helpers were compiled in isolated scratch storage against the
candidate. The full source-audited `authLabBrowserTest`/transport profiles were
not run or claimed by this smoke check.

Installer SHA-256:
`77ab3568ce83a993362be7c6bd0726e612a7af36e0ad323d6995c9e65d714936`.
Factory `BurpSuite.vmoptions` SHA-256 before and after:
`8d56a6e21f79da841a8a4db6bdf95cd70dd46b5fa82cb55c851aed866ec3132b`.
Community Edition was sufficient; no user license was read or entered. The
Windows host Burp session was untouched.

### Memory finding

An earlier standalone `java -jar burpsuite.jar` test inherited Java's default
25% RAM limit (1.45 GiB here) and failed with Java heap exhaustion inside Burp's
JAR read. A 3 GiB launch passed, but that was not a measured minimum. The normal
installer's unmodified 50% setting also passed. Therefore **no Burp configuration
change was required in the tested normal client**. This does not establish the
minimum system RAM or acceptance on every smaller-memory machine.

PortSwigger documents the normal half-RAM setting in its
[performance settings](https://portswigger.net/burp/documentation/desktop/settings/suite/performance).

## Fresh Windows installation and normal Burp client

Environment: a new VMware Workstation VM, 4 virtual CPUs and 8 GiB RAM, installed
from Microsoft's Windows 11 Enterprise Evaluation x64 media. The guest reports
Windows version `10.0.26300`, build `26300`, and a new local `tester` profile.
The pre-load receipt proves that `.bpsh` did not exist and that the copied JAR
matches the delivered SHA-256 above. The only initial additions were VMware
Tools, the official Burp installer and the owned test payload.

The official Burp Suite 2026.10.1 Windows installer completed successfully using
its default options. Community Edition, a temporary project and **Use Burp
defaults** were selected. Burp ran through `C:\Program Files\BurpSuite\BurpSuite.exe`
without arguments, with its bundled OpenJDK 26.0.2. Its factory
`-XX:MaxRAMPercentage=50` setting displayed a **4.00 GB** heap limit. No
`user.vmoptions` existed, and the factory file's SHA-256 was unchanged before
and after the check:
`e5bd83ee80f0072428d4602d7cd343fe4a90971f2607de73c6b2bf9700e0637f`.
No license was read or entered, and the host's existing Burp was untouched.

Observed sequence:

1. Add the exact universal JAR once through Extensions / Installed. Burp reported
   successful loading and one of each required hook and suite tab.
2. Reuse the same frozen `test-suite` lab JAR and native-example generator as the
   Linux check. Burp's trimmed Java runtime lacks `jdk.httpserver`, which the lab
   needs, so a private Java 21 runtime was supplied **only to the lab**. It was
   never used to launch Burp or the extension and was not installed system-wide.
3. Import the existing basic JSON example and enter its disposable fixture
   password. The initial empty-cache run extracted the browser and started the
   driver, but Chromium startup failed with the example's five-second browser
   timeout. A standalone blank-page launch and subsequent UI logins passed
   without installing browser dependencies or changing the JAR. The original
   failure remains recorded; its raw launch exception was not captured, so its
   precise cause is not established.
4. Change only the imported journey's browser timeout from five seconds to the
   app's normal **30 seconds**. Uncheck Loaded, confirm unload, and move the owned
   published cache aside after verifying its exact path. Confirm that the cache
   is absent, then check Loaded again. Reload passed with one set of hooks.
   Re-enter the session-only fixture password, as expected after unload.
5. Disconnect the VM's virtual network adapter, retaining local loopback. Test
   login extracted Chromium again and completed in about **19 seconds**:
   extraction began at 16:05:36 UTC, Chromium startup at 16:05:45, and credentials
   were captured at 16:05:55. This is an empty extension-cache repeat, not a
   second fresh OS installation or a flushed OS page cache.
6. Send the native-tagged protected request over an explicit TCP connection to
   this Burp's proxy. It returned **HTTP 200**, `user2`, role `B`, issuance `s8`,
   matching the lab's completed-login event. An earlier .NET HTTP client probe
   returned `BAD_INPUT`; the final explicit proxy connection avoids any
   loopback-proxy bypass ambiguity.
7. Repeat Test login with the published cache. It completed in about one second,
   without extraction; the protected request again returned **HTTP 200**, with
   matching issuance `s9`. The network adapter remained disconnected throughout
   both successful cold/cache proofs. The final cache contains only
   `windows-x64`; the candidate JAR and factory memory-file hashes still match.

Lab run: `18dd52d6-d70b-4eb2-9281-4a879040707b`. The VM network was reconnected
afterward, the VM was suspended, and its temporary loopback-only console
configuration was removed. This is installation and basic login smoke
acceptance, not the broader authentication suite. No production change was
required for this Windows check; the five-second fixture limit is not evidence
that users need a Burp memory/configuration change.

Windows installer SHA-256:
`793e42d920e14eff09e5aa438d21076970f306e1a15b6a3752184a374c91f206`;
its Authenticode signature was valid and identified PortSwigger Ltd. Original
Microsoft ISO SHA-256:
`bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38`.
For unattended boot, a separate local copy used the official no-prompt EFI boot
image already included in that ISO; Windows OS files were unchanged. The local
setup seed creates the test account and copies the test payload. Private
provisioning receipts, sanitized environment/protected-request records and
screenshots are retained at
`C:\Users\Rapha\orca\vm-tests\bpsh-windows-20261106`.

## Offline preparation, timing and disk use

The final Linux installation subset ran from 14:04:26 to 14:05:08 UTC with a
temporary guest firewall rule allowing only loopback and established SSH replies.
A new connection to an external address failed; loopback remained available.
The rule dropped 67 packets and the check passed. Its `finally` cleanup removed
only the owned table and restored network access. Gradle also used `--offline`.
This establishes runtime browser preparation without external downloads after
the developer dependencies and normal OS libraries were installed.

Each child probe kept the normal 60-second attempt budget, including extraction
and login. It used a fresh owned user home under the platform's normal temporary
directory, then reused the same home for the cache probe. The child does not
override `java.io.tmpdir`: an earlier artificially deep temporary path made
Chromium fail on Linux. Production already uses its normal short attempt paths.

| Measurement | Windows | Linux |
| --- | ---: | ---: |
| Cold preparation | 6,630 ms | 5,498 ms |
| Cold preparation plus login | 8,373 ms | 6,656 ms |
| Cached preparation plus login | 1,797 ms | 1,765 ms |
| Published cache regular-file bytes | 569,641,957 | 566,912,498 |
| Sampled peak cache regular-file bytes | 816,908,573 | 801,931,622 |

Cold means an empty extension cache, not a flushed OS page cache. These are
single-run observations, not performance guarantees. Peak cache bytes are sampled
every 100 ms and include the archive/staging files under the cache; this is not
a continuous peak or physical allocation measurement, and excludes Chromium's
temporary profile and unrelated files.

Linux `du -sB1` measured 568,381,440 allocated bytes for the published cache and
737,918,976 for the JAR. Together that is 1,306,300,416 allocated bytes, excluding
Java/Burp, system libraries, profiles and old caches. The measured regular-file
sum is 1,304,823,436 bytes. Adding the JAR's logical bytes to the sampled cache
peak gives 1,539,842,560 bytes during first preparation; it is not a measured
whole-machine peak allocation. Physical Windows/Mac allocation was not measured.

Published old caches are intentionally retained for rollback; upgrades can use
more space. Close all sessions using an obsolete cache before manually deleting
only that digest directory. There is no automatic published-cache deletion.

## Reproduction and retained evidence

From `bapp` on Windows:

```powershell
.\gradlew.bat classes test verifyBrowserAssetProducer verifyNativeDocumentation jar --offline --console=plain
.\gradlew.bat browserIntegrationTest `
  --tests 'BrowserJourneyIntegrationTest.coldAndUpgradeProbesUseNormalBudgets' `
  --tests 'BrowserJourneyIntegrationTest.packagedClassloaderUsesExactResourcesWithoutSharedDriverCacheOrJvmMutation' `
  '-PpackagedJar=C:/artifacts/browser-powered-session-handler-dev.jar' `
  '-PoldPackagedJar=C:/artifacts/previous-compatible.jar' --offline --console=plain
```

Use `./gradlew` on Linux, the same two test filters and its copied artifact path.
Omit `oldPackagedJar` if unavailable and retain the resulting NOT RUN status.
The `test-suite` worktree's Java lab guide owns serving and native-example
generation; it remains the source for broader authentication validation.

Generated probe reports are under
`bapp/build/reports/bpsh-runtime/<target>/<artifact SHA-256>/<run UUID>/`.
Private verification receipts, source/test input manifests, sanitized normal
Burp observations and screenshots are retained outside the repository at
`C:\Users\Rapha\orca\vm-tests\bpsh-linux-20261106`. No PIN, user license,
acquired token, browser profile or lab control key is part of this report.

The implementation also normalizes the Unix Gradle wrapper to LF and adds four
Maven metadata checksum pins, verified against Maven Central's published SHA-256
sidecars. Strict dependency verification and dependency versions are unchanged.
The approved [design and resolved review](../designs/universal-packaging.md)
describe the remaining runtime/producer contracts.

# Main integration validation — 2026-11-06

This record qualifies the native Java/universal packaging integration in the commit containing this document. It does not claim the separate authentication lab's full acceptance matrix or physical-token interoperability.

## Inputs and reconciliation

The uncommitted `rfrisch/java-playwright` and `install` working snapshots were captured on 2026-11-06, with both branches and main based on `8accbeab2ba1beb216df3e447842f19ba130a9ff`. Source worktrees were left intact. Main's pre-existing mTLS fixture changes remain outside the integration commit.

The newer native UI, device discovery, input-attributed failures and recovery behavior are retained. Universal packaging, setup-stage observation, safe startup diagnostics and packaged-JAR verification come from `install`. Dependency locking and strict verification remain enabled, including JNA for discovery.

Final source/test/build-input manifest SHA-256:
`ae4f20933689991f82a52f91ce649c904688e88a5023084b6490cc425cb31424`.
The detailed path/checksum manifest and recoverable original snapshots are outside the repository in the task's temporary rollback directory.

The merged runtime no longer starts Python or uses the API as a fallback. The API environment, browser downloads, wheels, obsolete launch settings, legacy JAR and old Python/Hackvertor demo videos were retired from main. Historical API source and user-owned profiles remain; no profile or legacy-store migration occurs. Python fixture utilities are developer tools only.

## Delivered artifact

| Item | Value |
| --- | --- |
| Canonical output | `bapp/build/libs/browser-powered-session-handler-dev.jar` |
| Bytes | 739,898,973 |
| SHA-256 | `d377e2b24d1fa73b9ad1958f8281eaeb1e9423377df6ccd2ebde0848e1006541` |
| Browser targets | Windows x64, Linux x64, Intel macOS |
| Runtime dependencies | Java 21+ inside compatible Burp; no Python runtime or external browser download |

The producer verified all three scoped manifest/ZIP pairs and archive digests. Inspection also confirmed the discovery helper and JNA classes are present and retired API clients are absent. The JAR is generated output and is not committed.

## Automated verification

| Check | Result |
| --- | --- |
| Unit/component suite | 694 discovered; 0 failures/errors; 1 POSIX-only check skipped on Windows |
| Browser asset producer | 17 synthetic cases passed; no downloads or native execution |
| Private-member Javadoc validation | Passed |
| Universal artifact structure and archive integrity | Passed |
| Packaged browser integration | 13 discovered; 0 failures/errors/skips |
| Packaged PKCS#11 integration | 8 discovered; 0 failures/errors/skips; fresh disposable SoftHSM store |
| Cold setup, cache reuse, compatible upgrade and rollback probes | Passed against the delivered JAR and the preceding universal artifact |
| Maintained documentation links and staged whitespace | Passed |

The full browser run exposed a popup-navigation race inherited by both snapshots. Playwright may emit navigation requests before their frames exist; an unguarded frame lookup in status observation interrupted event pumping and token collection. The runner now classifies top-level navigation only when frame metadata establishes it; configured extraction URLs remain independently relevant. The [Playwright Request API](https://playwright.dev/java/docs/api/class-request#request-frame) documents frame unavailability. A regression test covers non-navigation, unavailable/null frames, established main frames and child frames. The marker fixture also uses the ready service-worker registration and reports safe observed paths on failure. The final complete browser suite passed after the production fix; isolated successes and earlier failed runs are not counted as acceptance.

Reproduction from `bapp`, after preparing the locked source archive cache:

```powershell
.\gradlew.bat classes test verifyBrowserAssetProducer verifyNativeDocumentation jar --offline --console=plain
.\gradlew.bat browserIntegrationTest pkcs11IntegrationTest `
  '-PpackagedJar=C:/artifacts/browser-powered-session-handler-dev.jar' `
  '-PoldPackagedJar=C:/artifacts/previous-compatible-universal.jar' `
  '-Ppkcs11Fixture=build/pkcs11-fixtures/FRESH-RUN/fixture.json' --offline --console=plain
```

Generate a fresh disposable fixture using `test/pkcs11_fixture.py`; never reuse a personal or physical token store. The old-artifact property is optional for general development, but was supplied for this integration's successful upgrade/rollback checks.

## Installed Burp smoke test

The light-theme Burp Community 2026.10.1 temporary project was refreshed through its existing extension registration. Loaded was unchecked and unload confirmed before an atomic JAR replacement; Loaded was then checked again. The other lab-probe instance was not reloaded.

The existing registration retains its compatibility filename under the `java-playwright` worktree's ignored `bapp/build/libs/browser-powered-session-handler-dev-windows-x64.jar`; it now contains exactly the same universal JAR bytes as main's canonical output. The previous installed file was preserved outside the repository for rollback. No extension removal/re-addition or global Burp configuration change was needed.

The extension initialized with its HTTP/Proxy handlers and an empty startup Errors panel. The existing certificate journey remained present. A native `BROW.basic.json` export from the separate Java authentication lab was imported into the temporary Project collection with a session-only fixture password and Remember secrets disabled. Test login completed successfully at 19:04:48 local time: event history showed bundled-file verification, driver startup, Chromium startup, signing in and credentials captured. No Python service was used.

This proves packaged initialization and a local browser login inside Burp. It does not establish complete tool/drop/interception acceptance or a new physical-token claim. Current-candidate native Linux and Intel macOS execution were not run here; their payloads were structurally verified. Earlier platform-specific evidence remains attributed to its own recorded artifacts.
The task-created smoke journey was removed after recording the successful login, leaving the original certificate journey intact. The owned Java lab run was stopped through `authLabStop`, which acknowledged cleanup.

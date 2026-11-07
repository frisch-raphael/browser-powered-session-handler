# Installation evidence reused from `install`

The `install` branch is at `../rfrisch-java-playwright`, despite that directory's name. Its validation report (historical reference) owns packaging, cold/cache startup, previous-artifact update/rollback and normal installed-Burp smoke checks. Do not repeat those checks in the authentication lab.

The inspected delivered universal JAR has SHA-256 `0c7c377a20d644feb011de6aa8d715d141a07157c27719879074f1d9c4ab657a`; its current bytes match the report. Installation source/test/build inputs have fingerprint `9d02dbd2174618f1634e2a17a7e7ffeb80d2a0d036b6b102119ae58ad2bab492`. This is separate from the A8 platform JAR used by the authentication lab's current product tests and Burp observations.

| Requirement or owner | Reused evidence | Decision |
| --- | --- | --- |
| H06.offline-load | Fresh Windows installation, Burp Community 2026.10.1 with factory settings, absent extension cache, VM network disconnected; cold and cached logins both yield working protected credentials. Linux exact-JAR tests run with outbound networking blocked. | Reuse for the identified universal artifact. Do not request another VM or claim this reran A8. |
| `BrowserJourneyIntegrationTest.packagedClassloaderUsesExactResourcesWithoutSharedDriverCacheOrJvmMutation` | Existing exact-JAR installation owner, verified on Windows and Linux. | Remove from this lab's browser execution allowlist. Keep the source available and keep its execution owned by `install`; no catalog requirement loses its owner. |
| `BrowserJourneyIntegrationTest.coldAndUpgradeProbesUseNormalBudgets` | Existing cold/cache probes and Windows old/new/rollback probes; final Windows run `c66a8f8c-b35f-45ee-8e13-b0be6be685ba`, Linux run `4421085c-23b5-4f64-a518-73d7f07cabdf`. | Reuse; introduce no second packaging probe. |
| H06.unload-reload | `install` establishes normal-client reload. This lab additionally observes unload while an actual login response is held, disappearance of owned workers/processes, and rejection of its obsolete result. | Keep the additional active-work check: ordinary reload alone does not establish cancellation/cleanup. |
| Broader authentication and host tool checks | Installation uses basic bearer login as smoke coverage and explicitly excludes full authentication acceptance. | Retain credential combinations, replay/pause, diagnostics and actual tool dispatch in this worktree. |

The sanitized Windows proofs were read directly, not inferred from test counts. `normal-burp-offline-cold-proof.json` records HTTP 200, account `user2`, role `B`, issuance `s8`; the cached proof records issuance `s9`. Both match their completed lab logins in run `18dd52d6-d70b-4eb2-9281-4a879040707b`. The pre-load receipt says the extension cache did not exist. The final environment receipt confirms the same artifact hash, only the `windows-x64` cache, no user VM-options file and an unchanged factory VM-options hash.

Those receipts remain under `C:/Users/Rapha/orca/vm-tests/bpsh-windows-20261106/`. Their SHA-256 values are:

| Receipt | SHA-256 |
| --- | --- |
| `normal-burp-offline-cold-proof.json` | `0bb244756499de0b8107f2859447d7fd2fc067064876a2a3cff9eb1bf1991f1b` |
| `normal-burp-offline-cached-proof.json` | `31534a2e7d4eeb2e774e81eccf8d27ce7fb8396fa1962fc51f80e9b8944aa6b4` |
| `burp-installation-sanitized.json` | `46331c918edba8bbaaa6e14f0ca30aae9acf5e781b59ee0073788176211c97f7` |
| `normal-burp-final-environment.json` | `067db7cceb56500555a689e62d27acf14dcfe82527395a934eeb4bf1587a5987` |

The installation report retains an initial five-second example startup failure; the offline cold repeat passes using the application's normal 30-second browser timeout, taking about 19 seconds. Do not remove that limitation or convert it into an authentication defect. Native macOS and Linux previous-artifact rollback remain explicitly unperformed there. Reuse supplies no physical-token or full-profile claim.

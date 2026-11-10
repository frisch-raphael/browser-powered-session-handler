# Repository instructions

The production Burp Montoya extension is in `bapp` and owns authentication in Java. Maintained documentation is indexed in [docs/README.md](docs/README.md); the product and UI contracts are in `docs/product.md` and `docs/designs/interface.md`.

## Repository hygiene

Keep only maintained implementation, tests, fixtures and current documentation. Delete obsolete implementations, superseded plans, archived snapshots and unused assets. Never retain anything solely as historical reference or create an archive or backup of removed material.

## Development delivery

Publish verified universal development builds to `bapp/build/libs/browser-powered-session-handler-dev.jar`. The same JAR bundles Windows x64, Linux x64 and Intel macOS resources. Do not commit generated JARs or browser payloads.

Build directly to the development JAR path. Do not create a candidate JAR to preserve the existing JAR.

After implementation, complete the required checks and build the development JAR before starting any Computer Use. Then proceed with GUI verification when authorized. The latest build must already be available if the user cancels computer interaction, so they can check it themselves without requesting another build.

## Test ownership

The broader authentication lab and acceptance suites are integrated in `test/authentication-lab` and `test/federation-client`. Reuse their fixtures; do not duplicate the lab or harness. Production acceptance overlays live under `test/authentication-lab/production-tests` and run only in isolated captured builds. Python helper scripts are developer tools only.

## Verification VMs

Use these existing VMware Workstation VMs for Windows and Linux Burp UI verification:

| Platform | VM name | VM configuration |
| --- | --- | --- |
| Windows 11 | BPSH fresh Windows 11 verification | `C:\Users\Rapha\orca\vm-tests\bpsh-windows-20261106\bpsh-windows.vmx` |
| Ubuntu 24.04 x64 | BPSH Linux verification (Ubuntu 24.04) | `C:\Users\Rapha\orca\vm-tests\bpsh-linux-20261106\bpsh-linux.vmx` |

Build the active worktree's development JAR before Computer Use, then transfer that exact artifact into the selected VM and verify its checksum. Use the guest's installed Burp and refresh its existing extension entry. Report results against the current artifact; previous VM reports do not qualify a new build.

WSL2 smoke tests are separate evidence and do not replace Linux VM or Burp UI verification unless the user explicitly requests WSL. The Linux VM's existing SSH/transfer helper is `C:\Users\Rapha\orca\vm-tests\bpsh-linux-20261106\vm.py`; keep its private key and guest credentials out of logs and documentation.

## Burp refresh

Use the extension JAR from the active worktree.

Build before using Computer Use, including for extension refresh. After the build, refresh the existing extension by toggling its Loaded checkbox off and then on. Do not remove/re-add the extension. Disposable test drafts do not require preserving before an authorized refresh.

## Code structure

Production Java uses feature packages under `bapp/src/main/java/bpsh`; native tests mirror those packages. Follow `docs/designs/code-structure.md`. Keep package dependencies acyclic and run `verifyArchitecture` (also part of `check`). Journey domain, authentication/session and request settings must not import Swing, Montoya or Playwright. Runtime readers consume JourneyCatalog; edits and storage belong to journey.editing/persistence. Keep algorithms shared in their owning codec/compiler rather than duplicating them in the UI. Intentional lab binding changes use `:auth-lab:refreshBindings`; review the diff and run acceptance in a separate invocation.

## UI validation

Show configuration and HTTP authentication errors inline beside the relevant input or settings group, with specific, actionable guidance. An explicit Test login, Retry or recording action should reveal that page and focus the identified input; background validation must not steal focus. Do not open an error popup for these problems. When the server cannot identify which credential is wrong, show the observed error at the HTTP authentication group rather than blaming a particular field.

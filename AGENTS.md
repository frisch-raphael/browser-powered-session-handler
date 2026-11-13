# Repository instructions
The codebase is yours: what's it for and how it's built are your call, and you'll keep building it. Don't preserve any preexisting state should to be "safe".
The production Burp Montoya extension is in `bapp` and owns authentication in Java. Maintained documentation is indexed in [docs/README.md](docs/README.md); the product and UI contracts are in `docs/product.md` and `docs/designs/interface.md`.

## Tooltips

Formatted tooltips are supported. Follow [the Swing tooltip contract](docs/designs/swing-tooltips.md) and use `UiTooltips.set` with plain text and component-owned tooltip creation. Burp can disable HTML on the actual `JToolTip`; opt in there after host UI installation only for builder-produced content, without changing global defaults or removing formatting. Carry caption provenance with `UiTooltips.copy`, never by copying HTML strings. Keep HTML disabled in literal-data renderers. Test actual tooltip rendering under an HTML-disabled host UI, theme updates, caption/control parity, escaped data and plain accessible descriptions. Preserve the injection and resource-loading tests, including their unsafe positive control.

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

The Linux VM uses a minimal Openbox desktop. It needs `xserver-xorg-input-libinput` for its VMware mouse and keyboard, `open-vm-tools-desktop` for desktop integration, and `python3-xdg` for Openbox autostart. The desktop starts through `bpsh-verification-desktop.service`; a 2 GiB swap file supplements its 6 GiB RAM. Check kernel OOM messages if Burp disappears. The guest's `~/.config/openbox/rc.xml` uses one workspace. Its `~/.config/openbox/autostart` sets a visible background, disables display blanking, and starts the installed Burp with a 3 GiB heap and an instance lock. An empty workspace can otherwise look like a black-screen failure; check the active workspace and the Burp window's workspace before changing graphics drivers.

The Linux VMX currently enables USB input (`usb.present`, `ehci.present`, and `keyboard.vusb.enable` are `TRUE`) and sets `keyboard.allowBothIRQs = "FALSE"`; change VMX settings only after a clean guest shutdown. These input workarounds have not established working console input: automated host clicks on Burp's Next button and Ctrl+G still had no visible effect after reboot. SSH responsiveness, installed Tools, and guest-side XTEST/xdotool clicks do not prove that VMware console input works. Verify the actual console path separately and report any unverified input path explicitly.

## Burp refresh

Use the extension JAR from the active worktree.

For the normal Windows verification VM extension entry, use `C:\bpsh\browser-powered-session-handler-dev.jar`. Updating this stable VM copy is part of development delivery: after each verified build used for VM testing or handed to the user, overwrite that exact file directly from the active worktree's `bapp/build/libs/browser-powered-session-handler-dev.jar` and compare host/guest SHA-256 before refreshing Burp. Do not leave the stable copy stale when an isolated acceptance run uses its captured JAR under `C:\bpsh\host-tests\...\assets\<sha256>.jar`; record that run's exact captured path and checksum separately. The stable C: path is the documented path for manual Windows VM testing.

Build before using Computer Use, including for extension refresh. After the build, refresh the existing extension by toggling its Loaded checkbox off and then on. Do not remove/re-add the extension. Disposable test drafts do not require preserving before an authorized refresh.

## Code structure

Production Java uses feature packages under `bapp/src/main/java/bpsh`; native tests mirror those packages. Follow `docs/designs/code-structure.md`. Keep package dependencies acyclic and run `verifyArchitecture` (also part of `check`). Journey domain, authentication/session and request settings must not import Swing, Montoya or Playwright. Runtime readers consume JourneyCatalog; edits and storage belong to journey.editing/persistence. Keep algorithms shared in their owning codec/compiler rather than duplicating them in the UI. Intentional lab binding changes use `:auth-lab:refreshBindings`; review the diff and run acceptance in a separate invocation.

## UI validation

Show configuration and HTTP authentication errors inline beside the relevant input or settings group, with specific, actionable guidance. An explicit Test login, Retry or recording action should reveal that page and focus the identified input; background validation must not steal focus. Test login errors associated with a field, settings group or journey step must never open an error popup: show the error at that location instead. A popup is allowed for a generic error with no associated UI location. When the server cannot identify which credential is wrong, show the observed error at the HTTP authentication group rather than blaming a particular field.

## Local verification VM access

Keep guest passwords, VMware encryption passwords and SSH private keys out of tracked files, tool output, reports and chat. Read credentials from their local files without echoing values. Desktop unlocking is one-time provisioning outside the unattended acceptance run.

The Windows verification VM is configured for automatic sign-in as `tester`, with idle locking and display/sleep timeouts disabled for unattended tests. Its account password is retained for VMware guest operations. Autologon uses Microsoft's signed Sysinternals utility with the password stored as an LSA secret; do not write a plaintext `DefaultPassword` registry value. These settings apply only to the verification guest.

Windows credential sources:

- Guest sign-in: [guest-credentials.json](C:/Users/Rapha/orca/vm-tests/bpsh-windows-20261106/guest-credentials.json), with `username` and `password` fields.
- VMware encryption: [vm-encryption-private.json](C:/Users/Rapha/orca/vm-tests/bpsh-windows-20261106/vm-encryption-private.json), with a `password` field.

Linux SSH/transfer helper: `C:\Users\Rapha\orca\vm-tests\bpsh-linux-20261106\vm.py`. The Linux guest account is `tester`; password login is locked, so use the SSH helper.

## Local federation test trust

The dedicated federation CA is retained in this host account's Windows CurrentUser/Root store for repeated testing, as explicitly requested by the user. Its current certificate expires in November 2036; public certificate and installation metadata are under `test/authentication-lab/build/prepared/federation/ca/ca.crt` and `test/authentication-lab/build/prepared/federation/root-installation.json`. Do not remove this CA after ordinary test runs. The default authority lifetime is 3650 days, with short-lived server certificates generated automatically per run. Normal tests never install trust or change hosts mappings; see [Windows federation setup](test/authentication-lab/Windows-Federation-Setup.md). Keep the signing key and its password private.

# Working on the native extension

Read [root AGENTS.md](../AGENTS.md) before changing or testing this checkout.
The native extension is implemented; this is not the Montoya starter template.

## Architecture and build

[README.md](README.md) describes the service boundaries, build commands and
existing verification tasks. The entry point is `src/main/java/Extension.java`.
Java compatibility is 21. Dependencies and browser assets are pinned through
Gradle, lock files, verification metadata and the browser source lock.

The deployed runtime is the Java BApp with bundled Playwright/Chromium assets.
Do not add a Python API fallback, Hackvertor dependency, system-browser installer
or separate Java launcher.

## Changes and documentation

Follow [the authentication design](../docs/designs/bapp-owned-authentication.md)
and its approved [universal packaging amendment](../docs/designs/universal-packaging.md).
Ship one offline Chromium-only JAR for Windows x64, Linux x64 and Intel macOS;
retain scoped manifests and previous cache identities. Do not restore per-OS
artifacts, ARM payloads, browser downloads or Burp-browser discovery.
[PRODUCT.md](../docs/product.md) and [DESIGN.md](../docs/designs/interface.md)
record current interface commitments.

Document responsibilities, ownership, lifecycle and failures, including private
helpers, using the existing Doxide-compatible Java comments.
Run appropriate existing checks for changed behavior; distinguish component
results from browser/native integration and actual host acceptance.

## Coordination

The separate `test-suite` worktree owns the broader authentication lab, full
acceptance suite and stress work. Do not duplicate its fixtures or coverage
matrix here. Keep changes scoped so its reuse audit can integrate the actual
production revision.

Do not report unfinished or skipped platform/provider/host checks as passing.
Build a separate candidate while its installed JAR is loaded, then follow the
Loaded checkbox off/on refresh procedure from root AGENTS.md.

# Working on the native extension

Read [root AGENTS.md](../AGENTS.md) before changing or testing this checkout.
The native extension is implemented; this is not the Montoya starter template.

## Architecture and build

[README.md](README.md) describes the service boundaries, build commands and
existing verification tasks. The entry point is `src/main/java/bpsh/Extension.java`.
Java compatibility is 21. Dependencies and browser assets are pinned through
Gradle, lock files, verification metadata and the browser source lock.

The deployed runtime is the Java BApp with bundled Playwright/Chromium assets.
Do not add a Python API fallback, Hackvertor dependency, system-browser installer
or separate Java launcher.

## Changes and documentation

Follow [the authentication design](../docs/designs/bapp-owned-authentication.md)
and the [universal packaging contract](../docs/designs/universal-packaging.md).
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

The integrated `test/authentication-lab` and `test/federation-client` modules own
the broader authentication lab and acceptance suite. Reuse their fixtures and
assertions. Production acceptance overlays run only in isolated captures.

Do not report unfinished or skipped platform/provider/host checks as passing.
Use the active worktree's development JAR. Complete checks and build directly
to that path before Computer Use, then refresh the existing extension through
the Loaded checkbox. Never create a candidate JAR to preserve the installed file. Remove superseded code, fixtures
and documentation instead of retaining historical copies.

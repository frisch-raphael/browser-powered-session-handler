# Driver classpath resource removal: focused design evidence

* **Date:** 2026-11-06
* **Scope:** Private scratch archive and existing local probe only. No production implementation or build file was changed.

## Inputs and operation

The source artifact was the existing `java-playwright` worktree's Windows development JAR, `browser-powered-session-handler-dev-windows-x64.jar`, SHA-256 `42101d8b188519c78434b5b8dac382f4f04e47bc874e52d0b6894beb3d04715f`.

A new private scratch directory outside the repository held a copied JAR with every root `driver/` classpath resource removed. Java classes under `com/microsoft/playwright/` and the verified execution asset ZIP under `META-INF/bpsh/` were retained. The operation removed 145 entries totaling 107,732,186 uncompressed bytes. The scratch JAR SHA-256 is `0da0cfa6a713136cbb74932bee15baa1dd774eb44cd401ae73026881751a0773`.

The scratch outer JAR used stored entries to make the experiment quick. Its size is not a proposed distribution size or compression measurement. Its inner execution asset ZIP was unchanged.

## Result

The existing Java source probe ran against only that scratch JAR and the JDK. It used `BrowserRuntimeManager` and `PlaywrightDriverAdapter`, then selected the manager's bundled Chromium executable, version `156.0.8078.4`, in headless mode. The probe successfully filled and submitted a loopback fixture form, captured the JSON response and HTTP cookie, and verified that a fresh browser context had no inherited cookies. Its owned browser/driver try-with-resources scopes completed.

The first run also succeeded with the installed Burp Chromium, but the bundled-browser run is the relevant result for the selected architecture. No real login or Burp license activation was involved. The pinned upstream `Driver.java` and `DriverJar.java` sources were also inspected: their resource-extraction path belongs to the public driver installation/bootstrap machinery that the extension's owned adapter bypasses.

## Limits and required follow-up

This is Windows feasibility evidence for removing the root classpath `driver/` data while retaining complete execution payloads. It is not a universal artifact, a Linux/macOS result, a Burp-loaded test or proof of every lazy SDK feature. Completing Java resource scopes is not independent evidence of every OS descendant's termination. The final packaged checks must still verify required application operations, shared-driver/JVM isolation and owned-process cleanup using the delivered universal JAR on each exercised target.

The implementation should remove the duplicate classpath data and test the resulting bootstrap, rather than retain it solely to satisfy the old resource-presence assertion. A later pinned dependency update must repeat the packaged checks; it must not assume this result covers an arbitrary future SDK.

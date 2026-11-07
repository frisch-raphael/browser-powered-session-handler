# Code structure refactor: validation

2026-11-07. Starting point: main `386b81b`. The refactor reorganizes production/native acceptance sources into feature packages and separates existing responsibilities without changing the native document schema, storage keys, tag grammar or browser payload lock.

## Source and dependency review

- Production: 73 Java source files in 14 registered `bpsh` packages. No default-package source files remain in production, native tests or acceptance extensions.
- `verifyArchitecture` passes package/directory matching, explicit allowed dependencies and absence of package cycles. Model/session code is independent of Swing, Montoya and Playwright imports. A separate generated project proves that forbidden dependencies and cycles are rejected with both explicit and wildcard imports.
- Acquisition results, preparation stages, credential-use provenance and stable journey keys are shared contracts. Browser/native wiring lives outside the coordinator's policy implementation. Executor/thread ownership is separate from coordinator state.
- Strict document, journey and scalar codecs have distinct owners. Draft snapshots contain no Swing types, and one compiler handles their executable representation. Browser manifest/path validation is separate from cache publication. Private file helpers are shared without a user-library dependency on browser setup.
- Modal presentation, layout, validation wording and transfer I/O are separate from editor coordination. UI implementation classes remain package-private; tests that exercise them live in the UI package. A test-only runtime fixture provides unsupported-platform observations without exposing manifest internals.
- The launchers and collectors share one configuration-input manifest. Explicit binding refresh preserves nullable fields and unbound entries and has a regression for that behavior. It grants no acceptance.
- All 980 catalog requirement definitions, recipes, expected facts and profile memberships compare equal to the starting point when source-binding metadata is excluded. Schema resources and `browser-assets.lock.json` are unchanged. Runtime dependency versions are unchanged.

The native acceptance extensions remain separate same-named test owners where isolated snapshot testing requires them. This is not a claim that every historical test overlap or remaining controller responsibility has been eliminated. The architecture guide identifies the boundaries and maintenance rules; DRY/SOLID were reviewed through these concrete ownership and dependency changes, rather than treated as a blanket certification.

## Automated checks

| Check | Result |
| --- | --- |
| Native regressions | 699 tests; zero failures/errors; one existing platform-specific skip |
| Lab checks | 730 tests; zero failures/errors/skips |
| Federation checks | 27 tests; zero failures/errors/skips; no provider-login acceptance claimed |
| Architecture | 73 Java files, 14 packages, no cycles; forbidden-dependency/cycle negative probes also pass |
| Private-member documentation lint | Passed |
| Browser asset producer | 17 synthetic cases passed; no downloads/native execution in this gate |
| Packaged browser integration | 13 checks passed; zero skips |
| Packaged native/SoftHSM integration | Eight checks passed; zero skips; fresh disposable software-token store |
| Isolated production components | 569 checks passed; zero skips; 313 scoped requirements PASS, none blocked/failed, complete cleanup |

Counts overlap and must not be summed as distinct scenarios. Isolated component invocation: `5e0afda6-b6a5-49ab-96c7-e418b7b1cc62`; source boundary: `5294f3158df91ed38f19aac03b47529d9715d9f7068f3ce9b39905bc9faa91cd`.

The native proxy regression previously combined an excluded configured-authentication challenge with an unavailable listener and expected terminal PROXY_AUTH for both. Main's earlier authentication fixes already classify positively identified unavailable sockets as retryable TRANSPORT. The regression now exercises the supported unauthenticated unavailable route, requires PROXY/TRANSPORT and retryability, and still requires zero direct-origin requests. No production proxy behavior changed for this correction.

The initial package-migration checks also identified test reflection targeting helpers in their former classes, and a binding-maintenance serializer omitting required JSON nulls. Those failures were diagnosed, corrected and covered by the successful checks above; preliminary failed results were not promoted to passes.

## Delivered artifact

Universal development JAR: `bapp/build/libs/browser-powered-session-handler-dev.jar`.

- Size: 739,929,642 bytes.
- SHA-256: `cd97e28238ba3b20716d6a42cd1d6af3395099ca5312e7bda4eb2f71678698d0`.
- Montoya entry point: `bpsh.Extension`.
- All bundled platform archives pass their existing integrity checks. Stale default-package classes and host/test APIs are rejected.
- Every packaged `bpsh` class was compared byte-for-byte with the current compiled production output; none differed.

No manual UI walkthrough, extension reload, real-device qualification or macOS execution was performed. Existing browser-cache identities and serialized journey formats are retained. Generated JARs, caches, fixtures, keys and detailed run evidence remain outside version control.

See [code structure and working rules](../designs/code-structure.md) and [the authentication lab guide](../../test/authentication-lab/README.md) for layout, commands and scoped prerequisites.

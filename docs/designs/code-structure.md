# Java architecture

The tree follows application responsibilities. Domain contracts sit with their feature; concrete browser, filesystem and Burp integrations sit at explicit outer boundaries. Java packages are not split merely to give every class a directory.

```text
bpsh/
  Extension.java             Composition and host lifecycle
  journey/                   Definitions, drafts, identity, secrets, read-only catalog
    editing/                 Workspace, draft compiler, transfer and storage orchestration
    persistence/             Strict JSON, document envelopes and concrete stores
  authentication/            Failures, progress and scheduling policy
    credentials/             Extraction observations, results and lifetimes
    session/                 Coordinator, executors and event history
  request/                   Automatic rules and request-origin settings
  browser/                   Real browser attempts and traffic provenance
    runtime/                 Bundled browser assets and driver lifecycle
    mtls/                    Device discovery and attempt TLS transport
  burp/
    http/                    Montoya hooks, tags, injection, recovery and diagnostics
    ui/                      Swing editor and explicit user actions
  platform/files/            Restricted file creation attributes
```

## Boundary decisions

`JourneyCatalog` is the read-only publication contract. Its immutable entries and snapshots expose saved definitions and generation/availability checks. Authentication, tag resolution, HTTP processing and request menus cannot mutate the workspace or call its storage methods. `JourneyWorkspace` implements the contract and owns editable collections, generation changes and publication. It is an authoring service, not configuration data.

`JourneyStorage` owns observed storage revisions and external-load epochs. It loads and saves through the existing conflict-checked stores, distinguishes watcher echoes from external changes and merges final captured edits during unload. The UI captures input and presents outcomes; it no longer owns project revisions, library hashes or final document merging. Ordinary saves persist before publication, while final saves deliberately avoid live runtime publication.

`JourneyDocument` is the owned storage/transfer envelope. `JourneyJson` owns the strict shared serialization boundary; `ProjectStore` only reads/writes Burp project persistence. `NativeDocumentCodec`, `NativeJourneyCodec` and `NativeJson` remain package-private format implementation details. Domain naming and typed secret validation belong to `JourneyNames` and `JourneySecrets`, so browser execution and diagnostics do not call a persistence facade.

`AuthenticationPolicy` exposes only deadlines and admission limits. `AuthenticationCoordinator` cannot depend on tool selection, automatic injection rules, editor state or concrete journey storage. Its existing attempt/retry ports bind real browser and native behavior in `BrowserAuthentication`. Policy and catalog substitution are exercised directly by `AuthenticationBoundaryTest`.

`RequestSettings` owns automatic request rules. Its `Tool` enum is independent of Montoya and retains existing persisted names. The Burp HTTP adapter matches host tool names at its boundary. `CapturedCookie` similarly carries browser-independent cookie observations; only `BrowserFlowRunner` translates Playwright cookies.

## Dependency rules

- `journey` uses JDK types only and imports no application or adapter packages.
- Authentication contracts and request settings may use journey values. Session policy depends on the read-only catalog and credential contracts, never editing, persistence, UI, browser or Montoya.
- Credential extraction may use Jackson/RE2 for bounded parsing, but does not import Playwright, Montoya or Swing.
- Editing depends on journey values, request settings and the explicit persistence boundary. Concrete storage owns document validation and I/O; the catalog never exposes those operations.
- Browser execution adapts core attempt contracts. Runtime/native resources are grouped beneath the browser that owns their lifecycle.
- Burp UI/HTTP adapters depend on core contracts. Only the composition root wires the complete graph.
- Package paths, permitted edges, framework exclusions and absence of cycles are enforced by `verifyArchitecture`, included in `check`.

Public types represent boundaries consumed by another package. Internal JSON helpers, UI forms and process details stay package-private. A new interface must support a real substitution or ownership boundary; do not introduce one per class.

## Review and verification

The structure applies the [Java architecture review principles](https://github.com/decebals/claude-code-java/blob/main/skills/architecture-review/SKILL.md): cohesive feature ownership, explicit APIs, inward dependencies, framework-free domain code and enforceable boundaries. Tests mirror owning packages. Shared integration fixtures remain shared, and isolated production acceptance extensions stay under `test/authentication-lab/production-tests`.

Run from the repository root:

```powershell
.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline
```

Browser and PKCS#11 tasks exercise the actual universal development JAR; they require their explicit prerequisites. Native JSON schemas, project keys, tag syntax, deadlines, credential ownership and browser-cache identity are compatibility contracts, independent of Java package layout. The Montoya entry point remains `bpsh.Extension`.

After intentional source/package or harness changes, refresh reviewed binding fingerprints with `:auth-lab:refreshBindings --offline`, inspect the diff, then run selected acceptance profiles in a new invocation. This grants no acceptance itself. READMEs under the federation source tree participate in its evidence fingerprint.

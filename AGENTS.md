# Repository instructions

The production Burp Montoya extension is in `bapp` and owns authentication in Java. `api` contains unsupported historical Python reference sources, not a runtime dependency. Maintained documentation is indexed in [docs/README.md](docs/README.md); the product and UI contracts are in `docs/product.md` and `docs/designs/interface.md`.

## Development delivery

Publish verified universal development builds to `bapp/build/libs/browser-powered-session-handler-dev.jar`. The same JAR bundles Windows x64, Linux x64 and Intel macOS resources. Do not commit generated JARs or browser payloads.

## Test ownership

The broader authentication lab and acceptance suites are integrated in `test/authentication-lab` and `test/federation-client`. Reuse their fixtures; do not duplicate the lab or harness. Production acceptance overlays live under `test/authentication-lab/production-tests` and run only in isolated captured builds. Python helper scripts are developer tools only.

## Burp refresh

Toggle the existing extension's Loaded checkbox off before replacing its JAR, then on after replacement. Do not remove/re-add the extension. Disposable test drafts do not require preserving before an authorized refresh.

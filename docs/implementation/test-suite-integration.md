# Test-suite integration into main

Date: 2026-11-07. Source: the uncommitted `rfrisch/test-suite` worktree based on `8accbeab2ba1beb216df3e447842f19ba130a9ff`. Integration target: main at `fbb1d72`, including its existing local authentication fixes during validation.

## Integrated source

- Java controlled authentication applications, requirement catalog, HTTP proofs, lifecycle controls and host probe in `test/authentication-lab`.
- Locked Java federation client/API and provider definitions in `test/federation-client`.
- Production acceptance overlays in `test/authentication-lab/production-tests`. Main's native test files remain intact. Only isolated production captures substitute the overlays.
- Gradle orchestration under `bapp/gradle/auth-lab*`, isolated from the extension runtime dependency graph. Existing production dependency versions and universal packaging remain unchanged.
- Full reviewed design, cases, contracts and terminology under `docs/designs`, with useful requirements, decisions and historical validation in `docs/designs/authentication-test-lab`.

The older Python lab prototype, generated binaries, browser archives, caches, private keys/certificates, run evidence and raw review/progress artifacts were not imported. Existing historical developer utilities remain available without a Python runtime environment for the extension.

## Changes needed for main

Production tasks default to this checkout, rather than an absolute sibling worktree path. A portable reviewed policy selects owners and exclusions; each invocation captures the actual production inventory and source hashes, checks that bytes have not changed, and executes those retained bytes. Its audit is hashed into the invocation plan. The collector verifies the captured source, compiled outputs, dependency pins, current test/configuration hashes, JUnit results and observed facts.

Binding provenance identifies reviewed tests. Actual production revision comes from the current capture and must agree across the audit, plan, context and observations. A changed source, audit, XML or mismatched configuration cannot earn passing coverage. A regression explicitly checks audit tampering, changed captured source and a foreign production revision.

The source/configuration files used by catalog fingerprints have explicit LF rules. Their staged bytes were checked against the working files. The historical authentication baseline is retained byte-for-byte. The host-probe lock now matches main's Montoya API 2026.4.

## Verification

| Check | Result |
| --- | --- |
| Main native regressions | 699 tests, zero failures/errors, one platform-specific skip |
| Java lab checks, including new capture regression | 729 tests, zero failures/errors/skips |
| Federation unit checks | 27 tests, zero failures/errors/skips; no provider login acceptance |
| Host probe | Compiles against Montoya 2026.4 |
| Fixture acceptance | 523 requirements PASS, none blocked/failed, complete cleanup; invocation `9e034c39-398f-442a-a16c-67ef96941493` |
| Diagnostics acceptance | 18 requirements PASS through 31 JUnit checks, none blocked/failed, complete cleanup; invocation `7545c6d4-88ee-4b23-a79b-bac252897b29` |
| Full production components | 569 tests, zero failures/errors/skips; 313 requirements PASS, 0 blocked; invocation `ab205a7d-2438-4663-846f-ac8f5591fe26` |

Counts overlap and must not be added as independent coverage.

An earlier scoped browser run passed all 50 automated checks without skips, using invocation `89aa96ca-baca-4250-8889-780aaccebcf5` and boundary `d6d02200345b527e424ef6184394d1d4f7f88bac4f1bc17679b710b90a4f1df1`. That run preceded final harness fingerprint adjustments; it does not establish final catalog/profile acceptance. A concurrent preliminary baseline/recovery/diagnostics aggregate was rejected after its harness inputs changed, even though its 18 browser checks passed. The fresh diagnostics and fixture profiles above validate the completed evidence join. Preliminary rejected captures were not relabeled as passing.

Validation used the existing uncommitted main authentication fixes. Those files and the local mTLS changes were preserved outside the original suite integration commit. They are included in the subsequent main delivery; the native source/test bytes were checked against the passing capture before that delivery. Existing root production dependency versions were compared and remained identical.

No additional Burp/UI acceptance or install/refresh was performed. Full federation/transport/host/capability and `all` acceptance are not claimed. Provider assets, certificates and private software-token stores need explicit preparation in this checkout; the old worktree's generated material was not copied. No push was performed.

Generated evidence is local under ignored `test/authentication-lab/build`; it is not committed. [The lab guide](../../test/authentication-lab/README.md) documents commands and prerequisites.

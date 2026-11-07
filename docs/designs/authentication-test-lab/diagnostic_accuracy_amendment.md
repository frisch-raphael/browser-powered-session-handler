# User-visible diagnostic accuracy: design amendment

**Date:** 2026-11-05. **Author requirement:** The displayed outcome must match what happened; a missing selected cookie must not be reported as a connection failure. **State:** The author approved the addition and Stage 8 re-review. The first Stage 8 re-audit completed with no new findings and the same two earlier Nits (report (historical reference)). The author then approved Stage 9; its first readiness round (historical reference) found implementation-contract gaps, with no separate diagnostic-policy defect. The author approved the explained repair proposal; its document changes are applied and fresh Stage 9 round 2 is running. No implementation or passing-test claim.

## Scope and acceptance

The [design's diagnostic contract](../../designs/authentication-test-lab.md#user-visible-diagnostic-accuracy) requires actual production summary/details/status and applicable request feedback to agree with the independently induced outcome, known stage/cause, safe journey/output attribution and current attempt/revision. The [18 named requirements](../../designs/authentication-test-lab-cases.md#user-visible-diagnostic-contract) include the author's missing-cookie example and a genuine connection-refused contrast. They also cover trust/navigation/step failures, confirmed login rejection, missing/ambiguous/malformed outputs, incomplete sets, rejected protected use, unresolved tags, missing capabilities, cancellation, exhausted attempts, stale results and success presentation.

Required and forbidden message meaning are assertions. A correct internal error enum or detailed explanation cannot excuse a misleading displayed headline. Whole-message snapshots are unnecessary: wording can improve while preserving the required facts. Unknown causes remain uncertain; wrappers preserve the underlying known failure; extraction alone does not establish protected access. Current success and revision changes cannot leave stale active errors or transfer an old failure to another journey. Ordinary unchanged forwarding and tagged atomic stopping require different, accurate feedback. Displayed and exported evidence excludes secrets.

## Allocation and reuse

Actual production failure mapping/presentation and editor/state tests own the semantic matrix. At P2, reuse the existing `DiagnosticsTest`, registry/editor assertions and already-owned browser/transport failure witnesses after the mandatory fresh full audit; extend only missing assertions. The added file-inventory row names the existing diagnostic suite rather than creating a parallel suite. Diagnostic expectations use the existing catalog `registry.json`; no extra data file, production classifier, UI framework or lab renderer is introduced.

The existing H05 test/paused-test checkpoints contrast missing-cookie extraction with an actual connection failure, and late-result verifies freshness in Burp. H02 checks real request feedback. These observations remain within the existing six H05 and 24 overall host-manual entries. They do not repeat the 18-case matrix through Burp. Requirements may share execution IDs with existing assertions when evidence establishes both claims. Missing diagnostic information/presentation seams stay blocked pending the production contract.

The diagnostic profile selects these owning assertions and shared propagation witnesses. Default component tests remain independent of browsers, providers and native middleware; only selected propagation witnesses need their actual prerequisites. No upstream proxy-authentication scenario is added. Internal mTLS-proxy credentials remain governed by the existing retained scope.

## Catalog accounting and review impact

One group, `CORE.diagnostics`, adds **18 automated requirements**. The active catalog becomes **41 groups / 980 entries: 940 automated requirements, 24 host-manual entries and 16 capability assessments**. These remain requirements, not a count of new tests or passing executions. H05's existing entry count remains six. Checks of the documented table confirm these sums and all 18 distinct diagnostic variants.

The main document now has 582 logical lines: FeatureRange 1–417; DetailedRange 418–582. The amendment changes both reviewed inputs. Earlier completed reports retain their original recorded hashes, counts and line references as historical results; they do not establish independent review of this addition. The approved first Stage 8 re-audit reviewed the amended inputs and found no new architectural issue. The original Stage 8 result remains preserved separately. Stage 9 subsequently began with the author's approval and has an unresolved first-round repair proposal. No fresh audit of the moving sibling code/test tree was performed; it remains at P2. The two earlier baseline-membership/marker-definition issues remain open, now also addressed by proposed readiness repairs.

Input before amendment: main SHA-256 `0A149D4497E172CEAC9C819A37E25334AEBDF4A92ADFE4EC9D629335B63687D9`; matrix `E8E872D2E2C0E02AE871179BD314F2101141339D9BE2B35541BD473577DF53BF`.

Amended inputs: main SHA-256 `D6A328728ABF48CA81A84B030DFD462B0C2C57DEF38590571AB91A652997A691`; matrix `3DD77562A3A994272FFADC6C6E3F97182BDE6E1614E7DFF44A4F895D39355555`.

Only design/context/progress Markdown was changed. No implementation, tests, apps or containers were run. Markdown tables/fences, local references, catalog totals and variant membership are the scope of the document checks, not implementation validation.

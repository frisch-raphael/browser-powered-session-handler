# Documentation

The extension and authentication lab are maintained in Java. This index contains current contracts and operating instructions.

## Product and development

- [User guide](../README.md)
- [Build, prerequisites and verification](../bapp/README.md)
- [Product contract](product.md)
- [Code structure and dependency rules](designs/code-structure.md)
- [BApp Store requirements](bapp-store-requirements.md), [compliance audit](bapp-store-verification.md) and [fix plan](bapp-store-fix-plan.md)

## Runtime contracts

- [Authentication, request tags and recovery](designs/bapp-owned-authentication.md)
- [Journey interface and credential controls](designs/interface.md)
- [Formatted Swing tooltips and Burp rendering](designs/swing-tooltips.md)
- [Universal offline packaging](designs/universal-packaging.md)
- [HTTP authentication](designs/http-authentication.md) - Basic/NTLM implementation, isolated acceptance and Linux Burp qualification completed; Windows Burp UI qualification remains separate.

## Proposed features

- [Burp Browser design](superpowers/specs/2026-11-12-burp-browser-design.md) and [implementation plan](superpowers/plans/2026-11-12-burp-browser.md) - approved design for isolated sessions and universal driver-only packaging; plan review and execution method pending.

- [Session handling by URL and proxy port](designs/session-handling-by-url-and-proxy-port.md) - routing is implemented, with best-effort native Proxy DROP. Final acceptance and platform qualification remain in progress.
- [Browser journey recording](designs/browser-journey-recording.md) - recording and native review are implemented; popup edge cases and final acceptance remain under qualification.

## Authentication lab

- [Run the Java lab](../test/authentication-lab/README.md)
- [Architecture and ownership](designs/authentication-test-lab.md)
- [Case matrix](designs/authentication-test-lab-cases.md)
- [Data and execution contracts](designs/authentication-test-lab-contracts.md)
- [Terms and examples](designs/authentication-test-lab-terms.md)
- [Capability assessment recipes](designs/capability-assessments.md)
- [Real Burp acceptance implementation plan](designs/burp-host-acceptance-plan.md) - separate-agent plan for a small lab-owned suite using real Burp tools and independent server evidence; not implemented yet.
- [Federation client](../test/federation-client/README.md)

Each verification run records its source, artifact and actual results under the owning module's ignored build directory. Passing unit tests, browser execution, software-token checks and actual Burp acceptance establish different facts. Use the reports from the artifact being qualified.

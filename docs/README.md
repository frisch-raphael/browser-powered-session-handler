# Documentation

The extension and authentication lab are maintained in Java. This index contains current contracts and operating instructions.

## Product and development

- [User guide](../README.md)
- [Build, prerequisites and verification](../bapp/README.md)
- [Product contract](product.md)
- [Code structure and dependency rules](designs/code-structure.md)

## Runtime contracts

- [Authentication, request tags and recovery](designs/bapp-owned-authentication.md)
- [Journey interface and credential controls](designs/interface.md)
- [Universal offline packaging](designs/universal-packaging.md)

## Proposed features

- [Browser journey recording](designs/browser-journey-recording.md) - recording and native review are implemented; popup edge cases and final acceptance remain under qualification.

## Authentication lab

- [Run the Java lab](../test/authentication-lab/README.md)
- [Architecture and ownership](designs/authentication-test-lab.md)
- [Case matrix](designs/authentication-test-lab-cases.md)
- [Data and execution contracts](designs/authentication-test-lab-contracts.md)
- [Terms and examples](designs/authentication-test-lab-terms.md)
- [Capability assessment recipes](designs/capability-assessments.md)
- [Federation client](../test/federation-client/README.md)

Each verification run records its source, artifact and actual results under the owning module's ignored build directory. Passing unit tests, browser execution, software-token checks and actual Burp acceptance establish different facts. Use the reports from the artifact being qualified.

# Documentation

The extension runtime is Java-owned. Python is not required to install or run it.

## Product and development

- [User guide](../README.md)
- [Build, prerequisites and verification](../bapp/README.md)
- [Product contract](product.md)

## Maintained designs

- [Native authentication and recovery](designs/bapp-owned-authentication.md)
- [Journey interface and credential controls](designs/interface.md)
- [Universal offline packaging](designs/universal-packaging.md)
- [Authentication test lab](designs/authentication-test-lab.md), [case ownership](designs/authentication-test-lab-cases.md), [contracts](designs/authentication-test-lab-contracts.md) and [terms](designs/authentication-test-lab-terms.md)
- [Run the Java authentication lab](../test/authentication-lab/README.md)

The universal design supersedes the authentication design's earlier platform-specific JAR distribution. Current interface amendments supersede its older UI descriptions. The former API environment and wheelhouse are retired; historical API sources remain unsupported reference only.

## Validation evidence

[Current integration validation](implementation/main-integration-validation.md) identifies the merged source, installed artifact and current test results.

[Test-suite integration](implementation/test-suite-integration.md) records the integrated lab, portable capture changes and scoped validation.

Each historical record applies only to its recorded artifact and date. It does not establish acceptance of a later integrated build.

- [driver resource probe](implementation/driver-resource-probe.md)
- [journey ux audit checklist](implementation/journey-ux-audit-checklist.md)
- [p2 browser tls validation](implementation/p2-browser-tls-validation.md)
- [p3 coordination tags validation](implementation/p3-coordination-tags-validation.md)
- [p4 native cutover validation](implementation/p4-native-cutover-validation.md)
- [session loss recovery validation](implementation/session-loss-recovery-validation.md)
- [universal packaging validation](implementation/universal-packaging-validation.md)
- [ux test matrix](implementation/ux-test-matrix.md)

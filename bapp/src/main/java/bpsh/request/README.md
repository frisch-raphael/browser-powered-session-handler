# Request authentication settings

## Overview

Defines ordered automatic-injection rules, URL matching and eligible request origins independently of Burp.

## Interface

- [RequestSettings](./RequestSettings.java): Defines immutable native project controls; journey definitions and secret values are stored separately.

## Invariants

RequestSettings.java:Tool preserves native wire names without Montoya types. URL conditions are sealed JDK-only values (all requests, Burp scope, literal prefix or regex source); listener restrictions are nullable ports from 1 through 65535. Concrete boundaries compile regex syntax. Controls implements only the scheduling policy needed by authentication; explicit tags remain independent of the automatic switch.

## Side Effects

None. RequestSettings.java contains immutable values and defensive collection copies.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../README.md).

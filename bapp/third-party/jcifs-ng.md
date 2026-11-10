# jcifs-ng

BPSH uses jcifs-ng 2.1.10 under LGPL-2.1-or-later for NTLM message construction.
The universal JAR includes the complete current upstream source tree (including
pom.xml and build files) in META-INF/bpsh/third-party/jcifs-ng-source.zip and its
LICENSE in META-INF/bpsh/third-party/jcifs-ng-LICENSE.txt. The adjacent provenance
JSON identifies the source and binary hashes. No changes to jcifs-ng are applied.

To replace the library, build a compatible jcifs-ng JAR from your modified source,
then rebuild BPSH from its maintained source using:

`.\gradlew.bat jar -PjcifsReplacement=C:/path/jcifs-ng.jar -PjcifsReplacementSources=C:/path/full-source.zip`

Both properties are required together. The replacement is used for Java compilation,
tests and packaging; original jcifs classes are excluded from those inputs. Include
all corresponding source and build files under a common root in the source ZIP,
including LICENSE and pom.xml. The existing dependency graph must remain compatible.
The build embeds your provided source and computes provenance for both inputs.
Run the native and interoperability tests for your modified library. Generated JARs
and source ZIPs belong to ignored build outputs and must not be committed.

The normal pinned build does not use replacement inputs. Source redistribution and
replacement mechanics require artifact qualification before publishing a release.

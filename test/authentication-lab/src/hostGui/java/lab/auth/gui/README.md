# Guest Burp GUI driver

Test-only public Swing/AWT automation, packaged with the existing host probe.
`HostGuiBootstrap` starts a worker through normal vendor `java -jar` startup;
it never transforms or redefines classes. `HostGuiDriver` uses real Robot input,
unique public control selection, bounded waits and the private journal in
`LabHostGuiProtocol`. Unimplemented or unavailable operations fail explicitly.

`HostGuiPreferences` isolates user/system preferences from global registry or
filesystem stores. Its explicit `export-approved` provisioning command copies
only existing Community/EULA choices, never license or account credentials.
`HostGuiDiagnostics` emits safe counts and fixed labels; it excludes editor,
password and arbitrary message contents. No product authentication code is used.
Failure receipts are published before optional private screenshots. Diagnostic
EDT queries have a 250 ms budget, and the owner allows a finite diagnostics-only
publication grace. Private images are excluded from published evidence. If no
owned window has focus, a bounded rendering of the owned Burp frame can diagnose
its state without capturing another application. Optional thread diagnostics
retain only bounded class/method identifiers, numeric thread IDs and states;
they omit thread names, source files, messages and arguments.
The bounded thread selection prioritizes the UI dispatcher, product work and
archive/I/O/loading stacks, then newer threads, so repeated reloads do not hide
the newest loader behind older workers.
The guest adds the original deadline and closed, safe command intent to public
receipts. File inputs retain only their hash; fixture secrets retain only their
reference enum. The evidence collector can audit actions without private files.

The extension-file witness reads the native Item/Detail table's full Filename
model value and compares normalized native paths. It does not use renderer text.
Fixture secret entry and HTTP-only Test login are implemented but not VM-qualified.
Repeater submission waits for the current request nonce and one enabled Send
control within the operation deadline before issuing exactly one click. Its exact
caption may belong to a Swing button or a custom control with public mouse
handling. Plain labels and ambiguous matches are rejected. Optional private
control diagnostics retain only fixed captions, public control kinds, enabled
state and the Loaded click's fixed boolean state. Rule editing, passive-probe
capture and UI assertions are implemented; complete VM scenario qualification
remains required.

Build with `:auth-lab:hostProbeJar`. Unit tests mirror this package under
`src/test/java/lab/auth/gui`. A helper build or unit pass is not VM qualification.

# Guest Burp GUI driver

Test-only public Swing/AWT automation, packaged with the existing host probe.
`HostGuiBootstrap` starts a worker through normal vendor `java -jar` startup;
it never transforms or redefines classes. `HostGuiDriver` uses real Robot input,
unique public control selection, bounded waits and the private journal in
`LabHostGuiProtocol`. Unimplemented or unavailable operations fail explicitly.

`RobotInput` verifies the current target point with the public mouse-position API
before clicking or scrolling. Java's focus flag alone does not establish native
foreground ownership. Each normal target receives one public window-exposure
request, even when Java reports focused. If its point remains obscured, allow one
activation click on a verified exposed title-bar point, followed by fresh target
geometry and ownership checks. The caption search excludes window controls and resize
edges; an obscured popup or unavailable safe point fails without a click retry.
Before any press, at most four pointer positions may be observed while the same
owned control finishes moving, including a newly mapped result dialog. Only a
changed position can trigger another pointer move; changed ownership, window,
popup context or the original deadline still fails. A gesture is never retried.
Deadline and cancellation checks precede each new gesture or key press, while
already pressed keys and mouse buttons are released during cleanup.

`HostGuiPreferences` isolates user/system preferences from global registry or
filesystem stores. Its explicit `export-approved` provisioning command copies
only existing Community/EULA choices, never license or account credentials.
`HostGuiDiagnostics` emits safe counts and fixed labels; it excludes editor,
password and arbitrary message contents. No product authentication code is used.
Failure receipts are published before optional private screenshots. Diagnostic
EDT queries have a 250 ms budget, and the owner allows a finite diagnostics-only
publication grace. Private images are excluded from published evidence and render
only an owned Burp window, never foreground desktop pixels. Before the suite frame
is identified, a unique showing modal dialog or otherwise a unique showing frame
can supply that image; ambiguity omits it. Fixed startup window/control categories
remain available when readiness fails, without arbitrary titles or input values.
Optional thread diagnostics include the idle UI dispatcher and
retain only bounded class/method identifiers, numeric thread IDs and states;
they omit thread names, source files, messages and arguments.
Optional private failure signals read public output/error text and event-table
messages without selecting hidden tabs. Only fixed message markers and bounded
exception class/method identifiers survive; arbitrary messages, credential values,
URLs and source paths are discarded. These signals diagnose failures and never
establish an authentication pass.
Native output is read through its plain document text, so HTML serialization and
display wrapping cannot hide a failure phrase. Matching normalizes display spaces.
Native extension-loading stacks retain bounded Burp, product and JDK class/method
identifiers, including allocation frames. Module versions, source files, line
numbers, paths and exception messages are discarded.
The helper also indexes bounded string literals from the captured production
source. A matching message emits only its repository source location, allowing
unclassified failures to be traced without retaining message text or values.
The generated dictionary belongs only to this test helper. Probe exports publish
these private signals early; they are excluded from normalized acceptance facts.
Fixed `Journey actions` accessible status descriptions and `Input error` plain
documents are also inspected when hidden, to diagnose actions that return before
logging an event. They remain private signals, never visible-UI pass evidence.
`HostGuiPointerTrace` observes delivery of the one Robot mouse gesture using a
temporary public AWT listener; it retains only target/owned-window booleans,
removes the listener in `finally`, and never retries or changes pass conditions.
For Swing buttons it also observes public model and action events, distinguishing
pointer delivery from action generation and a disabled or replaced button model.
All listeners are removed after the gesture; no action is invoked by the trace.
`HostLibraryOrigins` uses the premain agent's public JDK Instrumentation to inspect
already loaded fixed public third-party classes off the EDT. It records bounded
counts and source categories, not paths; staged JARs with an unrecognized location
remain OTHER rather than establishing a dependency conflict. It never loads/initializes classes,
transforms code, inspects product internals or establishes acceptance.
The bounded thread selection prioritizes the UI dispatcher, product work and
archive/I/O/loading stacks, then newer threads, so repeated reloads do not hide
the newest loader behind older workers.
`HostHeapDiagnostics` observes public management notifications from natural garbage
collections. Its private journal has at most 4096 numeric/fixed-enum records and
1 MiB; it records aggregate heap use before and after each collection, never
objects or notification text. Overflow and unavailable observations are explicit.
It neither forces collection nor walks the heap. A major-GC notification alone
does not prove a full compacting collection or retained object ownership. The
coordinator may retain the bounded journal for diagnosis on either outcome;
it is excluded from normalized acceptance evidence.
Natural collections leaving at least 1 GiB used may also trigger up to 32 private
loader-stack samples, bounded to 256 KiB. Each retains at most four threads with
four class/method identifiers, numeric IDs and fixed states; names, source files,
messages and values are discarded. These observations can show concurrent copy
workers, but cannot establish which objects they retain. The GC-log size/count
journal omits region addresses and has its own explicit completeness marker.
Management collector-local IDs and native GC-log IDs are separate namespaces;
compare the recorded uptime windows rather than equating their IDs.
The guest adds the original deadline and closed, safe command intent to public
receipts. File inputs retain only their hash; fixture secrets retain only their
reference enum. The evidence collector can audit actions without private files.
Field selection follows public `JLabel.labelFor` relationships and counts a
caption and its input as one target. Distinct matching fields remain ambiguous;
hidden inputs and targets outside the owned frame are rejected.
Combo selection clicks the exact item in the public popup list owned by that
combo, scrolling the owned popup with real wheel input when needed, then verifies
the committed value and closed popup. It does not require keyboard focus or walk
through intermediate values. Rule edits expose bounded
policy, journey, URL, port, expiration, tool and verification progress stages.

HTTP history rows are selected through the read-only Method column resolved by
its public header. The row-action dropdown column is never used for selection;
nonce checks still identify the exact prepared request before copying it.
`HostGuiHistory` reveals an offscreen row with bounded real wheel input, checking
its pinned nonce, row, Method column and viewport after each scroll and before
the click. Missing or reordered requests, horizontal clipping, unsafe cells and
expired input budgets fail without selecting another row.

Journey selection first opens Setup and verifies the visible, enabled name field
belongs to the selected journey. A remembered Test & use page cannot leave the
helper waiting on a hidden Setup field. Test-login diagnostics distinguish that
selection check from finding, clicking and waiting for the actual Test button.

The extension-file witness reads the native Item/Detail table's full Filename
model value and compares normalized native paths. It does not use renderer text.
Loaded transitions use the public `Extension loaded` checkbox in the selected
extension's Details pane, after the full filename witness identifies its JAR.
They wait for that control to be enabled and consistent with the summary table,
then recheck the requested state before one click. The summary cell need not be
editable. Loading can expose the product tab before the next action is ready.
Fixture secret entry has passed live setup on both VMs. HTTP-only Test login and
the complete authentication recipes still require successful VM qualification.
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

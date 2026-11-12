# Formatted Swing tooltips in Burp

Formatted help is supported. Use headings, paragraph breaks and bounded wrapping
when they improve readability. Keep this separate from rendering saved values as
literal text.

## Why valid HTML appeared literally

`setToolTipText` stores a string; it does not select a renderer. Swing's
`ToolTipManager` asks the hovered component's `createToolTip()` for a `JToolTip`.
That tooltip has its own look-and-feel UI and client properties, independent of
the control or its cell renderer.

The installed Burp tooltip factory was inspected and reproduced in a headless
probe: it sets **`html.disable = Boolean.TRUE` on the actual `JToolTip`** before
installing its FlatLaf UI. An ordinary tooltip consequently has no HTML view and
paints `<html>`, `<br>` and style attributes literally. Merely adding an HTML
wrapper, escaping it again, or setting a property on the combo box cannot fix it.
This is host behavior, not evidence that tooltip formatting is unsupported.

Swing's supported customization hook is
[`JComponent.createToolTip()`](https://docs.oracle.com/en/java/javase/21/docs/api/java.desktop/javax/swing/JComponent.html#createToolTip()).
The JDK implementation builds and paints its HTML view through
[`BasicToolTipUI`](https://github.com/openjdk/jdk21u/blob/master/src/java.desktop/share/classes/javax/swing/plaf/basic/BasicToolTipUI.java)
and checks the tooltip's `html.disable` property in
[`BasicHTML.updateRenderer`](https://github.com/openjdk/jdk21u/blob/master/src/java.desktop/share/classes/javax/swing/plaf/basic/BasicHTML.java).
The property is an implementation detail qualified against our JDK and host;
recheck this boundary when upgrading either.

## The implementation contract

[`UiTooltips`](../../bapp/src/main/java/bpsh/burp/ui/UiTooltips.java) owns formatting
and tooltip creation. Use its component factories, or override a component's
`createToolTip()` to return `UiTooltips.create(this)`.

```java
var policy = UiTooltips.comboBox(RequestSettings.RequestPolicy.values());
JourneyForms.row(panel, "Automatic handling policy", policy);
UiTooltips.set(policy, plainExplanation, 340, "Wait for login");
```

The helper retains the host's UI delegate, fonts, colors and borders. After
`super.updateUI()` installs the host UI, it enables HTML on **this tooltip only,
and only for content created by `UiTooltips.set`**, then rebuilds its HTML view.
Rebuilding matters when a theme update disabled HTML on an already populated
tooltip. The same provenance check runs after text, owner and theme changes.
Do not change `UIManager` or the application's global tooltip defaults.

`UiTooltips.set` accepts **plain text**, escapes it, adds the optional bold heading,
preserves paragraph/line breaks and applies a bounded width. Pass text, not a
prebuilt HTML document. A literal `<@journey/>`, selector or `<option>` example
must remain literal content. HTML starts at the first character of the resulting
string; use Swing's supported basic HTML and CSS subset rather than browser HTML,
Markdown, scripts, images or modern web layouts.

Control and form caption share the tooltip. `JourneyForms.row` creates a caption
with the same tooltip factory and uses `UiTooltips.copy` to transfer the content's
provenance; copying just the HTML string does not enable formatting. Later updates
through `UiTooltips.set` update both. Accessible descriptions retain the plain
explanation, without markup or CSS.

Keep `html.disable = true` on labels and cell renderers displaying saved values,
names, options or event messages. Enabling formatting on their separately created
tooltip does not enable HTML in those data displays. Escape any dynamic content
included in formatted help through the shared builder.

## Safety argument and its limits

Treat every body and heading as untrusted plain text, even though current callers
supply maintained help strings and enum labels. The trust boundary is text versus
markup, not whether an input appears to come from a trustworthy caller.

Swing HTML is not an inert string format. The JDK's
[`ImageView`](https://github.com/openjdk/jdk21u/blob/master/src/java.desktop/share/classes/javax/swing/text/html/ImageView.java)
can load an image URL; its HTML document also supports stylesheet handling.
[`ObjectView`](https://github.com/openjdk/jdk21u/blob/master/src/java.desktop/share/classes/javax/swing/text/html/ObjectView.java)
can instantiate a named Java component when enabled; `BasicHTML` gates that
behavior with `swing.html.object`. We do not rely on that setting, lack of
JavaScript, or Burp's proxy and TLS policies as the safety boundary.

The local argument has three parts:

1. **A closed markup grammar.** Only the private builder emits tags: `html`,
   `div`, optional `b`, and `br`. The sole style is a positive integer width from
   the caller. Both body and heading escape `&`, `<`, `>`, quotes and apostrophes
   before newline conversion. Escaping `&` first prevents existing entities from
   becoming a second markup channel. There is no raw-HTML overload, URL slot,
   stylesheet input, image, link, form or object slot. Current production callers
   use fixed widths of 320 or 340 and short maintained help, not response bodies,
   journey field values or secrets.
2. **Enforcement at the renderer.** `UiTooltips.set` stores a private immutable
   content marker under a private object key. The tooltip enables HTML only when
   its owner still holds that marker and both its current tooltip string and the
   text being rendered equal the generated content. Raw `setToolTipText` calls,
   altered strings and strings copied without `UiTooltips.copy` stay literal.
   Text and owner changes check this before Swing handles the new text; theme
   changes reapply it. This prevents an accidental future caller from bypassing
   escaping merely by passing an HTML-looking string.
3. **Executable evidence.** `UiTooltipSecurityTest` feeds hostile content into
   both body and heading, including image URLs, file/UNC URLs, stylesheet imports,
   object/classid, forms, scripts, entities and closing-tag attempts. It inspects
   Swing's parsed document and view tree, allowing only structural tags and
   attributes and rejecting image/object/form views. It also renders against the
   canonical lab's loopback origin: escaped content and raw bypass attempts must
   make zero requests, while an intentionally unsafe ordinary Swing tooltip must
   load a control image. The positive control prevents a disabled or broken
   network detector from reporting a false pass. Ownership, clearing, captions
   and theme updates are covered.

This is evidence for the escaping and rendering boundary on the tested JDK and
look and feel, not a formal proof of Swing or a process sandbox. It does not cover
malicious Java code in the same JVM, unknown JDK vulnerabilities, arbitrary host
UI delegates, or accepting unbounded response data as help. Keep help small and
rerun these checks when changing the grammar, sources of content, JDK or host UI.
Network observations cover loopback HTTP; file/resource safety follows from the
absence of resource-bearing parsed elements, not from a claim that every protocol
was monitored. VM/Burp GUI qualification remains separate.

## Native combo-popup lists

The look and feel creates the existing action-popup `JList`; it owns that list's
`createToolTip()` implementation. Setting HTML text there would repeat the same
bug. `StepActionHelp` therefore gives this host-owned surface wrapped plain lines
through `UiTooltips.lines`; the host's FlatLaf tooltip supports those line breaks.
The selected combo and our own fields retain formatted tooltips. If a native popup
later needs rich headings, supply an owned popup/list with the tooltip factory;
do not assume setting an owner property changes an existing list's tooltip.

## Required regression checks

`UiTooltipsTest` installs a test tooltip UI that reproduces the host's HTML-disable
behavior, then creates and paints actual tooltips. It verifies:

- The ordinary tooltip reproduces the failure, while our tooltip has an HTML view.
- Both Automatic handling policy options and their caption render formatted help.
- Theme updates preserve rendering and the selected UI delegate.
- Literal markup remains text, and accessible descriptions contain plain copy.
- Data renderers retain their own HTML-disable property.

`UiTooltipSecurityTest` adds the injection, provenance and resource-loading checks
described above. A rendering regression alone cannot establish these properties.

`StepActionHelpTest` covers native popup hover/keyboard help and clearing on close.
Checking only `getToolTipText()` is insufficient: it returns source text even when
the host will paint that markup literally. Headless renderer checks are distinct
from VM/Burp GUI qualification; follow `AGENTS.md` for any authorized GUI checks.

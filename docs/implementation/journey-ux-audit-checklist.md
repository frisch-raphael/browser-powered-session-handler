# Journey UX audit implementation

This tracks the full 2026-11-05 review, with the user's corrections applied.
It supersedes the earlier partial implementation of only the follow-up points.

| Audit area | Result |
| --- | --- |
| Setup naming and timing | Browser action timeout and Final capture wait replace ambiguous labels; capture-throughout behavior is explained on hover. |
| Generated reference | No request-tag preview. Copy token reference offers named credentials and explicit encodings without authenticating. |
| Rename consequence | Contextual explanation appears when a name edit changes an existing reference. |
| Wizard navigation | Tabs and Back/Next consistently permit incomplete settings; execution validates. Optional certificate page is skipped. Redundant numbered progress is removed. |
| Empty login sequence | Leads with adding the actions needed to sign in; zero steps is explained only for flows that return credentials without further interaction. |
| Action discovery | Picker groups interaction actions and waits; saved type discriminators remain unchanged. |
| Long sequences | Expandable action summaries show action/selector metadata without entered text or secrets. |
| Add and focus | Adding expands and reveals the new row and focuses its first input. |
| Reorder and removal | Native controls plus Alt+Up, Alt+Down and Alt+Delete; focus follows the affected row. Accessible action names include step numbers. |
| Undo | Alt+Backspace or Undo restores the changed row without overwriting later edits to other rows. History is bounded and session-only; discarded secret buffers are wiped. |
| Click feedback | Observed timeouts and SDK multiple-match reports preserve the exact action identity; unknown causes remain factual. No static selector checker was added. |
| Ordinary text | Fill field explains replacement and intentionally empty text; sensitive-value guidance points to Enter secret. |
| Secure text | Always-visible masked input. Missing versus explicitly empty remains internal. Retention wording is accurate and missing-value failures reveal the row. |
| Page-load waits | Readable Page load event, DOM ready and Network idle options with specific explanations. |
| URL waits | Explicit Exact URL / URL pattern modes, examples and stated glob syntax. Legacy journeys retain their prior matching behavior. |
| Duration waits | Seconds with exact fractional values; saved executable milliseconds retained. Legacy unfinished drafts retain explicit unit interpretation. |
| Element waits | Explicit Visible, Hidden, Present in page and Removed from page conditions; legacy default remains visible. |
| Capture naming | Capture credentials replaces Token. |
| Capture versus use | Separate Capture from browser and Use on matching requests groups. Disabled automatic injection still permits references. |
| Demonstration values | Newly created capture sources are blank rather than preconfigured for an example service. |
| Existing JSON/origin help | Existing field-specific tooltips retained. The duplicate recommendation was withdrawn; no permanent explanations were added. |
| Cookie filters | Optional domain/path filters are collapsed unless saved values require them. |
| Regex boundaries | Text between patterns names the behavior, with a synthetic boundary example in plain-text field help. |
| Multiple credentials | Required naming explanation, focus on newly required names, and expandable credential summaries. |
| Cache | Fixed dates/times remain; no countdowns or extra status widget. Settings explain maximum age and earlier credential expiry. |
| Certificate prerequisites | Dependent inputs still require middleware selection; automatic PIN use remains integral and fingerprints stay internal. |
| Certificate listing | Busy state prevents duplicate activation; Retry appears only after a positively observed PIN recovery condition. Empty listings have explicit inline feedback. |
| Human certificate identity | Readable name, organization/email when available, issuer and validity. Technical identifiers remain expandable. |
| Saved certificate inspection | Explicit read-only inspection is separate from replacement; selected public summaries are retained within the session. Inspection never changes the pinned fingerprint. |
| Certificate controls | Slot selection wording, Use login origin shortcut, independent remembered CA picker, and missing-certificate focus. Redirect origins are never guessed. |
| Test and use | Visible primary/secondary labels, explicit tests open the existing Event log, shared Cancel remains, and runtime outcomes preserve step identity. |
| Early credential capture | Existing early-completion policy retained and skipped remaining steps explained in the log. |
| Error/privacy constraints | No speculative VPN/device instructions, collision hints, Help tab, credential-bearing diagnostics or automatic screenshots. |

## Validation boundary

Focused editor, codec, clipboard, ownership and existing event-log checks plus
documentation validation run here. Native Swing previews cover the forms and
compact/expanded rows. Runtime/browser acceptance, especially failed-step log
attribution, remains owned by the separate test-suite worktree. See
`journey-step-log-test-suite-handoff.md`.

New wait-condition and URL-match runtime cases should be included by that owner;
codec round-trips and UI transitions are checked here without duplicating its lab.

# Burp journey interface

## Overview

Owns Swing editing/presentation, autosave interaction, explicit device actions and cache/event inspection.

## Interface

- [BrowserRuntimePreferences](./BrowserRuntimePreferences.java): Persists the browser executable override only in Burp's user preferences.
- [BurpBrowserSettingsPanel](./BurpBrowserSettingsPanel.java): Native browser location, selection and inline prerequisite guidance; performs no filesystem discovery.
- [AuthenticationTagMenu](./AuthenticationTagMenu.java): Inserts literal saved references at the request selection without acquiring or exposing credentials.
- [AutomaticRulesPanel](./AutomaticRulesPanel.java): Ordered session-handling rules with typed URL/regex choices, existing listener ports and inline expiration settings.
- [CertificatePresentation](./CertificatePresentation.java): Human-readable public identity labels; exact certificate selection remains fingerprint-based.
- [CredentialsPanel](./CredentialsPanel.java): Edits response tokens, captured cookies and their request destinations without runtime values.
- [DocumentChangeListener](./DocumentChangeListener.java): Adapts all Swing document changes to the same callback.
- [InlineValidation](./InlineValidation.java): Places safe validation guidance beside its input without changing the input's identity or keyboard contract.
- [JourneyCachePanel](./JourneyCachePanel.java): Explicit read-only inspection of one journey's usable cache and saved certificate fingerprint. The mTLS row shows only the selected certificate, without origins or HTTPS results, and never opens middleware. Captured values never enter logs, persistence or diagnostics.
- [JourneyDialogs](./JourneyDialogs.java): Isolates modal decisions from storage actions so cancellation and preview flows can be exercised locally.
- [JourneyEventLogPanel](./JourneyEventLogPanel.java): Burp-style event dock with per-journey time/type/message rows, filters and selectable safe details.
- [JourneyForms](./JourneyForms.java): Shared native form layout, independent of journey persistence and authentication state.
- [JourneyImportPanel](./JourneyImportPanel.java): Reviews a batch of files without exposing or retaining imported secret values in table cells.
- [JourneyValidationMessages](./JourneyValidationMessages.java): Sanitized field-path guidance shared by editor validation and execution failures.
- [PlaceholderPasswordField](./PlaceholderPasswordField.java): PlaceholderPasswordField
- [PlaceholderTextField](./PlaceholderTextField.java): PlaceholderTextField
- [RememberingFileChooser](./RememberingFileChooser.java): Remembers each file picker's navigation separately through Burp's user preferences.
- [SecurityDevicePicker](./SecurityDevicePicker.java): Inline device selection with automatic single-device choice and no PIN or certificate responsibilities.
- [SessionStatusBar](./SessionStatusBar.java): Journey dock/action toolbar; controller state is retained without displaying a status message.
- [StepsPanel](./StepsPanel.java): Edits stable-ID native steps on the EDT; password buffers travel separately from saved definitions.
- [StepActionHelp](./StepActionHelp.java): Shared per-action copy and native popup hover/accessibility help.
- [SwingJourneyDialogs](./SwingJourneyDialogs.java): Presents standard parented Swing dialogs; it performs no storage or authentication work.
- [UiController](./UiController.java): Owns the native Swing editor, serialized revision-checked storage and explicit background actions.
- [UiIcons](./UiIcons.java): Small native vector actions sharing one stroke, theme color, and accessible button contract.
- [UiTooltips](./UiTooltips.java): Escaped formatted help and component-owned tooltips that survive the host's HTML-disable setting and theme updates. Follow the [tooltip contract](../../../../../../../docs/designs/swing-tooltips.md).

## Invariants

UiController.java captures Swing fields on the EDT, rejects obsolete completions and delegates revisions/epochs/final merging to JourneyStorage. StepsPanel.java retains stable secure-step ownership.

Listener refresh exports run on the existing I/O worker and preserve saved missing/stopped ports and unfinished drafts. Failed validation or persistence leaves the last atomically applied source/matcher pair intact; listener-only refresh never autosaves or starts authentication.

## Side Effects

Creates UI/timers/background jobs, requests storage/authentication/native actions, opens file dialogs and performs explicit clipboard actions.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).

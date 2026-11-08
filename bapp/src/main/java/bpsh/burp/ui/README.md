# Burp journey interface

## Overview

Owns Swing editing/presentation, autosave interaction, explicit device actions and cache/event inspection.

## Interface

- [AuthenticationTagMenu](./AuthenticationTagMenu.java): Inserts literal saved references at the request selection without acquiring or exposing credentials.
- [AutomaticRulesPanel](./AutomaticRulesPanel.java): Ordered session-handling rules with inline scope and expiration settings.
- [CertificatePresentation](./CertificatePresentation.java): Human-readable public identity labels; exact certificate selection remains fingerprint-based.
- [CredentialsPanel](./CredentialsPanel.java): Edits response tokens, captured cookies and their request destinations without runtime values.
- [DocumentChangeListener](./DocumentChangeListener.java): Adapts all Swing document changes to the same callback.
- [InlineValidation](./InlineValidation.java): Places safe validation guidance beside its input without changing the input's identity or keyboard contract.
- [JourneyCachePanel](./JourneyCachePanel.java): Explicit read-only inspection of one journey's usable cache; values never enter logs, persistence or diagnostics.
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

## Invariants

UiController.java captures Swing fields on the EDT, rejects obsolete completions and delegates revisions/epochs/final merging to JourneyStorage. StepsPanel.java retains stable secure-step ownership.

## Side Effects

Creates UI/timers/background jobs, requests storage/authentication/native actions, opens file dialogs and performs explicit clipboard actions.

## Verification

From the repository root: `.\bapp\gradlew.bat -p bapp check verifyNativeDocumentation --offline`. Browser/native integration uses explicit tasks in [the build guide](../../../../../../README.md).

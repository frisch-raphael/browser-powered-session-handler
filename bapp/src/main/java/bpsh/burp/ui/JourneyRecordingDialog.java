package bpsh.burp.ui;

import bpsh.journey.AuthStep;
import bpsh.journey.JourneyDraft;
import bpsh.journey.JourneyRecording;
import bpsh.journey.SecretStore;
import bpsh.journey.editing.JourneyDraftCompiler;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GraphicsEnvironment;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/** Native Stop/Cancel and unsaved review; candidate edits never call the journey's autosave listener. */
final class JourneyRecordingDialog implements AutoCloseable {
    static final String UNKNOWN_FIELD = "Could not identify this field's type. Kept as Enter secret; change to Fill field if it is not sensitive.";
    static final String NO_PASSWORD = "No password field was identified. If you entered a password, change that step to Enter secret.";
    final JPanel component = new JPanel(new BorderLayout(8, 8));
    final StepsPanel editor = new StepsPanel();
    final JButton stop = new JButton("Stop recording"), apply = new JButton("Replace steps"), cancel = new JButton("Cancel"), again = new JButton("Record again");
    final JTextArea notes = new JTextArea(), feedback = new JTextArea();
    final JPanel relationships = new JPanel();
    final JLabel progress = new JLabel("Preparing browser...");
    private final Runnable cancelled;
    private final Consumer<StepsPanel.Snapshot> application;
    private final Map<UUID, JComboBox<Opening>> openingPickers = new HashMap<>();
    private final Map<UUID, UUID> chosen = new HashMap<>();
    private final Set<UUID> corrected = new HashSet<>();
    private JourneyRecording.Result result;
    private JDialog window;
    private boolean updating, applying, closed;
    private record Opening(UUID id, String label) { @Override public String toString() { return label; } }

    JourneyRecordingDialog(Runnable stopped, Runnable cancelled, Runnable rerecord, Consumer<StepsPanel.Snapshot> application) {
        this.cancelled = cancelled; this.application = application;
        component.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        var top = new JPanel(); top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS)); top.add(progress);
        configure(notes); configure(feedback); notes.setText("Wait for the browser to be ready, then perform the login. Your current steps are kept until you choose Replace steps.");
        var noteScroll = new JScrollPane(notes); noteScroll.setBorder(BorderFactory.createEmptyBorder()); noteScroll.setPreferredSize(new Dimension(600, 100)); top.add(noteScroll);
        relationships.setLayout(new BoxLayout(relationships, BoxLayout.Y_AXIS)); top.add(relationships); component.add(top, BorderLayout.NORTH);
        editor.setVisible(false); component.add(editor); component.add(footer(), BorderLayout.SOUTH);
        stop.setEnabled(false); stop.addActionListener(event -> { stop.setEnabled(false); progress.setText("Stopping recording..."); stopped.run(); });
        cancel.addActionListener(event -> cancelled.run()); again.addActionListener(event -> { cancelled.run(); rerecord.run(); });
        apply.setVisible(false); again.setVisible(false); apply.addActionListener(event -> submit());
        editor.setChangeListener(this::refreshReview);
    }

    private JPanel footer() {
        var footer = new JPanel(new BorderLayout(6, 6)); footer.add(feedback);
        var buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT)); buttons.add(again); buttons.add(stop); buttons.add(apply); buttons.add(cancel); footer.add(buttons, BorderLayout.SOUTH);
        return footer;
    }
    private static void configure(JTextArea area) {
        area.setEditable(false); area.setOpaque(false); area.setLineWrap(true); area.setWrapStyleWord(true); area.setFont(UIManager.getFont("Label.font"));
    }

    /** Opens only for a displayed native owner; component tests inspect the same content without a desktop window. */
    void show(Component parent) {
        if (closed || GraphicsEnvironment.isHeadless() || parent == null || !parent.isShowing()) return;
        Window owner = parent instanceof Window nativeWindow ? nativeWindow : SwingUtilities.getWindowAncestor(parent);
        window = new JDialog(owner, "Record login steps", Dialog.ModalityType.MODELESS); window.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        window.addWindowListener(new WindowAdapter() { @Override public void windowClosing(WindowEvent event) { cancelled.run(); } });
        window.setContentPane(component); var bounds = parent.getGraphicsConfiguration().getBounds();
        window.setSize(Math.min(1000, bounds.width - 48), Math.min(760, bounds.height - 48)); window.setLocationRelativeTo(parent); window.setVisible(true);
    }

    void state(JourneyRecording.State state) {
        if (closed) return;
        switch (state) {
            case PREPARING -> progress.setText("Preparing browser...");
            case WAITING_FOR_BROWSER -> progress.setText("Waiting for browser setup...");
            case VERIFYING_BROWSER -> progress.setText("Verifying bundled driver files...");
            case EXTRACTING_BROWSER -> progress.setText("Extracting bundled driver files...");
            case STARTING_DRIVER -> progress.setText("Starting the browser driver...");
            case STARTING_BROWSER -> progress.setText("Starting Burp Browser...");
            case OPENING_LOGIN -> progress.setText("Opening the login page...");
            default -> { }
        }
        if (state == JourneyRecording.State.RECORDING) { progress.setText("Recording — perform the login in the browser"); stop.setEnabled(true); }
        if (state == JourneyRecording.State.STOPPING) { progress.setText("Stopping recording..."); stop.setEnabled(false); }
    }

    /** Acquires candidate values into the review editor, then wipes the producer's duplicate secret buffers. */
    void review(JourneyRecording.Result captured) {
        if (closed) { captured.close(); return; }
        result = captured; progress.setText("Review recorded steps"); stop.setVisible(false); cancel.setText("Discard recording");
        apply.setVisible(true); again.setVisible(true); editor.setVisible(true);
        var popups = captured.popups().stream().map(JourneyRecording.Popup::declarationId).collect(java.util.stream.Collectors.toSet());
        editor.recordingReview(popups, (id, type) -> corrected.add(id));
        try (var values = captured.copySecrets()) { editor.setSteps(captured.candidates().stream().map(JourneyRecording.Candidate::step).toList(), values); }
        finally { captured.releaseCapturedSecrets(); }
        for (var popup : captured.popups()) {
            chosen.put(popup.declarationId(), popup.suggestedStep());
            var choice = new JComboBox<Opening>(); choice.setToolTipText("Choose the step that opened this popup.");
            choice.getAccessibleContext().setAccessibleDescription("Choose the step that opened this popup."); openingPickers.put(popup.declarationId(), choice);
            var line = new JPanel(new BorderLayout(8, 4)); var label = new JLabel("Opening step for " + popup.pageRef()); label.setLabelFor(choice);
            line.add(label, BorderLayout.WEST); line.add(choice); line.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0)); relationships.add(line);
            choice.addActionListener(event -> selectOpening(popup));
        }
        refreshReview(); component.revalidate(); component.repaint();
    }

    private void selectOpening(JourneyRecording.Popup popup) {
        if (updating || closed || applying) return;
        var selected = openingPickers.get(popup.declarationId()).getSelectedItem();
        UUID id = selected instanceof Opening opening ? opening.id() : null; chosen.put(popup.declarationId(), id);
        if (id != null) {
            try (var snapshot = editor.snapshot(); var values = new SecretStore.Values(null, snapshot.secrets)) {
                String name = snapshot.inputs.stream().filter(row -> row.id().equals(popup.declarationId()) && row.operation() instanceof JourneyDraft.Popup)
                        .map(row -> ((JourneyDraft.Popup) row.operation()).pageRef()).findFirst().orElse(popup.pageRef());
                var rows = JourneyDraftCompiler.placePopup(snapshot.inputs, popup.declarationId(), name, id);
                updating = true;
                try { editor.setDraft(rows, values); editor.restoreMissingValues(snapshot.missingValues); }
                finally { updating = false; }
            } catch (IllegalArgumentException error) { feedback.setText("Choose an available Click element or Press key step."); }
        }
        refreshReview();
    }

    private void refreshReview() {
        if (updating || closed || result == null) return;
        updating = true;
        try (var snapshot = editor.snapshot()) {
            var messages = new ArrayList<String>();
            if (!result.complete()) {
                messages.add("This recording is incomplete. You can replace the captured steps and finish editing in Login steps, then use Test login. Browser interaction numbers refer to what happened in the browser, not the steps below.");
                messages.addAll(result.problems());
            }
            else messages.add("Review the steps, then choose Replace steps. Use Test login afterward. You can undo the replacement in Login steps.");
            boolean password = result.candidates().stream().anyMatch(candidate -> candidate.step().type() == AuthStep.Type.SECURE_INPUT && !candidate.passwordUnclassified());
            if (!password) messages.add(NO_PASSWORD);
            for (var candidate : result.candidates()) if (candidate.passwordUnclassified() && !corrected.contains(candidate.step().id())) {
                for (int i = 0; i < snapshot.inputs.size(); i++) if (snapshot.inputs.get(i).id().equals(candidate.step().id()) && snapshot.inputs.get(i).type() == AuthStep.Type.SECURE_INPUT)
                    messages.add("Step " + (i + 1) + ": " + UNKNOWN_FIELD);
            }
            boolean relationshipsReady = true; Set<UUID> assigned = new HashSet<>();
            for (var popup : result.popups()) {
                var choice = openingPickers.get(popup.declarationId()); if (choice == null) continue;
                var options = new ArrayList<Opening>(); options.add(new Opening(null, "Choose opening step"));
                for (int i = 0; i < snapshot.inputs.size(); i++) {
                    var row = snapshot.inputs.get(i);
                    if (popup.openingSteps().contains(row.id()) && Set.of(AuthStep.Type.CLICK, AuthStep.Type.PRESS_KEY).contains(row.type()))
                        options.add(new Opening(row.id(), "Step " + (i + 1) + " — " + row.type().label()));
                }
                UUID selected = chosen.get(popup.declarationId()); boolean valid = selected != null && options.stream().anyMatch(option -> selected.equals(option.id()));
                if (selected != null && !valid) options.add(new Opening(selected, "Unavailable opening step"));
                choice.setModel(new DefaultComboBoxModel<>(options.toArray(Opening[]::new)));
                options.stream().filter(option -> java.util.Objects.equals(option.id(), selected)).findFirst().ifPresent(choice::setSelectedItem);
                if (!valid || !assigned.add(selected)) relationshipsReady = false;
                choice.setEnabled(!applying); choice.setToolTipText(options.size() == 1 ? "No recorded opening step is available. Add one in Login steps after replacing, or record again." : "Choose the step that opened this popup.");
            }
            if (!result.popups().isEmpty() && !relationshipsReady) messages.add("Some popup opening steps are missing. Choose them here or finish editing in Login steps after replacing.");
            if (!snapshot.missingValues.isEmpty()) messages.add("A field has no recorded value. Enter it here or in Login steps after replacing.");
            if (snapshot.inputs.isEmpty()) messages.add("No steps were recorded. Record the login again.");
            notes.setText(String.join("\n\n", messages)); notes.setCaretPosition(0);
            apply.setEnabled(!applying && !snapshot.inputs.isEmpty()); again.setEnabled(!applying);
        } finally { updating = false; }
    }

    private void submit() {
        if (closed || applying || !apply.isEnabled()) return;
        var snapshot = editor.snapshot(); applying = true; feedback.setText("Replacing steps..."); refreshReview();
        try { application.accept(snapshot); }
        catch (RuntimeException error) { snapshot.close(); validation("steps: the recorded steps could not be applied. Try again."); }
    }
    void validation(String message) {
        if (closed) return; applying = false;
        String text = JourneyValidationMessages.validationMessage(message); feedback.setText(text);
        editor.showInvalid(message, text, true); refreshReview();
    }
    void refreshPresentation() { editor.refreshPresentation(); }
    @Override public void close() {
        if (closed) return; closed = true; editor.clear(); if (result != null) result.close(); if (window != null) window.dispose();
    }
}

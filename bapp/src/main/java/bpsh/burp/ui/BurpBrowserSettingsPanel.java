package bpsh.burp.ui;

import bpsh.authentication.BrowserInstallation;
import java.util.function.Consumer;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import javax.swing.*;

/** Native presentation of user-local browser selection; performs no filesystem work. */
final class BurpBrowserSettingsPanel extends JPanel {
    private final JTextField executable = UiTooltips.textField(24);
    private final JTextArea location = JourneyForms.note("Browser detection starts when the extension is ready.");
    private boolean populating;
    /** @param onOverride Edited raw path. @param browse Native chooser action. @param useAutomatic Reset action. */
    BurpBrowserSettingsPanel(Consumer<String> onOverride, Runnable browse, Runnable useAutomatic) {
        super(new BorderLayout()); setBorder(BorderFactory.createTitledBorder("Burp Browser"));
        var form = JourneyForms.form();
        executable.getAccessibleContext().setAccessibleName("Burp Browser executable");
        UiTooltips.set(executable, "Leave empty to detect Burp's installed browser automatically. Choose its executable for a custom installation. Login and recording each use a separate temporary session.", 340, "Burp Browser");
        JourneyForms.row(form, "Executable", executable);
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        var choose = new JButton("Browse"); choose.addActionListener(event -> browse.run()); actions.add(choose);
        var automatic = new JButton("Use automatic"); automatic.addActionListener(event -> useAutomatic.run()); actions.add(automatic);
        JourneyForms.row(form, "", actions);
        location.setRows(2); location.getAccessibleContext().setAccessibleName("Detected Burp Browser");
        JourneyForms.row(form, "", location);
        JourneyForms.row(form, "", JourneyForms.note("Uses Burp's installed browser in a fresh temporary session for each login and recording."));
        add(form);
        executable.getDocument().addDocumentListener(new DocumentChangeListener(() -> { if (!populating) onOverride.accept(executable.getText()); }));
    }
    /** @param value Current raw selection; population never publishes an edit. */
    void setOverride(String value) { populating = true; try { executable.setText(value); InlineValidation.clear(executable); } finally { populating = false; } }
    /** @param selection Worker-resolved installed executable. */
    void showSelection(BrowserInstallation.Selection selection) { location.setText((selection.explicit() ? "Selected: " : "Detected: ") + selection.executable()); location.setCaretPosition(0); InlineValidation.clear(executable); }
    /** @param guidance Safe actionable guidance. */
    void showFailure(String guidance) { location.setText("Check Burp Browser settings."); InlineValidation.show(executable, guidance); }
    /** Keeps selection stable while a worker resolves its location. */
    void detecting() { location.setText("Detecting Burp Browser..."); InlineValidation.clear(executable); }
    /** @return Executable control for explicit error navigation. */
    JComponent focusTarget() { return executable; }
}

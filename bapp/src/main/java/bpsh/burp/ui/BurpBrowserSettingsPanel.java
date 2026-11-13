package bpsh.burp.ui;

import bpsh.authentication.BrowserInstallation;
import java.util.function.Consumer;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import javax.swing.*;

/** Native presentation of user-local browser selection; performs no filesystem work. */
final class BurpBrowserSettingsPanel extends JPanel {
    private final JTextField executable = UiTooltips.textField(24);
    private final JTextArea location = JourneyForms.note("Automatic detection. Browser detection starts when the extension is ready.");
    private final JButton automatic = new JButton("Restore automatic detection");
    private boolean automaticMode = true;
    private boolean populating;
    /** @param onOverride Edited raw path. @param browse Native chooser action. @param useAutomatic Reset action. */
    BurpBrowserSettingsPanel(Consumer<String> onOverride, Runnable browse, Runnable useAutomatic) {
        super(new BorderLayout()); setBorder(BorderFactory.createTitledBorder("Burp Browser"));
        var form = JourneyForms.form();
        executable.getAccessibleContext().setAccessibleName("Burp Browser executable");
        UiTooltips.set(executable, "Shows the automatically detected Burp Browser executable. Edit the path or browse to choose a custom executable. Restore automatic detection to follow Burp's installed browser again. Login and recording each use a separate temporary session.", 340, "Burp Browser");
        JourneyForms.row(form, "Executable", executable);
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        var choose = new JButton("Browse"); choose.addActionListener(event -> browse.run()); actions.add(choose);
        automatic.setEnabled(false); automatic.addActionListener(event -> useAutomatic.run()); actions.add(automatic);
        JourneyForms.row(form, "", actions);
        location.setRows(2); location.getAccessibleContext().setAccessibleName("Detected Burp Browser");
        JourneyForms.row(form, "", location);
        JourneyForms.row(form, "", JourneyForms.note("Each login and recording uses a fresh temporary browser session."));
        add(form);
        executable.getDocument().addDocumentListener(new DocumentChangeListener(() -> {
            if (!populating) { setAutomaticMode(executable.getText().isEmpty()); onOverride.accept(executable.getText()); }
        }));
    }
    /** @param value Current raw selection; population never publishes an edit. */
    void setOverride(String value) { setAutomaticMode(value.isEmpty()); displayPath(value); }
    /** Updates the displayed path without changing the persisted selection. @param value Literal executable path. */
    private void displayPath(String value) { populating = true; try { executable.setText(value); executable.setCaretPosition(0); InlineValidation.clear(executable); } finally { populating = false; } }
    /** @param value Whether the path is resolved automatically rather than selected by the user. */
    private void setAutomaticMode(boolean value) { automaticMode = value; automatic.setEnabled(!value); }
    /** @param selection Worker-resolved installed executable. */
    void showSelection(BrowserInstallation.Selection selection) {
        setAutomaticMode(!selection.explicit());
        if (automaticMode) displayPath(selection.executable().toString());
        location.setText(automaticMode ? "Automatic detection. Edit the path or browse to choose a custom executable."
                : "Custom executable. Restore automatic detection to follow Burp's installed browser.");
        location.setCaretPosition(0); InlineValidation.clear(executable);
    }
    /** @param guidance Safe actionable guidance. */
    void showFailure(String guidance) { location.setText(automaticMode ? "Automatic detection needs attention." : "Custom executable needs attention."); InlineValidation.show(executable, guidance); }
    /** Keeps selection stable while a worker resolves its location. */
    void detecting() { location.setText(automaticMode ? "Automatic detection: locating Burp Browser..." : "Checking custom executable..."); InlineValidation.clear(executable); }
    /** @return Executable control for explicit error navigation. */
    JComponent focusTarget() { return executable; }
}

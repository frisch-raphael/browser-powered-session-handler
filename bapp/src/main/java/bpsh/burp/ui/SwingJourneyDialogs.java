package bpsh.burp.ui;

import java.awt.*;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import javax.swing.*;
import static bpsh.burp.ui.JourneyForms.note;

/** Presents standard parented Swing dialogs; it performs no storage or authentication work. */
final class SwingJourneyDialogs implements JourneyDialogs {
    private final RememberingFileChooser journeys, middleware, trustedCa;
    private JDialog loginDialog;
    SwingJourneyDialogs(burp.api.montoya.persistence.Preferences preferences) {
        journeys = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.JOURNEYS);
        middleware = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.MIDDLEWARE);
        trustedCa = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.TRUSTED_CA);
    }
    /** @return Selected path, preserving the native chooser's cancellation behavior. */
    @Override public Path file(Component parent, boolean save) {
        var chooser = journeys.create(false); int result = save ? chooser.showSaveDialog(parent) : chooser.showOpenDialog(parent);
        journeys.remember(chooser, result == JFileChooser.APPROVE_OPTION);
        return result == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile().toPath() : null;
    }
    @Override public List<Path> importFiles(Component parent) {
        var chooser = journeys.create(true); chooser.setDialogTitle("Import journeys");
        boolean approved = chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION; journeys.remember(chooser, approved);
        if (!approved) return List.of();
        var files = chooser.getSelectedFiles();
        if (files.length == 0 && chooser.getSelectedFile() != null) return List.of(chooser.getSelectedFile().toPath());
        return Arrays.stream(files).map(java.io.File::toPath).distinct().toList();
    }
    @Override public Path middleware(Component parent) {
        var chooser = middleware.create(false);
        boolean approved = chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION;
        middleware.remember(chooser, approved);
        return approved ? chooser.getSelectedFile().toPath() : null;
    }
    @Override public Path trustedCa(Component parent) { var chooser = trustedCa.create(false); chooser.setDialogTitle("Choose trusted CA PEM bundle"); boolean approved = chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION; trustedCa.remember(chooser, approved); return approved ? chooser.getSelectedFile().toPath() : null; }
    /** @return Whether the operator accepted this task-specific confirmation. */
    @Override public boolean confirm(Component parent, Object content, String title) { return JOptionPane.showConfirmDialog(parent, dialogContent(parent, content), title, JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION; }
    @Override public boolean confirmAction(Component parent, Object content, String title, String action) { return JOptionPane.showOptionDialog(parent, dialogContent(parent, content), title, JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{action, "Cancel"}, "Cancel") == 0; }
    /** Displays plain-text information over the same suite frame as other extension dialogs. */
    @Override public void inform(Component parent, String text) { JOptionPane.showMessageDialog(parent, text, "Browser Powered Session Handler", JOptionPane.INFORMATION_MESSAGE); }
    @Override public void inspect(Component parent, Component content) { JOptionPane.showMessageDialog(parent, dialogContent(parent, content), "Saved certificate details", JOptionPane.INFORMATION_MESSAGE); }

    /** Shows one owned, keyboard-dismissible completion dialog while its suite frame remains visible. */
    @Override public void loginResult(Component parent, String title, String text, boolean error) {
        if (parent == null || !parent.isShowing()) return;
        closeLoginResult();
        var pane = new JOptionPane(dialogContent(parent, loginResultContent(title, text)),
                error ? JOptionPane.ERROR_MESSAGE : JOptionPane.INFORMATION_MESSAGE, JOptionPane.DEFAULT_OPTION);
        var dialog = pane.createDialog(parent, title); dialog.setResizable(true); loginDialog = dialog;
        try { dialog.setVisible(true); }
        finally { if (loginDialog == dialog) loginDialog = null; dialog.dispose(); }
    }
    @Override public void closeLoginResult() { if (loginDialog != null) { var dialog = loginDialog; loginDialog = null; dialog.dispose(); } }

    /** Keeps long credential lists readable, selectable and scrollable in compact suite windows. */
    static JScrollPane loginResultContent(String title, String text) {
        var area = note(text); area.setFont(UIManager.getFont("Label.font"));
        area.setRows(Math.min(12, Math.max(4, (int) text.lines().count() + 1)));
        area.getAccessibleContext().setAccessibleName(title); area.setCaretPosition(0);
        var scroll = new JScrollPane(area, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(BorderFactory.createEmptyBorder()); scroll.setOpaque(false); scroll.getViewport().setOpaque(false);
        scroll.getVerticalScrollBar().setUnitIncrement(area.getFontMetrics(area.getFont()).getHeight());
        return scroll;
    }

    /**
     * Keeps wrapping confirmations and scrollable previews inside a compact Burp window.
     * @param parent Owning suite frame; null is supported for isolated component checks.
     * @param value Plain text or an owned preview component.
     * @return Original component with bounded preferred dimensions, or wrapping plain-text guidance.
     */
    static Object dialogContent(Component parent, Object value) {
        Object content = value instanceof String text ? note(text) : value;
        if (parent == null || !(content instanceof JComponent component)) return content;
        int width = Math.max(240, parent.getWidth() - 160), height = Math.max(160, parent.getHeight() - 180);
        var preferred = component.getPreferredSize();
        component.setPreferredSize(new Dimension(Math.min(width, preferred.width), Math.min(height, preferred.height)));
        return component;
    }
}

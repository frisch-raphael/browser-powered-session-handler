import javax.swing.*;
import java.awt.*;

/** Places safe validation guidance beside its input without changing the input's identity or keyboard contract. */
final class InlineValidation {
    /** Shared utility only. */
    private InlineValidation() {}
    /** @param input Existing field or combo. @return Field container with initially hidden, wrapping guidance. */
    static JPanel wrap(JComponent input) {
        return wrap(input, () -> clear(input));
    }
    /** @param input Existing field or combo. @param onEdit Refreshes validation after an edit. @return Field container with initially hidden, wrapping guidance. */
    static JPanel wrap(JComponent input, Runnable onEdit) {
        var panel = new JPanel(new BorderLayout(0, 3)); var error = new JTextArea(1, 0);
        error.setEditable(false); error.setLineWrap(true); error.setWrapStyleWord(true); error.setOpaque(false); error.setVisible(false);
        error.getAccessibleContext().setAccessibleName("Input error");
        input.putClientProperty("validationMessage", error); input.putClientProperty("validationContainer", panel);
        panel.add(input); panel.add(error, BorderLayout.SOUTH);
        if (input instanceof javax.swing.text.JTextComponent text) text.getDocument().addDocumentListener(new DocumentChangeListener(onEdit));
        else if (input instanceof JComboBox<?> combo) combo.addActionListener(e -> onEdit.run());
        return panel;
    }
    /** @param input Existing field. @param message Sanitized explanation; never raw parser/input contents. */
    static void show(JComponent input, String message) { if (input.getClientProperty("validationMessage") instanceof JTextArea error) { error.setText(message); error.setVisible(true); input.getAccessibleContext().setAccessibleDescription(message); input.revalidate(); } }
    /** @param input Corrected or repopulated field. */
    static void clear(JComponent input) { if (input.getClientProperty("validationMessage") instanceof JTextArea error) { error.setText(""); error.setVisible(false); input.getAccessibleContext().setAccessibleDescription(null); input.revalidate(); } }
    /** @param input Revealed input. Focus after Swing lays out newly expanded rows/tabs, only while it remains visible. */
    static void focus(JComponent input) {
        SwingUtilities.invokeLater(() -> { if (input.isShowing() && input.isEnabled()) { input.scrollRectToVisible(new Rectangle(0, 0, input.getWidth(), input.getHeight())); input.requestFocusInWindow(); } });
    }
    /** @param input Conditional field. @param visible Whether its field and guidance should occupy layout space. */
    static void visible(JComponent input, boolean visible) { input.setVisible(visible); if (input.getClientProperty("validationContainer") instanceof JPanel panel) panel.setVisible(visible); if (!visible) clear(input); }
}

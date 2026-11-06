import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

/** Inline device selection with automatic single-device choice and no PIN or certificate responsibilities. */
final class SecurityDevicePicker extends JPanel {
    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);
    private final JTextArea summary = new JTextArea();
    private final JComboBox<Pkcs11IdentityManager.TokenInfo> choices = new JComboBox<>();
    private final JButton refresh;
    private boolean updating;
    private Pkcs11IdentityManager.TokenInfo selected;

    /** @param onChoice Explicit dropdown choice. @param onRefresh Explicit PIN-free rediscovery. */
    SecurityDevicePicker(Consumer<Pkcs11IdentityManager.TokenInfo> onChoice, Runnable onRefresh) {
        super(new BorderLayout(8, 0));
        summary.setEditable(false); summary.setOpaque(false); summary.setLineWrap(true); summary.setWrapStyleWord(true); summary.setRows(1);
        choices.getAccessibleContext().setAccessibleName("Security device");
        choices.setRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                var label = (JLabel) super.getListCellRendererComponent(list, "", index, selected, focus);
                label.putClientProperty("html.disable", true);
                if (value instanceof Pkcs11IdentityManager.TokenInfo token) {
                    label.setText(name(token) + (token.serial().isBlank() ? "" : " · " + token.serial()));
                    label.setToolTipText(name(token) + " · " + token.manufacturer() + " · " + token.model());
                } else { label.setText("Choose device..."); label.setToolTipText(null); }
                return label;
            }
        });
        choices.addActionListener(event -> { if (!updating) { selected = (Pkcs11IdentityManager.TokenInfo) choices.getSelectedItem(); onChoice.accept(selected); } });
        content.add(summary, "summary"); content.add(choices, "choices");
        refresh = UiIcons.button(UiIcons.Action.RETRY, "Refresh devices", onRefresh);
        add(InlineValidation.wrap(content)); putClientProperty("validationMessage", content.getClientProperty("validationMessage"));
        add(refresh, BorderLayout.EAST); reset();
    }

    /** Clears the previous middleware's choices without emitting a user selection. */
    void reset() { selected = null; InlineValidation.clear(this); status("Finding devices...", false); }
    /** Displays progress without opening a chooser or exposing downstream authentication fields. */
    void loading() { selected = null; status("Finding devices...", true); }
    /** @param text PIN-free discovery outcome. @param busy Whether refresh is currently unavailable. */
    private void status(String text, boolean busy) { summary.setText(text); cards.show(content, "summary"); refresh.setEnabled(!busy); }
    /** @param message Safe discovery error or empty state. */
    void unavailable(String message) { selected = null; status(message, false); }
    /**
     * @param devices Current initialized devices.
     * @param preferredId Previously selected actual slot ID, or null.
     * @return Automatically selected sole device or retained selection; null when a choice is needed.
     */
    Pkcs11IdentityManager.TokenInfo devices(List<Pkcs11IdentityManager.TokenInfo> devices, Long preferredId) {
        updating = true;
        try {
            choices.removeAllItems(); devices.forEach(choices::addItem);
            selected = devices.size() == 1 ? devices.getFirst() : devices.stream().filter(t -> preferredId != null && t.slotId() == preferredId).findFirst().orElse(null);
            choices.setSelectedItem(selected); refresh.setEnabled(true);
            if (devices.isEmpty()) status("No devices found. Connect your device, then refresh.", false);
            else if (devices.size() == 1) status(name(selected) + (selected.model().isBlank() ? "" : "\n" + selected.model()), false);
            else cards.show(content, "choices");
            return selected;
        } finally { updating = false; }
    }
    /** @return Currently chosen actual device, or null while pending/unselected. */
    Pkcs11IdentityManager.TokenInfo selected() { return selected; }
    /** Reveals the actual device choice, or the PIN-free refresh action when no dropdown is displayed. */
    void focusChoice() { InlineValidation.focus(choices.isVisible() ? choices : refresh); }
    /** @param token Public device identity. @return Literal human-readable device name. */
    private static String name(Pkcs11IdentityManager.TokenInfo token) { return token.label().isBlank() ? "Unnamed security device" : token.label(); }
}

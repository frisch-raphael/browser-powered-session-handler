package bpsh.burp.ui;

import javax.swing.*;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.table.TableModel;
import java.util.Objects;

/** Component-owned formatted help; preserves the host theme without changing global Swing defaults. */
final class UiTooltips {
    private static final Object CONTENT = new Object();
    /** Only this class constructs formatted content; a tooltip string alone never grants HTML rendering. */
    private record Content(String html) {}
    private UiTooltips() {}

    /** Retains the host UI while allowing only builder-produced content to opt into HTML. */
    static JToolTip create(JComponent owner) {
        var tip = new JToolTip() {
            @Override public void updateUI() {
                putClientProperty("html.disable", Boolean.TRUE);
                super.updateUI();
                refresh();
            }
            @Override public void setTipText(String text) {
                putClientProperty("html.disable", !trusted(getComponent(), text));
                super.setTipText(text);
                refresh();
            }
            @Override public void setComponent(JComponent component) {
                putClientProperty("html.disable", Boolean.TRUE);
                super.setComponent(component);
                refresh();
            }
            /** Recheck provenance after text, owner and theme changes, including unchanged tip strings. */
            private void refresh() {
                putClientProperty("html.disable", !trusted(getComponent(), getTipText()));
                BasicHTML.updateRenderer(this, getTipText());
            }
        };
        tip.setComponent(owner);
        tip.getAccessibleContext().setAccessibleDescription(owner.getAccessibleContext().getAccessibleDescription());
        return tip;
    }

    static <T> JComboBox<T> comboBox(T[] values) {
        return new JComboBox<>(values) { @Override public JToolTip createToolTip() { return create(this); } };
    }
    static <T> JComboBox<T> comboBox() {
        return new JComboBox<>() { @Override public JToolTip createToolTip() { return create(this); } };
    }
    static JLabel label(String text) {
        return new JLabel(text) { @Override public JToolTip createToolTip() { return create(this); } };
    }
    static JCheckBox checkBox(String text) {
        return new JCheckBox(text) { @Override public JToolTip createToolTip() { return create(this); } };
    }
    static JTextField textField(int columns) {
        return new JTextField(columns) { @Override public JToolTip createToolTip() { return create(this); } };
    }
    static JTable table(TableModel model) {
        return new JTable(model) { @Override public JToolTip createToolTip() { return create(this); } };
    }

    /** Sets matching formatted help on a control and its caption, with plain accessible copy. */
    static void set(JComponent control, String text, int width) { set(control, text, width, null); }
    static void set(JComponent control, String text, int width, String heading) {
        Content content = text == null ? null : new Content(html(text, width, heading));
        control.putClientProperty(CONTENT, content);
        control.setToolTipText(content == null ? null : content.html());
        control.getAccessibleContext().setAccessibleDescription(text);
        if (control.getClientProperty("rowLabel") instanceof JLabel caption) {
            copy(control, caption);
        }
    }

    /** Carries builder provenance to a form caption; raw strings remain untrusted. */
    static void copy(JComponent source, JComponent target) {
        target.putClientProperty(CONTENT, trusted(source, source.getToolTipText()) ? source.getClientProperty(CONTENT) : null);
        target.setToolTipText(source.getToolTipText());
        target.getAccessibleContext().setAccessibleDescription(source.getAccessibleContext().getAccessibleDescription());
    }

    /** Checks the owner and exact current content, rather than trusting an HTML prefix or public property key. */
    private static boolean trusted(JComponent owner, String text) {
        return owner != null && owner.getClientProperty(CONTENT) instanceof Content content
            && Objects.equals(content.html(), owner.getToolTipText()) && Objects.equals(content.html(), text);
    }

    /** Input is always plain text; markup comes exclusively from this builder. */
    private static String html(String text, int width, String heading) {
        if (width < 1) throw new IllegalArgumentException("Tooltip width must be positive.");
        String title = heading == null || heading.isBlank() ? "" : "<b>" + escape(heading) + "</b><br><br>";
        return "<html><div style='width: " + width + "px'>" + title + escape(text).replace("\r\n", "\n").replace("\n", "<br>") + "</div></html>";
    }
    private static String escape(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    /** Host-owned combo-popup lists receive wrapped plain lines because their tooltip factory is not ours. */
    static String lines(String text, int width) {
        if (text == null) return null;
        if (width < 1) throw new IllegalArgumentException("Tooltip width must be positive.");
        var result = new StringBuilder(); int column = 0;
        for (String word : text.split("\\s+")) {
            if (word.isEmpty()) continue;
            if (column > 0) { if (column + 1 + word.length() > width) { result.append('\n'); column = 0; } else { result.append(' '); column++; } }
            result.append(word); column += word.length();
        }
        return result.toString();
    }
}

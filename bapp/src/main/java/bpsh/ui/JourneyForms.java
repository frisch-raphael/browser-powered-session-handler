package bpsh.ui;

import java.awt.*;
import javax.swing.*;

/** Shared native form layout, independent of journey persistence and authentication state. */
final class JourneyForms {
    private JourneyForms() {}
    /**
     * Displays wrapping plain-text help without interpreting user content as HTML.
     *
     * @param text Wrapping plain-text guidance.
     * @return Noneditable label-like content with no HTML rendering.
     */
    static JTextArea note(String text) { var area = new JTextArea(text, Math.min(12, Math.max(2, text.length() / 90)), 45); area.setEditable(false); area.setLineWrap(true); area.setWrapStyleWord(true); area.setOpaque(false); return area; }
    /**
     * Returns vertically filled form panel inside a scroll pane.
     *
     * @return Vertically filled form panel inside a scroll pane.
     */
    static JPanel form() { return new JPanel(new GridBagLayout()); }
    /**
     * Adds an accessible label/control pair with stable form alignment and horizontal resizing.
     *
     * @param panel Form.
     * @param label Human-readable field label.
     * @param value Control or help component.
     */
    static void row(JPanel panel, String label, Component value) {
        Integer nextRow = (Integer) panel.getClientProperty("bpsh.nextRow"); int y = nextRow == null ? 0 : nextRow; panel.putClientProperty("bpsh.nextRow", y + 1);
        var c = new GridBagConstraints(); c.gridx = 0; c.gridy = y; c.anchor = GridBagConstraints.NORTHWEST; c.insets = new Insets(6, 8, 6, 8);
        if (!label.isBlank()) { var caption = new JLabel(label); caption.setLabelFor(value); if (value instanceof JComponent input) caption.setToolTipText(input.getToolTipText()); if (value instanceof JComponent component) component.putClientProperty("rowLabel", caption); panel.add(caption, c); c.gridx = 1; }
        else c.gridwidth = 2;
        c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL; panel.add(value instanceof JTextField input ? InlineValidation.wrap(input) : value, c);
    }
    /**
     * Anchors content at the top of a scrollable surface so shorter forms do not drift vertically.
     *
     * @param content Form/content to scroll.
     * @return Borderless scrolling surface that remains usable in smaller suite windows.
     */
    static JScrollPane scroll(Component content) { var pane = new JScrollPane(new FormViewport(content)); pane.setBorder(BorderFactory.createEmptyBorder()); pane.getVerticalScrollBar().setUnitIncrement(18); return pane; }
    /** Keeps top-aligned forms at the visible width so fields and help wrap after a Burp window resize. */
    static final class FormViewport extends JPanel implements Scrollable {
        /**
         * Anchors the form without stretching short forms vertically.
         * @param content Local form or help component whose preferred height determines vertical scrolling.
         */
        private FormViewport(Component content) { super(new BorderLayout()); add(content, BorderLayout.NORTH); }
        /**
         * Supplies the form's natural initial viewport size; later widths follow the actual viewport.
         * @return Preferred size of the top-aligned content.
         */
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        /**
         * Moves one small readable increment in either scroll direction.
         * @param visibleRect Current visible content bounds.
         * @param orientation Scroll axis supplied by Swing.
         * @param direction Scroll direction supplied by Swing.
         * @return Eighteen logical pixels.
         */
        @Override public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) { return 18; }
        /**
         * Pages through content while retaining one line of visual context.
         * @param visibleRect Current visible content bounds.
         * @param orientation Scroll axis supplied by Swing.
         * @param direction Scroll direction supplied by Swing.
         * @return Visible axis length less one small increment, with a positive minimum.
         */
        @Override public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) { return Math.max(18, (orientation == SwingConstants.VERTICAL ? visibleRect.height : visibleRect.width) - 18); }
        /**
         * Fits the form to Burp's current width, allowing text fields and wrapping help to shrink.
         * @return True; preferred widths must not create a horizontal scrollbar.
         */
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        /**
         * Retains the form's natural height so lower controls remain reachable by vertical scrolling.
         * @return False; tall forms scroll instead of clipping their final rows.
         */
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}

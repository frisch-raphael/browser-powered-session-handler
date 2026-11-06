import javax.swing.*;
import java.awt.*;
import java.awt.geom.Path2D;

/** Small native vector actions sharing one stroke, theme color, and accessible button contract. */
final class UiIcons {
    /** Supported action silhouettes; no font glyph or platform-specific image is required. */
    enum Action { ADD, MORE, UP, DOWN, BACK, NEXT, REMOVE, SAVE, PLAY, STOP, RETRY, UNDO, COPY, FOLDER, TRASH }
    /** Prevents construction of the shared action factory. */
    private UiIcons() {}
    /**
     * Creates a keyboard-focusable icon action with a persistent accessible name and tooltip.
     * @param action Vector silhouette.
     * @param label Accessible action and hover explanation.
     * @param run Local action callback.
     * @return Theme-aware native button.
     */
    static JButton button(Action action, String label, Runnable run) {
        var button = new JButton(new ActionIcon(action)); button.setToolTipText(label);
        button.getAccessibleContext().setAccessibleName(label); button.setName(label);
        button.setMargin(new Insets(5, 7, 5, 7)); button.addActionListener(e -> run.run()); return button;
    }
    /** Paints a scalable 18-pixel action in the component's current foreground. */
    private record ActionIcon(Action action) implements Icon {
        /** @return Logical icon width. */
        @Override public int getIconWidth() { return 18; }
        /** @return Logical icon height. */
        @Override public int getIconHeight() { return 18; }
        /**
         * Draws geometry directly so the host theme and display scale remain authoritative.
         * @param c Owning native component.
         * @param graphics Borrowed paint context.
         * @param x Logical left offset.
         * @param y Logical top offset.
         */
        @Override public void paintIcon(Component c, Graphics graphics, int x, int y) {
            var g = (Graphics2D) graphics.create();
            try {
                g.translate(x, y); g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g.setColor(c.isEnabled() ? c.getForeground() : UIManager.getColor("Label.disabledForeground"));
                g.setStroke(new BasicStroke(1.7f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                switch (action) {
                    case ADD -> { g.drawLine(9, 3, 9, 15); g.drawLine(3, 9, 15, 9); }
                    case MORE -> { for (int i : new int[]{3, 8, 13}) g.fillOval(i, 8, 3, 3); }
                    case UP, DOWN, BACK, NEXT -> {
                        g.rotate(switch (action) { case DOWN -> Math.PI; case BACK -> -Math.PI / 2; case NEXT -> Math.PI / 2; default -> 0; }, 9, 9);
                        g.drawLine(9, 3, 9, 15); g.drawLine(9, 3, 4, 8); g.drawLine(9, 3, 14, 8);
                    }
                    case REMOVE -> { g.drawLine(4, 4, 14, 14); g.drawLine(14, 4, 4, 14); }
                    case SAVE -> { g.drawRect(3, 3, 12, 12); g.drawRect(6, 3, 6, 4); g.drawRect(6, 10, 6, 5); }
                    case PLAY -> { var p = new Path2D.Double(); p.moveTo(5, 3); p.lineTo(15, 9); p.lineTo(5, 15); p.closePath(); g.draw(p); }
                    case STOP -> g.drawRect(4, 4, 10, 10);
                    case RETRY -> { g.drawArc(3, 3, 12, 12, 35, 285); g.drawLine(15, 3, 15, 8); g.drawLine(10, 8, 15, 8); }
                    case UNDO -> { var p = new Path2D.Double(); p.moveTo(3, 6); p.lineTo(10, 6); p.curveTo(17, 6, 17, 14, 10, 14); g.draw(p); g.drawLine(3, 6, 7, 2); g.drawLine(3, 6, 7, 10); }
                    case COPY -> { g.drawRect(6, 6, 9, 9); g.drawLine(3, 12, 3, 3); g.drawLine(3, 3, 12, 3); }
                    case FOLDER -> { var p = new Path2D.Double(); p.moveTo(2, 15); p.lineTo(2, 4); p.lineTo(7, 4); p.lineTo(9, 6); p.lineTo(16, 6); p.lineTo(16, 15); p.closePath(); g.draw(p); }
                    case TRASH -> { g.drawLine(3, 5, 15, 5); g.drawLine(7, 2, 11, 2); g.drawLine(5, 5, 6, 16); g.drawLine(6, 16, 12, 16); g.drawLine(12, 16, 13, 5); g.drawLine(8, 8, 8, 13); g.drawLine(10, 8, 10, 13); }
                }
            } finally { g.dispose(); }
        }
    }
}

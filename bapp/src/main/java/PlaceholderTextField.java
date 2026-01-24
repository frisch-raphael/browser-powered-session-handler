import javax.swing.*;
import java.awt.*;

public final class PlaceholderTextField extends JTextField
{
    private final String placeholder;

    public PlaceholderTextField(String placeholder, int columns)
    {
        super(columns);
        this.placeholder = placeholder;
    }

    @Override
    protected void paintComponent(Graphics g)
    {
        super.paintComponent(g);

        if (!getText().isEmpty() || isFocusOwner()) {
            return;
        }

        Graphics2D g2 = (Graphics2D) g.create();
        g2.setColor(new Color(120, 120, 120));
        Insets insets = getInsets();
        FontMetrics fm = g2.getFontMetrics();
        int x = insets.left + 2;
        int y = getHeight() / 2 + fm.getAscent() / 2 - 2;
        g2.drawString(placeholder, x, y);
        g2.dispose();
    }
}

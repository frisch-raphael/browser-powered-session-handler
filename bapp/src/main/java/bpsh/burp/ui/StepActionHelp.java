package bpsh.burp.ui;

import bpsh.journey.AuthStep;
import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.BorderFactory;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.plaf.basic.BasicComboPopup;

/** Action copy and native popup hover help shared by all step pickers. */
final class StepActionHelp {
    private StepActionHelp() {}

    /** @return Static help without selectors, entered values or browser details. */
    static String text(AuthStep.Type type) {
        return switch (type) {
            case CLICK -> "Click a button, link or other element.";
            case INPUT -> "Replace the field's contents with saved text. Leave empty to clear it.";
            case SECURE_INPUT -> "Fill a field with a secret. Saved between sessions only if Remember secrets is on.";
            case WAIT_LOAD_STATE -> "Wait for the selected load condition in the current page or frame.";
            case WAIT_URL -> "Wait until the current page or frame's URL matches your exact URL or pattern.";
            case WAIT_TIME -> "Pause for the full duration, even if the page is ready sooner.";
            case WAIT_SELECTOR -> "Wait for an element to be visible, hidden, present in the page or removed from it.";
            case SET_CHECKED -> "Set a checkbox to checked or unchecked, or select a radio button.";
            case SELECT_OPTIONS -> "Select options in a dropdown. An empty list clears a multi-select dropdown.";
            case PRESS_KEY -> "Press Enter, Ctrl+Enter, Tab or Shift+Tab in the chosen field or element.";
            case EXPECT_POPUP -> "Name the popup opened by the next click or key action so later steps can switch to it.";
            case SWITCH_PAGE -> "Run the next steps in the chosen tab or popup, starting outside any frame.";
            case ENTER_FRAME -> "Run the next steps inside the chosen embedded frame.";
            case PARENT_FRAME -> "Move one frame level outward. Run the next steps there.";
            case MAIN_FRAME -> "Run the next steps in the current tab or popup, outside all embedded frames.";
            case CLOSE_PAGE -> "Close the current tab or popup. Add Switch page before continuing.";
        };
    }

    /** Wraps long static guidance inside the native Swing tooltip, preserving plain accessible copy. */
    static String tooltip(String text) {
        if (text == null || text.length() <= 85) return text;
        return "<html><div style='width: 320px'>" + text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") + "</div></html>";
    }

    /** Installs once per combo and restores its native renderer after a host theme update. */
    static void install(JComboBox<AuthStep.Type> combo) {
        combo.setRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                var option = super.getListCellRendererComponent(list, value instanceof AuthStep.Type type ? type.label() : "", index, selected, focus);
                String heading = index < 0 || !(value instanceof AuthStep.Type type) ? null : heading(type);
                if (heading == null) return option;
                var panel = new JPanel(new BorderLayout()); var label = new JLabel(heading);
                label.setBorder(BorderFactory.createEmptyBorder(5, 5, 3, 5)); label.setFont(label.getFont().deriveFont(Font.BOLD));
                panel.setBackground(list.getBackground()); panel.add(label, BorderLayout.NORTH); panel.add(option); return panel;
            }
        });
        if (!Boolean.TRUE.equals(combo.getClientProperty("actionHelpInstalled"))) {
            combo.putClientProperty("actionHelpInstalled", true);
            combo.addActionListener(event -> describe(combo, combo.getSelectedItem()));
            combo.addPopupMenuListener(new PopupMenuListener() {
                @Override public void popupMenuWillBecomeVisible(PopupMenuEvent event) { attach(combo); }
                @Override public void popupMenuWillBecomeInvisible(PopupMenuEvent event) { clear(combo); }
                @Override public void popupMenuCanceled(PopupMenuEvent event) { clear(combo); }
            });
        }
        describe(combo, combo.getSelectedItem()); attach(combo);
    }

    private static JList<?> list(JComboBox<?> combo) {
        var popup = combo.getAccessibleContext().getAccessibleChild(0);
        return popup instanceof BasicComboPopup nativePopup ? nativePopup.getList() : null;
    }

    private static void attach(JComboBox<AuthStep.Type> combo) {
        var list = list(combo);
        if (list == null || Boolean.TRUE.equals(list.getClientProperty("actionHelpInstalled"))) return;
        list.putClientProperty("actionHelpInstalled", true);
        var mouse = new MouseAdapter() {
            @Override public void mouseMoved(MouseEvent event) { hover(list, event.getPoint()); }
            @Override public void mouseExited(MouseEvent event) { list.setToolTipText(null); }
        };
        list.addMouseMotionListener(mouse); list.addMouseListener(mouse);
        list.addListSelectionListener(event -> {
            describe(combo, list.getSelectedValue());
            if (!event.getValueIsAdjusting()) list.setToolTipText(list.getSelectedValue() instanceof AuthStep.Type type ? tooltip(text(type)) : null);
        });
    }

    /** Resolves real cell bounds; hovering never chooses an action or edits the sequence. */
    static void hover(JList<?> list, Point point) {
        int index = list.locationToIndex(point);
        var bounds = index < 0 ? null : list.getCellBounds(index, index);
        var value = bounds != null && bounds.contains(point) ? list.getModel().getElementAt(index) : null;
        if (value instanceof AuthStep.Type type && heading(type) != null) {
            @SuppressWarnings({"rawtypes", "unchecked"})
            Component cell = ((javax.swing.ListCellRenderer) list.getCellRenderer()).getListCellRendererComponent(list, value, index, false, false);
            if (cell instanceof JPanel panel && panel.getLayout() instanceof BorderLayout layout) {
                Component caption = layout.getLayoutComponent(BorderLayout.NORTH);
                if (caption != null && point.y - bounds.y < caption.getPreferredSize().height) value = null;
            }
        }
        list.setToolTipText(value instanceof AuthStep.Type type ? tooltip(text(type)) : null);
    }

    private static String heading(AuthStep.Type type) {
        return switch (type) {
            case CLICK -> "Interactions"; case WAIT_LOAD_STATE -> "Waits"; case SET_CHECKED -> "Controls";
            case EXPECT_POPUP -> "Pages"; case ENTER_FRAME -> "Frames"; default -> null;
        };
    }

    private static void describe(JComboBox<?> combo, Object value) {
        String help = value instanceof AuthStep.Type type ? text(type) : null;
        combo.getAccessibleContext().setAccessibleDescription(help); combo.setToolTipText(tooltip(help));
    }

    private static void clear(JComboBox<AuthStep.Type> combo) {
        var list = list(combo); if (list != null) list.setToolTipText(null);
        describe(combo, combo.getSelectedItem());
    }
}

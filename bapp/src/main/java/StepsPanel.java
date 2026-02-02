import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public final class StepsPanel extends JPanel
{
    private final JPanel rowsPanel;
    private final List<StepRow> rows;


    public StepsPanel()
    {
        super(new BorderLayout(6, 6));
        setBorder(BorderFactory.createTitledBorder("Authentication steps"));

        rows = new ArrayList<>();
        rowsPanel = new JPanel();
        rowsPanel.setLayout(new BoxLayout(rowsPanel, BoxLayout.Y_AXIS));

        JScrollPane scroll = new JScrollPane(rowsPanel);
        scroll.setBorder(BorderFactory.createEmptyBorder());

        add(buildControls(), BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
    }

    public void setSteps(List<AuthStep> steps)
    {
        rows.clear();
        rowsPanel.removeAll();

        if (steps != null) {
            for (AuthStep step : steps) {
                addRow(step.type, step.selector, step.value);
            }
        }

        if (rows.isEmpty()) {
            addRow("click", "", "");
        }

        revalidate();
        repaint();
    }

    public List<AuthStep> getSteps()
    {
        List<AuthStep> result = new ArrayList<>();
        for (StepRow row : rows) {
            result.add(row.toAuthStep());
        }
        return result;
    }

    private JPanel buildControls()
    {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addClick = new JButton("Add Click");
        JButton addInput = new JButton("Add Input");
        JButton addWait = new JButton("Add Wait (load)");
        JButton addWaitUrl = new JButton("Add Wait URL");
        JButton addWaitTime = new JButton("Add Wait Time");
        JButton addWaitSelector = new JButton("Add Wait Selector");
        JButton addSecureInput = new JButton("Add Secure Input");
        addClick.addActionListener(e -> addRow("click", "", ""));
        addInput.addActionListener(e -> addRow("input", "", ""));
        addWait.addActionListener(e -> addRow("wait_load_state", "", "load"));
        addWaitUrl.addActionListener(e -> addRow("wait_url", "", ""));
        addWaitTime.addActionListener(e -> addRow("wait_time", "", "1000"));
        addWaitSelector.addActionListener(e -> addRow("wait_selector", "", ""));
        addSecureInput.addActionListener(e -> addRow("secure_input", "", ""));

        panel.add(addClick);
        panel.add(addInput);
        panel.add(addSecureInput);
        panel.add(addWait);
        panel.add(addWaitUrl);
        panel.add(addWaitTime);
        panel.add(addWaitSelector);
        return panel;
    }

    private void addRow(String type, String selector, String value)
    {
        StepRow row = new StepRow(type, selector, value);
        rows.add(row);
        rowsPanel.add(row);
        revalidate();
        repaint();
    }

    private void removeRow(StepRow row)
    {
        rows.remove(row);
        rowsPanel.remove(row);
        if (rows.isEmpty()) {
            addRow("click", "", "");
        }
        revalidate();
        repaint();
    }

    private void moveRow(StepRow row, int direction)
    {
        int index = rows.indexOf(row);
        if (index < 0) {
            return;
        }
        int target = index + direction;
        if (target < 0 || target >= rows.size()) {
            return;
        }
        rows.remove(index);
        rows.add(target, row);

        rowsPanel.removeAll();
        for (StepRow r : rows) {
            rowsPanel.add(r);
        }
        revalidate();
        repaint();
    }

    private final class StepRow extends JPanel
    {
        private final JComboBox<String> typeCombo;
        private final JTextField selectorField;
        private final JTextField valueField;
        private final PlaceholderPasswordField secureValueField;
        private final JComboBox<String> loadStateCombo;
        private final JPanel fieldsPanel;

        StepRow(String type, String selector, String value)
        {
            super(new FlowLayout(FlowLayout.LEFT, 6, 0));

            typeCombo = new JComboBox<>(new String[] {
                    "click",
                    "input",
                    "secure_input",
                    "wait_load_state",
                    "wait_url",
                    "wait_time",
                    "wait_selector"
            });
            selectorField = new PlaceholderTextField("CSS selector", 18);
            valueField = new PlaceholderTextField("Value", 18);
            secureValueField = new PlaceholderPasswordField("Value", 18);
            loadStateCombo = new JComboBox<>(new String[] {"load", "domcontentloaded", "networkidle"});

            fieldsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            fieldsPanel.add(selectorField);
            fieldsPanel.add(valueField);
            fieldsPanel.add(secureValueField);
            fieldsPanel.add(loadStateCombo);

            typeCombo.setSelectedItem(type);
            selectorField.setText(selector == null ? "" : selector);
            valueField.setText(value == null ? "" : value);
            secureValueField.setText(value == null ? "" : value);
            loadStateCombo.setSelectedItem(value == null || value.isBlank() ? "load" : value);

            typeCombo.addActionListener(e -> applyTypeRules());
            applyTypeRules();

            add(buildRowButtons());
            add(typeCombo);
            add(fieldsPanel);
        }

        private JPanel buildRowButtons()
        {
            JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
            JButton up = new JButton("Up");
            JButton down = new JButton("Down");
            JButton remove = new JButton("Remove");

            up.addActionListener(e -> moveRow(this, -1));
            down.addActionListener(e -> moveRow(this, 1));
            remove.addActionListener(e -> removeRow(this));

            panel.add(up);
            panel.add(down);
            panel.add(remove);
            return panel;
        }

        private void applyTypeRules()
        {
            String type = (String) typeCombo.getSelectedItem();
            if ("click".equals(type)) {
                selectorField.setVisible(true);
                valueField.setVisible(false);
                secureValueField.setVisible(false);
                loadStateCombo.setVisible(false);
                valueField.setText("");
                secureValueField.setText("");
            } else if ("wait_load_state".equals(type)) {
                selectorField.setVisible(false);
                valueField.setVisible(false);
                secureValueField.setVisible(false);
                loadStateCombo.setVisible(true);
                selectorField.setText("");
            } else if ("wait_url".equals(type) || "wait_time".equals(type)) {
                selectorField.setVisible(false);
                valueField.setVisible(true);
                secureValueField.setVisible(false);
                loadStateCombo.setVisible(false);
                selectorField.setText("");
            } else if ("wait_selector".equals(type)) {
                selectorField.setVisible(true);
                valueField.setVisible(false);
                secureValueField.setVisible(false);
                loadStateCombo.setVisible(false);
                valueField.setText("");
                secureValueField.setText("");
            } else if ("secure_input".equals(type)) {
                selectorField.setVisible(true);
                valueField.setVisible(false);
                secureValueField.setVisible(true);
                loadStateCombo.setVisible(false);
                valueField.setText("");
            } else {
                selectorField.setVisible(true);
                valueField.setVisible(true);
                secureValueField.setVisible(false);
                loadStateCombo.setVisible(false);
            }
            fieldsPanel.revalidate();
            fieldsPanel.repaint();
        }

        AuthStep toAuthStep()
        {
            String type = (String) typeCombo.getSelectedItem();
            String selector = selectorField.getText().trim();
            String value;
            if ("wait_load_state".equals(type)) {
                value = (String) loadStateCombo.getSelectedItem();
            } else if ("secure_input".equals(type)) {
                value = new String(secureValueField.getPassword()).trim();
            } else {
                value = valueField.getText().trim();
            }
            return new AuthStep(type, selector, value);
        }

    }
}

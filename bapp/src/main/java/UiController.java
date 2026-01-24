import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class UiController {
    private final MontoyaApi api;
    private final ConfigManager configManager;
    private final ApiClient apiClient;
    private final LocalTokenCache localTokenCache;
    private final ApiServiceManager apiServiceManager;
    private final AtomicReference<Config> configRef;
    private final AtomicBoolean enabled;

    private JTextField apiBaseUrlField;
    private JTextField pythonPathField;
    private JTextField authenticationUrlField;
    private JCheckBox headlessCheckbox;
    private JLabel authenticationUrlLabel;
    private JLabel headlessLabel;

    private StepsPanel stepsPanel;

    private JTextField authenticationServerSubstringField;
    private JTabbedPane parsingTabs;
    private JTextField jsonPathField;
    private JTextField cookieNameField;
    private JSpinner refreshFrequencySpinner;
    private JLabel authenticationServerSubstringLabel;
    private JLabel parsingModeLabel;
    private JLabel jsonPathLabel;
    private JLabel refreshFrequencyLabel;

    private JRadioButton sessionStatusRadio;
    private JRadioButton sessionRegexRadio;
    private JSpinner sessionStatusSpinner;
    private JTextField sessionRegexField;

    private final Map<ToolType, JCheckBox> toolCheckboxes = new LinkedHashMap<>();

    private JToggleButton enableToggle;
    private JLabel statusLabel;

    public UiController(
            MontoyaApi api,
            ConfigManager configManager,
            ApiClient apiClient,
            LocalTokenCache localTokenCache,
            ApiServiceManager apiServiceManager,
            AtomicReference<Config> configRef,
            AtomicBoolean enabled) {
        this.api = api;
        this.configManager = configManager;
        this.apiClient = apiClient;
        this.localTokenCache = localTokenCache;
        this.apiServiceManager = apiServiceManager;
        this.configRef = configRef;
        this.enabled = enabled;
    }

    public Component buildUi() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Authentication configuration", buildAuthTab());
        tabs.addTab("Token configuration", buildTokenTab());
        tabs.addTab("Session lost detection", buildSessionLostTab());
        tabs.addTab("Scope", buildScopeTab());
        tabs.addTab("API", buildApiTab());
        tabs.addTab("Documentation", buildDocumentationTab());

        panel.add(tabs, BorderLayout.CENTER);
        panel.add(buildBottomBar(), BorderLayout.SOUTH);

        return panel;
    }

    public void applyConfigToUi(Config cfg) {
        apiBaseUrlField.setText(cfg.apiBaseUrl);
        if (pythonPathField != null) {
            pythonPathField.setText(cfg.pythonExecutable);
        }
        authenticationUrlField.setText(cfg.authenticationUrl);
        headlessCheckbox.setSelected(cfg.headless);

        stepsPanel.setSteps(cfg.steps);

        authenticationServerSubstringField.setText(cfg.authenticationServerUrlSubstring);
        if ("cookie".equals(cfg.tokenParsingMode)) {
            parsingTabs.setSelectedIndex(1);
        } else {
            parsingTabs.setSelectedIndex(0);
        }
        jsonPathField.setText(cfg.tokenJsonPath);
        cookieNameField.setText(cfg.tokenCookieName);
        refreshFrequencySpinner.setValue(cfg.refreshFrequencySeconds);

        if ("regex".equals(cfg.sessionLostMode)) {
            sessionRegexRadio.setSelected(true);
        } else {
            sessionStatusRadio.setSelected(true);
        }
        sessionStatusSpinner.setValue(cfg.sessionLostStatusCode);
        sessionRegexField.setText(cfg.sessionLostRegex);
        updateSessionModeControls();

        Set<ToolType> toolSet = cfg.scopeToolSet;
        for (Map.Entry<ToolType, JCheckBox> entry : toolCheckboxes.entrySet()) {
            entry.getValue().setSelected(toolSet.contains(entry.getKey()));
        }
    }

    private JPanel buildAuthTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();

        authenticationUrlField = new JTextField(40);
        headlessCheckbox = new JCheckBox("Run browser headless");
        authenticationUrlLabel = new JLabel("Authentication URL");
        headlessLabel = new JLabel("Headless");

        authenticationUrlLabel.setToolTipText("URL where the login flow starts.");
        authenticationUrlField.setToolTipText("URL where the login flow starts.");
        headlessLabel.setToolTipText("Run the browser without a visible window.");
        headlessCheckbox.setToolTipText("Run the browser without a visible window.");

        addRow(form, gbc, 0, authenticationUrlLabel, authenticationUrlField);
        addRow(form, gbc, 1, headlessLabel, headlessCheckbox);

        stepsPanel = new StepsPanel();
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton testAuth = new JButton("Test authentication steps");
        testAuth.addActionListener(e -> testAuthSteps());
        actions.add(testAuth);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(wrapLeft(form));
        content.add(stepsPanel);
        content.add(actions);

        panel.add(content, BorderLayout.CENTER);

        return panel;
    }

    private JPanel buildTokenTab() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel content = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();

        authenticationServerSubstringField = new JTextField(40);
        jsonPathField = new JTextField(30);
        cookieNameField = new JTextField(20);
        refreshFrequencySpinner = new JSpinner(new SpinnerNumberModel(120, 5, 86400, 5));

        parsingTabs = new JTabbedPane();
        parsingTabs.addTab("JSON", buildJsonParsingPanel());
        parsingTabs.addTab("Cookie", buildCookieParsingPanel());

        authenticationServerSubstringLabel = new JLabel("Authentication server substring");
        parsingModeLabel = new JLabel("Parsing mode");
        refreshFrequencyLabel = new JLabel("Refresh frequency (seconds)");
        jsonPathLabel = new JLabel("JSON path");

        authenticationServerSubstringLabel.setToolTipText("Substring of the URL that returns the token response.");
        authenticationServerSubstringField.setToolTipText("Substring of the URL that returns the token response.");
        parsingModeLabel.setToolTipText("Choose JSON if the token is in a JSON body, or Cookie if set via Set-Cookie.");
        parsingTabs.setToolTipText("Choose JSON if the token is in a JSON body, or Cookie if set via Set-Cookie.");
        jsonPathLabel.setToolTipText("Dot path to the token in the JSON response body.");
        jsonPathField.setToolTipText("Dot path to the token in the JSON response body.");
        refreshFrequencyLabel.setToolTipText("Force a token refresh after this many seconds.");
        refreshFrequencySpinner.setToolTipText("Force a token refresh after this many seconds.");

        addRow(content, gbc, 0, authenticationServerSubstringLabel, authenticationServerSubstringField);
        addRow(content, gbc, 1, parsingModeLabel, parsingTabs);
        addRow(content, gbc, 2, refreshFrequencyLabel, refreshFrequencySpinner);

        addVerticalSpacer(content, gbc, 3);

        panel.add(wrapLeft(content), BorderLayout.NORTH);
        return panel;
    }

    private JPanel buildSessionLostTab() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel content = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();

        sessionStatusRadio = new JRadioButton("Session lost when response status code equals");
        sessionRegexRadio = new JRadioButton("Session lost when response body matches regex");
        sessionStatusSpinner = new JSpinner(new SpinnerNumberModel(401, 100, 599, 1));
        sessionRegexField = new JTextField(30);

        ButtonGroup sessionGroup = new ButtonGroup();
        sessionGroup.add(sessionStatusRadio);
        sessionGroup.add(sessionRegexRadio);

        addRow(content, gbc, 0, "Mode", sessionStatusRadio);
        addRow(content, gbc, 1, "Status code", sessionStatusSpinner);
        addRow(content, gbc, 2, "", sessionRegexRadio);
        addRow(content, gbc, 3, "Regex", sessionRegexField);

        sessionStatusRadio.addActionListener(e -> updateSessionModeControls());
        sessionRegexRadio.addActionListener(e -> updateSessionModeControls());

        addVerticalSpacer(content, gbc, 4);

        panel.add(wrapLeft(content), BorderLayout.NORTH);
        return panel;
    }

    private JPanel buildScopeTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel list = new JPanel(new GridLayout(0, 3, 8, 8));

        addScopeTool(list, ToolType.SCANNER);
        addScopeTool(list, ToolType.PROXY);
        addScopeTool(list, ToolType.REPEATER);
        addScopeTool(list, ToolType.EXTENSIONS);
        addScopeTool(list, ToolType.INTRUDER);

        panel.add(list, BorderLayout.NORTH);
        return panel;
    }

    private JPanel buildDocumentationTab() {
        JPanel panel = new JPanel(new BorderLayout());
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setText(
                "Workflow:\n" +
                        "1) Authentication configuration: enter the login URL and record the steps.\n" +
                        "2) Token configuration: choose where the token appears (JSON or cookie).\n" +
                        "3) Session lost detection: set how a logout is detected.\n" +
                        "4) Scope: select which Burp tools use this session handler.\n" +
                        "5) API: set the token service URL and try a test token.\n" +
                        "6) Click Update configuration to apply changes.\n\n" +
                        "Tip: Use Save/Load to reuse configurations across projects.");
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildApiTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 16));
        JPanel content = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();

        if (apiBaseUrlField == null) {
            apiBaseUrlField = new JTextField(40);
        }
        if (pythonPathField == null) {
            pythonPathField = new JTextField(40);
        }

        JLabel apiBaseLabel = new JLabel("Token service base URL");
        apiBaseLabel.setToolTipText(
                "Base URL of the token service, e.g. http://127.0.0.1:7575. This service is a python service installed independently. See README for details.");
        apiBaseUrlField.setToolTipText("Base URL of the token service, e.g. http://127.0.0.1:7575");

        addRow(content, gbc, 0, apiBaseLabel, apiBaseUrlField);
        JLabel pythonLabel = new JLabel("Python executable (optional)");
        pythonLabel.setToolTipText("Uses PATH python by default. Set this to override.");
        pythonPathField.setToolTipText("Uses PATH python by default. Set this to override.");
        addRow(content, gbc, 1, pythonLabel, pythonPathField);

        JPanel actionsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actionsBar.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));

        JButton test = new JButton("Fetch test token");
        JButton emptyCache = new JButton("Empty API cache");
        JButton health = new JButton("Health test");
        JButton verify = new JButton("Verify API install");
        JButton install = new JButton("Install API");
        JButton startStop = new JButton();
        updateStartStopButton(startStop);
        test.addActionListener(e -> testToken());
        emptyCache.addActionListener(e -> emptyApiCache());
        health.addActionListener(e -> testHealth());
        verify.addActionListener(e -> verifyApiInstall());
        install.addActionListener(e -> installApi());
        startStop.addActionListener(e -> toggleTokenService(startStop));
        actionsBar.add(test);
        actionsBar.add(emptyCache);
        actionsBar.add(health);
        actionsBar.add(verify);
        actionsBar.add(install);
        actionsBar.add(startStop);
        for (Component c : actionsBar.getComponents()) {
            if (c instanceof AbstractButton b) {
                b.setBorderPainted(true);
                b.setContentAreaFilled(true);
                b.setOpaque(true);
                b.setFocusPainted(true);
            }
        }
        JScrollPane scrollPane = new JScrollPane(
                actionsBar,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );


        scrollPane.setPreferredSize(new Dimension(0, actionsBar.getPreferredSize().height + 11));
        scrollPane.setMinimumSize(new Dimension(0, actionsBar.getPreferredSize().height + 11));
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setViewportBorder(null);
        addRow(content, gbc, 2, "Actions", scrollPane);

        JTextArea apiHelp = new JTextArea(
                "Token service endpoints:\n" +
                        "POST /config  - update token configuration\n" +
                        "POST /token   - fetch token (auth data in body)\n" +
                        "GET  /invalidate - clear token cache\n" +
                        "GET  /health  - health check\n\n" +
                        "POST /config body:\n" +
                        "{\n" +
                        "  \"token_url_substring\": \"/protocol/openid-connect/token\",\n" +
                        "  \"refresh_frequency_seconds\": 120,\n" +
                        "  \"refresh_skew_seconds\": 10,\n" +
                        "  \"nav_timeout_ms\": 30000,\n" +
                        "  \"wait_token_timeout_ms\": 3000,\n" +
                        "  \"parsing\": {\n" +
                        "    \"mode\": \"json_path\",   // or \"cookie\"\n" +
                        "    \"path\": \"access_token\", // for json_path\n" +
                        "    \"cookie_name\": \"\"       // for cookie\n" +
                        "  }\n" +
                        "}\n\n" +
                        "POST /token body:\n" +
                        "{\n" +
                        "  \"authentication_url\": \"https://example.com/login\",\n" +
                        "  \"headless\": true,\n" +
                        "  \"steps\": [\n" +
                        "    {\"type\": \"input\", \"selector\": \"input#user\", \"value\": \"alice\"},\n" +
                        "    {\"type\": \"input\", \"selector\": \"input#pass\", \"value\": \"secret\"},\n" +
                        "    {\"type\": \"click\", \"selector\": \"button#login\", \"value\": \"\"},\n" +
                        "    {\"type\": \"wait_load_state\", \"selector\": \"\", \"value\": \"networkidle\"}\n" +
                        "  ],\n" +
                        "  \"force\": false\n" +
                        "}"
        );
        apiHelp.setEditable(false);
        apiHelp.setLineWrap(true);
        apiHelp.setWrapStyleWord(true);
        apiHelp.setBackground(panel.getBackground());

        JCheckBox docToggle = new JCheckBox("API documentation details");
        JPanel docPanel = new JPanel(new BorderLayout());
        JScrollPane docScroll = new JScrollPane(apiHelp);
        docPanel.add(docScroll, BorderLayout.CENTER);
        docPanel.setVisible(false);
        docToggle.addActionListener(e -> {
            docPanel.setVisible(docToggle.isSelected());
            content.revalidate();
            content.repaint();
        });

        addRow(content, gbc, 3, "API docs", docToggle);
        addRow(content, gbc, 4, "", docPanel);
        addVerticalSpacer(content, gbc, 5);

        panel.add(content, BorderLayout.NORTH);
        return panel;
    }

    private JPanel buildBottomBar() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controls.setBorder(BorderFactory.createTitledBorder("Actions"));

        JButton update = new JButton("Update configuration");
        JButton load = new JButton("Load");
        JButton save = new JButton("Save");
        JButton emptyLocalCache = new JButton("Empty local token cache");
        enableToggle = new JToggleButton("Enabled", enabled.get());
        statusLabel = new JLabel("Ready");

        update.addActionListener(e -> updateConfiguration());
        load.addActionListener(e -> loadFromFile());
        save.addActionListener(e -> saveToFile());
        emptyLocalCache.addActionListener(e -> emptyLocalCache());

        enableToggle.addActionListener(e -> {
            enabled.set(enableToggle.isSelected());
            enableToggle.setText(enabled.get() ? "Enabled" : "Disabled");
            statusLabel.setText(enabled.get() ? "Enabled" : "Disabled");
        });

        controls.add(update);
        controls.add(load);
        controls.add(save);
        controls.add(emptyLocalCache);
        controls.add(enableToggle);

        JScrollPane controlsScroll = new JScrollPane(
                controls,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );
        controlsScroll.setBorder(BorderFactory.createEmptyBorder());
        controlsScroll.setViewportBorder(null);
        controlsScroll.setPreferredSize(new Dimension(0, controls.getPreferredSize().height + 12));
        controlsScroll.setMinimumSize(new Dimension(0, controls.getPreferredSize().height + 12));

        panel.add(controlsScroll, BorderLayout.NORTH);
        panel.add(statusLabel, BorderLayout.SOUTH);

        return panel;
    }

    private GridBagConstraints baseConstraints() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        return gbc;
    }

    private void addRow(JPanel panel, GridBagConstraints gbc, int row, String label, Component field) {
        addRow(panel, gbc, row, new JLabel(label), field);
    }

    private void addRow(JPanel panel, GridBagConstraints gbc, int row, JLabel label, Component field) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 1;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.BASELINE_LEADING;
        panel.add(label, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.BASELINE;
        panel.add(field, gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
    }

    private JPanel wrapLeft(Component component) {
        JPanel wrapper = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        wrapper.add(component);
        return wrapper;
    }

    private void addScopeTool(JPanel list, ToolType type) {
        JCheckBox box = new JCheckBox(type.toolName());
        toolCheckboxes.put(type, box);
        list.add(box);
    }

    private void addVerticalSpacer(JPanel panel, GridBagConstraints gbc, int row) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.VERTICAL;
        panel.add(Box.createVerticalGlue(), gbc);
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
    }

    private void updateConfiguration() {
        try {
            Config cfg = configFromUi();
            if (cfg.apiBaseUrl == null || cfg.apiBaseUrl.isBlank()) {
                throw new IllegalArgumentException("Token service base URL is required");
            }
            apiClient.sendConfig(cfg);
            configRef.set(cfg);
            configManager.saveToStorage(cfg);
            localTokenCache.invalidate();
            statusLabel.setText("Configuration updated");
        } catch (Exception ex) {
            String msg = errorMessage(ex);
            api.logging().logToError("Update failed: " + msg);
            statusLabel.setText("Update failed: " + msg);
        }
    }

    private void testToken() {
        try {
            String apiBase = apiBaseUrlField.getText().trim();
            if (apiBase.isEmpty()) {
                throw new IllegalArgumentException("Token service base URL is required");
            }
            String token = localTokenCache.get(true);
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(token), null);
            statusLabel.setText("Token fetched (len=" + token.length() + ")");
            JOptionPane.showMessageDialog(
                    null,
                    token + "\n\nCopied to clipboard.",
                    "Token",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            String msg = errorMessage(ex);
            api.logging().logToError("Test failed: " + msg);
            statusLabel.setText("Test failed: " + msg);
        }
    }

    private void testAuthSteps() {
        runAsync("auth-test", () -> {
            try {
                String apiBase = apiBaseUrlField.getText().trim();
                if (apiBase.isEmpty()) {
                    throw new IllegalArgumentException("Token service base URL is required");
                }
                apiClient.fetchToken(true);
                setStatus("Authentication steps OK");
            } catch (Exception ex) {
                String msg = errorMessage(ex);
                api.logging().logToError("Auth test failed: " + msg);
                setStatus("Auth test failed: " + msg);
            }
        });
    }

    private void emptyApiCache() {
        try {
            String apiBase = apiBaseUrlField.getText().trim();
            if (apiBase.isEmpty()) {
                throw new IllegalArgumentException("Token service base URL is required");
            }
            apiClient.invalidateCache();
            statusLabel.setText("API cache cleared");
        } catch (Exception ex) {
            String msg = errorMessage(ex);
            api.logging().logToError("Empty cache failed: " + msg);
            statusLabel.setText("Empty cache failed: " + msg);
        }
    }

    private void emptyLocalCache() {
        localTokenCache.invalidate();
        statusLabel.setText("Local token cache cleared");
    }

    private void setStatus(String message) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
    }

    private void testHealth() {
        try {
            String apiBase = apiBaseUrlField.getText().trim();
            if (apiBase.isEmpty()) {
                throw new IllegalArgumentException("Token service base URL is required");
            }
            apiClient.testHealth();
            statusLabel.setText("Health OK");
        } catch (Exception ex) {
            String msg = errorMessage(ex);
            api.logging().logToError("Health test failed: " + msg);
            statusLabel.setText("Health test failed: " + msg);
        }
    }

    private void verifyApiInstall() {
        runAsync("api-verify", () -> {
            try {
                ApiServiceManager.VerificationResult result =
                        apiServiceManager.verify(pythonPathField == null ? "" : pythonPathField.getText());
                if (result.ok) {
                    setStatus("API install OK");
                    api.logging().logToOutput(result.message);
                } else {
                    setStatus("API verification failed. See error tab of extension for more details.");
                    api.logging().logToError(result.message);
                    if (!result.commands.isEmpty()) {
                        api.logging().logToError("API verification failed:");
                        api.logging().logToError("Suggested commands:");
                        for (String cmd : result.commands) {
                            api.logging().logToError(cmd);
                        }
                    }
                }
            } catch (Exception ex) {
                String msg = errorMessage(ex);
                api.logging().logToError("Verify failed: " + msg);
                setStatus("Verify failed: " + msg);
            }
        });
    }

    private void installApi() {
        runAsync("api-install", () -> {
            try {
                apiServiceManager.install(pythonPathField == null ? "" : pythonPathField.getText());
                setStatus("API installed");
                api.logging().logToOutput("API installed");
            } catch (Exception ex) {
                String msg = errorMessage(ex);
                api.logging().logToError("Install failed: " + msg);
                setStatus("Install failed: " + msg);
            }
        });
    }

    private void startTokenService() {
        runAsync("api-start", () -> {
            try {
                apiServiceManager.start(pythonPathField == null ? "" : pythonPathField.getText());
                setStatus("Token service started");
            } catch (Exception ex) {
                String msg = errorMessage(ex);
                api.logging().logToError("Start failed: " + msg);
                setStatus("Start failed: " + msg);
            }
        });
    }

    private void toggleTokenService(JButton button) {
        runAsync("api-toggle", () -> {
            try {
                if (apiServiceManager.isRunning()) {
                    apiServiceManager.stop();
                    setStatus("Token service stopped");
                } else {
                    apiServiceManager.start(pythonPathField == null ? "" : pythonPathField.getText());
                    setStatus("Token service started");
                }
                SwingUtilities.invokeLater(() ->
                        updateStartStopButton(button));
            } catch (Exception ex) {
                String msg = errorMessage(ex);
                api.logging().logToError("Start/stop failed: " + msg);
                setStatus("Start/stop failed: " + msg);
            }
        });
    }

    private void updateStartStopButton(JButton button) {
        boolean running = apiServiceManager.isRunning();
        button.setText(running ? "Stop token service" : "Start token service");
        Color bg = running ? new Color(210, 60, 60) : new Color(60, 150, 80);
        button.setBackground(bg);
        button.setForeground(Color.WHITE);
        button.setOpaque(true);
        button.setBorderPainted(false);
    }

    private void loadFromFile() {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            Path path = chooser.getSelectedFile().toPath();
            String json = Files.readString(path, StandardCharsets.UTF_8);
            Config cfg = configManager.normalize(configManager.parseJson(json));
            configManager.validate(cfg);
            configRef.set(cfg);
            applyConfigToUi(cfg);
            configManager.saveToStorage(cfg);
            statusLabel.setText("Loaded configuration");
        } catch (Exception ex) {
            String msg = errorMessage(ex);
            api.logging().logToError("Load failed: " + msg);
            statusLabel.setText("Load failed: " + msg);
        }
    }

    private void saveToFile() {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showSaveDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            Config cfg = configFromUi(false);
            Path path = chooser.getSelectedFile().toPath();
            Files.writeString(path, configManager.toJson(cfg), StandardCharsets.UTF_8);
            statusLabel.setText("Saved configuration");
        } catch (Exception ex) {
            String msg = errorMessage(ex);
            api.logging().logToError("Save failed: " + msg);
            statusLabel.setText("Save failed: " + msg);
        }
    }

    private Config configFromUi() {
        return configFromUi(true);
    }

    private Config configFromUi(boolean validate) {
        Config cfg = Config.defaults();
        cfg.apiBaseUrl = apiBaseUrlField.getText().trim();
        cfg.pythonExecutable = pythonPathField == null ? "" : pythonPathField.getText().trim();
        cfg.authenticationUrl = authenticationUrlField.getText().trim();
        cfg.headless = headlessCheckbox.isSelected();

        cfg.steps = new ArrayList<>(stepsPanel.getSteps());

        cfg.authenticationServerUrlSubstring = authenticationServerSubstringField.getText().trim();
        cfg.tokenParsingMode = parsingTabs.getSelectedIndex() == 1 ? "cookie" : "json_path";
        cfg.tokenJsonPath = jsonPathField.getText().trim();
        cfg.tokenCookieName = cookieNameField.getText().trim();
        cfg.refreshFrequencySeconds = (Integer) refreshFrequencySpinner.getValue();

        cfg.sessionLostMode = sessionRegexRadio.isSelected() ? "regex" : "status_code";
        cfg.sessionLostStatusCode = (Integer) sessionStatusSpinner.getValue();
        cfg.sessionLostRegex = sessionRegexField.getText().trim();

        cfg.scopeTools = new ArrayList<>();
        for (Map.Entry<ToolType, JCheckBox> entry : toolCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                cfg.scopeTools.add(entry.getKey().name());
            }
        }

        cfg = configManager.normalize(cfg);
        if (validate) {
            configManager.validate(cfg);
        }
        return cfg;
    }

    private void updateSessionModeControls() {
        boolean regexMode = sessionRegexRadio.isSelected();
        sessionRegexField.setEnabled(regexMode);
        sessionStatusSpinner.setEnabled(!regexMode);
    }

    private JPanel buildJsonParsingPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();
        JLabel desc = new JLabel("Use when the token is inside a JSON response body.");
        addRow(panel, gbc, 0, "", desc);
        if (jsonPathLabel == null) {
            jsonPathLabel = new JLabel("JSON path");
        }
        jsonPathLabel.setToolTipText("Dot path to the token in the JSON response body.");
        jsonPathField.setToolTipText("Dot path to the token in the JSON response body.");
        addRow(panel, gbc, 1, jsonPathLabel, jsonPathField);
        JLabel hint = new JLabel("Example: access_token, data.token");
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(hint, gbc);
        return panel;
    }

    private JPanel buildCookieParsingPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();
        JLabel desc = new JLabel("Use when the token is delivered in a Set-Cookie header.");
        addRow(panel, gbc, 0, "", desc);
        addRow(panel, gbc, 1, "Cookie name", cookieNameField);
        return panel;
    }

    private String errorMessage(Exception ex) {
        String msg = ex.getMessage();
        if (msg == null || msg.isBlank()) {
            return ex.getClass().getSimpleName();
        }
        return msg;
    }

    private void runAsync(String name, Runnable task) {
        Thread t = new Thread(task, name);
        t.setDaemon(true);
        t.start();
    }

}

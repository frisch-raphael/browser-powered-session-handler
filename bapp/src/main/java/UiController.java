import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

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
    private JTextField apiInstallProxyField;
    private JTextField authenticationUrlField;
    private JCheckBox headlessCheckbox;
    private JTextField browserProxyField;
    private JLabel authenticationUrlLabel;
    private JLabel headlessLabel;
    private JLabel browserProxyLabel;
    private JCheckBox mtlsEnabledCheckbox;
    private JTextField mtlsHostnameField;
    private PlaceholderPasswordField mtlsPinField;
    private JTextField mtlsCertCnField;
    private JPanel mtlsPanel;

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
    private JCheckBox sessionAutoRecoveryCheckbox;
    private JComboBox<RequestModeOption> requestHandlingModeCombo;
    private JTextField singleUrlPrefixField;
    private JLabel singleUrlPrefixLabel;

    private final Map<ToolType, JCheckBox> toolCheckboxes = new LinkedHashMap<>();

    private JToggleButton enableToggle;
    private JLabel statusLabel;
    private JLabel apiWarningLabel;
    private JButton apiStartStopButton;
    private Timer autoUpdateTimer;
    private Timer apiWarningTimer;
    private final AtomicBoolean apiWarningCheckInProgress = new AtomicBoolean(false);
    private final AtomicBoolean initialApiStartupPending = new AtomicBoolean(true);
    private boolean suppressAutoUpdate;

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
        tabs.addTab("Browser orchestration", buildAuthTab());
        tabs.addTab("Token configuration", buildTokenTab());
        tabs.addTab("Session lost detection", buildSessionLostTab());
        tabs.addTab("Scope", buildScopeTab());
        tabs.addTab("API", buildApiTab());
        tabs.addTab("Documentation", buildDocumentationTab());

        panel.add(tabs, BorderLayout.CENTER);
        panel.add(buildBottomBar(), BorderLayout.SOUTH);
        initAutoUpdate();
        initApiWarningMonitor();

        return panel;
    }

    public void applyConfigToUi(Config cfg) {
        suppressAutoUpdate = true;
        apiBaseUrlField.setText(cfg.apiBaseUrl);
        if (pythonPathField != null) {
            pythonPathField.setText(cfg.pythonExecutable);
        }
        if (apiInstallProxyField != null) {
            apiInstallProxyField.setText(cfg.apiInstallProxy);
        }
        authenticationUrlField.setText(cfg.authenticationUrl);
        headlessCheckbox.setSelected(cfg.headless);
        if (browserProxyField != null) {
            browserProxyField.setText(cfg.browserProxy);
        }

        stepsPanel.setSteps(cfg.steps);
        if (mtlsEnabledCheckbox != null) {
            mtlsEnabledCheckbox.setSelected(cfg.mtlsEnabled);
            if (mtlsHostnameField != null) {
                mtlsHostnameField.setText(cfg.mtlsHostname);
            }
            if (mtlsPinField != null) {
                mtlsPinField.setText(cfg.mtlsPin);
            }
            if (mtlsCertCnField != null) {
                mtlsCertCnField.setText(cfg.mtlsCertCn);
            }
            updateMtlsPanelVisibility();
        }

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
        if (sessionAutoRecoveryCheckbox != null) {
            sessionAutoRecoveryCheckbox.setSelected(cfg.autoSessionRecovery == null || cfg.autoSessionRecovery);
        }
        updateSessionModeControls();

        Set<ToolType> toolSet = cfg.scopeToolSet;
        for (Map.Entry<ToolType, JCheckBox> entry : toolCheckboxes.entrySet()) {
            entry.getValue().setSelected(toolSet.contains(entry.getKey()));
        }
        selectRequestMode(cfg.requestHandlingMode);
        if (singleUrlPrefixField != null) {
            singleUrlPrefixField.setText(cfg.singleUrlPrefix);
        }
        updateRequestHandlingModeControls();
        suppressAutoUpdate = false;
    }

    public void setInitialApiStartupPending(boolean pending) {
        initialApiStartupPending.set(pending);
        refreshApiWarningAsync();
    }

    private JPanel buildAuthTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();

        authenticationUrlField = new JTextField(40);
        headlessCheckbox = new JCheckBox("Run browser headless");
        authenticationUrlLabel = new JLabel("Authentication URL");
        headlessLabel = new JLabel("Headless");
        browserProxyLabel = new JLabel("Browser proxy");

        authenticationUrlLabel.setToolTipText("URL where the login flow starts.");
        authenticationUrlField.setToolTipText("URL where the login flow starts.");
        headlessLabel.setToolTipText("Run the browser without a visible window.");
        headlessCheckbox.setToolTipText("Run the browser without a visible window.");
        browserProxyLabel.setToolTipText("Proxy URL for the orchestrated browser (http(s)://host:port).");

        addRow(form, gbc, 0, authenticationUrlLabel, authenticationUrlField);
        addRow(form, gbc, 1, headlessLabel, headlessCheckbox);
        browserProxyField = new PlaceholderTextField("http://127.0.0.1:8080", 32);
        browserProxyField.setToolTipText("Proxy URL for the orchestrated browser (http(s)://host:port).");
        addRow(form, gbc, 2, browserProxyLabel, browserProxyField);

        stepsPanel = new StepsPanel();
        stepsPanel.setChangeListener(this::scheduleAutoUpdate);
        mtlsEnabledCheckbox = new JCheckBox("Enable PKCS#11 mTLS authentication");
        mtlsEnabledCheckbox.setToolTipText("Enable client certificate authentication before the page fully loads.");

        mtlsHostnameField = new PlaceholderTextField("example.com", 28);
        mtlsPinField = new PlaceholderPasswordField("PIN (optional)", 14);
        mtlsCertCnField = new PlaceholderTextField("Certificate CN (optional)", 20);

        mtlsPanel = new JPanel(new GridBagLayout());
        mtlsPanel.setBorder(BorderFactory.createTitledBorder("PKCS#11 configuration"));
        GridBagConstraints mtlsGbc = baseConstraints();
        JLabel hostLabel = new JLabel("Hostname");
        JLabel pinLabel = new JLabel("PIN");
        JLabel cnLabel = new JLabel("Certificate CN");
        hostLabel.setToolTipText(
                "Hostname that requires client certificate auth. Leave empty to use the authentication URL host.");
        mtlsHostnameField.setToolTipText(
                "Hostname that requires client certificate auth. Leave empty to use the authentication URL host.");
        pinLabel.setToolTipText("Optional PIN. Leave empty to skip PIN entry.");
        mtlsPinField.setToolTipText("Optional PIN. Leave empty to skip PIN entry.");
        cnLabel.setToolTipText("Optional certificate CN. Leave empty to select the first certificate.");
        mtlsCertCnField.setToolTipText("Optional certificate CN. Leave empty to select the first certificate.");

        addRow(mtlsPanel, mtlsGbc, 0, hostLabel, mtlsHostnameField);
        addRow(mtlsPanel, mtlsGbc, 1, pinLabel, mtlsPinField);
        addRow(mtlsPanel, mtlsGbc, 2, cnLabel, mtlsCertCnField);
        mtlsPanel.setVisible(false);
        mtlsEnabledCheckbox.addActionListener(e -> updateMtlsPanelVisibility());

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton testAuth = new JButton("Test authentication steps");
        JButton clearSteps = new JButton("Clear");
        testAuth.addActionListener(e -> testAuthSteps());
        clearSteps.addActionListener(e -> stepsPanel.setSteps(new ArrayList<>()));
        actions.add(testAuth);
        actions.add(clearSteps);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(wrapLeft(form));
        content.add(stepsPanel);
        content.add(wrapLeft(mtlsEnabledCheckbox));
        content.add(mtlsPanel);
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
        sessionAutoRecoveryCheckbox = new JCheckBox("Enable automatic session recovery");
        sessionAutoRecoveryCheckbox.setToolTipText(
                "If disabled, rely on the refresh frequency to keep the token fresh.");

        ButtonGroup sessionGroup = new ButtonGroup();
        sessionGroup.add(sessionStatusRadio);
        sessionGroup.add(sessionRegexRadio);

        addRow(content, gbc, 0, "Mode", sessionStatusRadio);
        addRow(content, gbc, 1, "Status code", sessionStatusSpinner);
        addRow(content, gbc, 2, "", sessionRegexRadio);
        addRow(content, gbc, 3, "Regex", sessionRegexField);
        addRow(content, gbc, 4, "", sessionAutoRecoveryCheckbox);

        sessionStatusRadio.addActionListener(e -> updateSessionModeControls());
        sessionRegexRadio.addActionListener(e -> updateSessionModeControls());

        addVerticalSpacer(content, gbc, 5);

        panel.add(wrapLeft(content), BorderLayout.NORTH);
        return panel;
    }

    private JPanel buildScopeTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel content = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();

        requestHandlingModeCombo = new JComboBox<>(new RequestModeOption[] {
                new RequestModeOption("Burp scope", "burp_scope"),
                new RequestModeOption("All requests", "all_requests"),
                new RequestModeOption("Single URL prefix", "single_url")
        });
        requestHandlingModeCombo.setToolTipText("Choose how requests are selected for token injection.");
        addRow(content, gbc, 0, "Request selection mode", requestHandlingModeCombo);

        singleUrlPrefixField = new PlaceholderTextField("https://target.example.com/api", 36);
        singleUrlPrefixLabel = new JLabel("Single URL prefix");
        singleUrlPrefixLabel.setToolTipText("Only requests starting with this URL prefix will be handled.");
        singleUrlPrefixField.setToolTipText("Only requests starting with this URL prefix will be handled.");
        addRow(content, gbc, 1, singleUrlPrefixLabel, singleUrlPrefixField);

        JPanel list = new JPanel(new GridLayout(0, 3, 8, 8));

        addScopeTool(list, ToolType.SCANNER);
        addScopeTool(list, ToolType.PROXY);
        addScopeTool(list, ToolType.REPEATER);
        addScopeTool(list, ToolType.EXTENSIONS);
        addScopeTool(list, ToolType.INTRUDER);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 3;
        gbc.weightx = 1.0;
        content.add(list, gbc);

        requestHandlingModeCombo.addActionListener(e -> {
            updateRequestHandlingModeControls();
            scheduleAutoUpdate();
        });
        updateRequestHandlingModeControls();

        panel.add(content, BorderLayout.NORTH);
        return panel;
    }

    private JPanel buildDocumentationTab() {
        JPanel panel = new JPanel(new BorderLayout());
        String markdown = loadDocumentationMarkdown();

        JEditorPane area = new JEditorPane();
        area.setEditable(false);
        area.setContentType("text/html");
        Parser parser = Parser.builder().build();
        HtmlRenderer renderer = HtmlRenderer.builder().build();
        Node document = parser.parse(markdown);
        area.setText(renderer.render(document));
        area.setCaretPosition(0);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        return panel;
    }

    private String loadDocumentationMarkdown() {
        try {
            String extensionFile = api.extension().filename();
            if (extensionFile != null && !extensionFile.isBlank()) {
                Path extPath = Path.of(extensionFile).toAbsolutePath();
                Path rootReadme = extPath.getParent()
                        .resolve("..")
                        .resolve("..")
                        .resolve("..")
                        .resolve("README.md")
                        .normalize();
                if (Files.exists(rootReadme)) {
                    return Files.readString(rootReadme, StandardCharsets.UTF_8);
                }
            }
        } catch (Exception ex) {
            api.logging().logToError("Failed to read README.md for documentation: " + ex.getMessage());
        }

        return "# Documentation unavailable\n\nProject root `README.md` was not found.";
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
        if (apiInstallProxyField == null) {
            apiInstallProxyField = new JTextField(40);
        }

        JLabel apiBaseLabel = new JLabel("Token service base URL");
        apiBaseLabel.setToolTipText(
                "Base URL of the token service, e.g. http://127.0.0.1:7575. This service is a python service installed independently of the bapp, and is what will launch the embedded firefox. See README for details.");
        apiBaseUrlField.setToolTipText("Base URL of the token service, e.g. http://127.0.0.1:7575");

        addRow(content, gbc, 0, apiBaseLabel, apiBaseUrlField);
        JLabel pythonLabel = new JLabel("Python executable (optional)");
        pythonLabel.setToolTipText("Uses PATH python by default. Set this to override.");
        pythonPathField.setToolTipText("Uses PATH python by default. Set this to override.");
        addRow(content, gbc, 1, pythonLabel, pythonPathField);
        JLabel installProxyLabel = new JLabel("API install proxy (optional)");
        installProxyLabel.setToolTipText(
                "Proxy used for API dependency/browser install. If the proxy needs authentication, set Burp as the proxy and configure authentication there.");
        apiInstallProxyField.setToolTipText(
                "Proxy used for API dependency/browser install. If the proxy needs authentication, set Burp as the proxy and configure authentication there.");
        addRow(content, gbc, 2, installProxyLabel, apiInstallProxyField);

        JPanel actionsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actionsBar.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));

        JButton test = new JButton("Fetch test token");
        JButton emptyCache = new JButton("Empty API cache");
        JButton health = new JButton("Health test");
        health.setToolTipText("Verify that the API is up");
        JButton verify = new JButton("Verify API install");
        JButton install = new JButton("Install API");
        JButton startStop = new JButton();
        apiStartStopButton = startStop;
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
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        scrollPane.setPreferredSize(new Dimension(0, actionsBar.getPreferredSize().height + 11));
        scrollPane.setMinimumSize(new Dimension(0, actionsBar.getPreferredSize().height + 11));
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setViewportBorder(null);
        addRow(content, gbc, 3, "Actions", scrollPane);

        JTextArea apiHelp = new JTextArea(
                "Token service endpoints:\n" +
                        "POST /config  - update token configuration\n" +
                        "POST /token   - fetch token (auth data in body)\n" +
                        "GET  /cache  - list tokens in cache\n" +
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
                        "  \"proxy\": \"http://127.0.0.1:8080\",\n" +
                        "  \"steps\": [\n" +
                        "    {\"type\": \"wait_url\", \"selector\": \"\", \"value\": \"**/login\"},\n" +
                        "    {\"type\": \"wait_selector\", \"selector\": \"input#user\", \"value\": \"\"},\n" +
                        "    {\"type\": \"input\", \"selector\": \"input#user\", \"value\": \"alice\"},\n" +
                        "    {\"type\": \"secure_input\", \"selector\": \"input#pass\", \"value\": \"secret\"},\n" +
                        "    {\"type\": \"click\", \"selector\": \"button#login\", \"value\": \"\"},\n" +
                        "    {\"type\": \"wait_time\", \"selector\": \"\", \"value\": \"1500\"},\n" +
                        "    {\"type\": \"wait_load_state\", \"selector\": \"\", \"value\": \"networkidle\"}\n" +
                        "  ],\n" +
                        "  \"mtls_enabled\": true,\n" +
                        "  \"mtls_hostname\": \"example.com\",\n" +
                        "  \"mtls_pin\": \"1234\",\n" +
                        "  \"mtls_cert_cn\": \"My Cert\",\n" +
                        "  \"force\": false\n" +
                        "}");
        apiHelp.setEditable(false);
        apiHelp.setLineWrap(true);
        apiHelp.setWrapStyleWord(true);
        apiHelp.setBackground(panel.getBackground());

        JCheckBox docToggle = new JCheckBox("API documentation details");
        JPanel docPanel = new JPanel(new BorderLayout());
        JScrollPane docScroll = new JScrollPane(apiHelp);
        docScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        docScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        docPanel.add(docScroll, BorderLayout.CENTER);
        docPanel.setVisible(false);
        docToggle.addActionListener(e -> {
            docPanel.setVisible(docToggle.isSelected());
            content.revalidate();
            content.repaint();
        });

        addRow(content, gbc, 4, "API docs", docToggle);
        addRow(content, gbc, 5, "", docPanel);
        addVerticalSpacer(content, gbc, 6);

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
        JButton copyHackvertor = new JButton("Copy hackvertor tag");
        enableToggle = new JToggleButton("Enabled", enabled.get());
        enableToggle.setToolTipText(
                "When enabled, the extension will reauthenticate and fetch new tokens according to the configuration.");
        statusLabel = new JLabel("Ready");
        apiWarningLabel = new JLabel();
        apiWarningLabel.setForeground(new Color(190, 40, 40));
        apiWarningLabel.setVisible(false);

        update.addActionListener(e -> updateConfiguration());
        load.addActionListener(e -> loadFromFile());
        save.addActionListener(e -> saveToFile());
        emptyLocalCache.addActionListener(e -> emptyLocalCache());
        copyHackvertor.addActionListener(e -> copyHackvertorTag());
        copyHackvertor.setToolTipText(
                "Create a hackvertor custom tag based on the current configuration. See wiki for more informations");

        enableToggle.addActionListener(e -> {
            enabled.set(enableToggle.isSelected());
            enableToggle.setText(enabled.get() ? "Enabled" : "Disabled");
            statusLabel.setText(enabled.get() ? "Enabled" : "Disabled");
        });

        controls.add(update);
        controls.add(load);
        controls.add(save);
        controls.add(emptyLocalCache);
        controls.add(copyHackvertor);
        controls.add(enableToggle);

        JScrollPane controlsScroll = new JScrollPane(
                controls,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        controlsScroll.setBorder(BorderFactory.createEmptyBorder());
        controlsScroll.setViewportBorder(null);
        controlsScroll.setPreferredSize(new Dimension(0, controls.getPreferredSize().height + 12));
        controlsScroll.setMinimumSize(new Dimension(0, controls.getPreferredSize().height + 12));

        JPanel bottomInfo = new JPanel();
        bottomInfo.setLayout(new BoxLayout(bottomInfo, BoxLayout.Y_AXIS));
        bottomInfo.add(apiWarningLabel);
        bottomInfo.add(statusLabel);

        panel.add(controlsScroll, BorderLayout.NORTH);
        panel.add(bottomInfo, BorderLayout.SOUTH);

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
            Config cfg = configFromUi(true);
            apiClient.sendConfig(cfg);
            configRef.set(cfg);
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

    private void copyHackvertorTag() {
        try {
            Config cfg = configFromUi(false);
            String tag = buildHackvertoTag(cfg);
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(new StringSelection(tag), null);
            statusLabel.setText("Hackvertor tag copied");
        } catch (Exception ex) {
            String msg = errorMessage(ex);
            api.logging().logToError("Copy hackvertor tag failed: " + msg);
            statusLabel.setText("Copy hackvertor tag failed: " + msg);
        }
    }

    private void testAuthSteps() {
        runAsync("auth-test", () -> {
            try {
                String apiBase = apiBaseUrlField.getText().trim();
                if (apiBase.isEmpty()) {
                    throw new IllegalArgumentException("Token service base URL is required");
                }
                Config cfg = configFromUi(true);
                apiClient.sendConfig(cfg);
                configRef.set(cfg);
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
                ApiServiceManager.VerificationResult result = apiServiceManager
                        .verify(pythonPathField == null ? "" : pythonPathField.getText());
                if (result.ok) {
                    setStatus("API install OK");
                    api.logging().logToOutput(result.message);
                } else {
                    setStatus("API verification failed. See error tab of extension for more details.");
                    String verifyMessage = (result.message == null || result.message.isBlank())
                            ? "API verification failed (no details)."
                            : result.message;
                    api.logging().logToError(verifyMessage);
                    // Keep output logging for debugging visibility.
                    api.logging().logToOutput(verifyMessage);
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
                setStatus("API installation in progress...");
                apiServiceManager.install(
                        pythonPathField == null ? "" : pythonPathField.getText(),
                        apiInstallProxyField == null ? "" : apiInstallProxyField.getText());
                setStatus("API installed");
                api.logging().logToOutput("API installed");
            } catch (Exception ex) {
                String msg = errorMessage(ex);
                api.logging().logToError("Install failed: " + msg);
                setStatus("Install failed: " + msg);
            }
        });
    }

    private void toggleTokenService(JButton button) {
        runAsync("api-toggle", () -> {
            try {
                if (apiServiceManager.isRunning()) {
                    setStatus("Stopping token service...");
                    apiServiceManager.stop();
                    setStatus("Token service stopped");
                } else {
                    startTokenServiceInternal();
                }
                SwingUtilities.invokeLater(() -> updateStartStopButton(button));
                refreshApiWarningAsync();
            } catch (Exception ex) {
                handleServiceError("Start/stop failed", ex);
                refreshApiWarningAsync();
            }
        });
    }

    private void startTokenServiceInternal() throws Exception {
        setStatus("Starting token service...");
        apiServiceManager.start(pythonPathField == null ? "" : pythonPathField.getText());
        if (apiServiceManager.isRunning()) {
            setStatus("Token service started");
        } else {
            setStatus("Token service start failed");
        }
    }

    private void handleServiceError(String prefix, Exception ex) {
        String msg = errorMessage(ex);
        api.logging().logToError(prefix + ": " + msg);
        setStatus(prefix + ": " + msg);
    }

    private void updateStartStopButton(JButton button) {
        boolean running = apiServiceManager.isRunning();
        button.setText(running ? "API is on" : "API is off");
        Color bg = running ? new Color(60, 150, 80) : new Color(210, 60, 60);
        button.setBackground(bg);
        button.setForeground(Color.WHITE);
        button.setOpaque(true);
        button.setBorderPainted(false);
    }

    private void loadFromFile() {
        JFileChooser chooser = new JFileChooser();
        Config current = configRef.get();
        if (current != null && current.lastConfigDir != null && !current.lastConfigDir.isBlank()) {
            chooser.setCurrentDirectory(new java.io.File(current.lastConfigDir));
        }
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
            cfg.lastConfigDir = path.getParent().toString();
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
        Config current = configRef.get();
        if (current != null && current.lastConfigDir != null && !current.lastConfigDir.isBlank()) {
            chooser.setCurrentDirectory(new java.io.File(current.lastConfigDir));
        }
        int result = chooser.showSaveDialog(null);
        if (result != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            Config cfg = configFromUi(false);
            Path path = chooser.getSelectedFile().toPath();
            Files.writeString(path, configManager.toJson(cfg), StandardCharsets.UTF_8);
            cfg.lastConfigDir = path.getParent().toString();
            configManager.saveToStorage(cfg);
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
        cfg.apiInstallProxy = apiInstallProxyField == null ? "" : apiInstallProxyField.getText().trim();
        cfg.authenticationUrl = authenticationUrlField.getText().trim();
        cfg.headless = headlessCheckbox.isSelected();
        cfg.browserProxy = browserProxyField == null ? "" : browserProxyField.getText().trim();

        cfg.steps = new ArrayList<>(stepsPanel.getSteps());
        cfg.mtlsEnabled = mtlsEnabledCheckbox != null && mtlsEnabledCheckbox.isSelected();
        cfg.mtlsHostname = mtlsHostnameField == null ? "" : mtlsHostnameField.getText().trim();
        cfg.mtlsPin = mtlsPinField == null ? "" : new String(mtlsPinField.getPassword()).trim();
        cfg.mtlsCertCn = mtlsCertCnField == null ? "" : mtlsCertCnField.getText().trim();

        cfg.authenticationServerUrlSubstring = authenticationServerSubstringField.getText().trim();
        cfg.tokenParsingMode = parsingTabs.getSelectedIndex() == 1 ? "cookie" : "json_path";
        cfg.tokenJsonPath = jsonPathField.getText().trim();
        cfg.tokenCookieName = cookieNameField.getText().trim();
        cfg.refreshFrequencySeconds = (Integer) refreshFrequencySpinner.getValue();

        cfg.sessionLostMode = sessionRegexRadio.isSelected() ? "regex" : "status_code";
        cfg.sessionLostStatusCode = (Integer) sessionStatusSpinner.getValue();
        cfg.sessionLostRegex = sessionRegexField.getText().trim();
        cfg.autoSessionRecovery = sessionAutoRecoveryCheckbox == null || sessionAutoRecoveryCheckbox.isSelected();

        cfg.scopeTools = new ArrayList<>();
        for (Map.Entry<ToolType, JCheckBox> entry : toolCheckboxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                cfg.scopeTools.add(entry.getKey().name());
            }
        }
        cfg.requestHandlingMode = selectedRequestModeValue();
        cfg.singleUrlPrefix = singleUrlPrefixField == null ? "" : singleUrlPrefixField.getText().trim();

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

    private void updateMtlsPanelVisibility() {
        if (mtlsPanel == null || mtlsEnabledCheckbox == null) {
            return;
        }
        mtlsPanel.setVisible(mtlsEnabledCheckbox.isSelected());
        mtlsPanel.revalidate();
        mtlsPanel.repaint();
    }

    private JPanel buildJsonParsingPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = baseConstraints();
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

    private String buildHackvertoTag(Config cfg) throws Exception {
        Map<String, Object> tokenRequest = new LinkedHashMap<>();
        tokenRequest.put("authentication_url", cfg.authenticationUrl);
        tokenRequest.put("headless", cfg.headless);
        if (cfg.browserProxy != null && !cfg.browserProxy.isBlank()) {
            tokenRequest.put("proxy", cfg.browserProxy);
        }
        List<Map<String, Object>> steps = new ArrayList<>();
        for (AuthStep step : cfg.steps) {
            Map<String, Object> stepMap = new LinkedHashMap<>();
            stepMap.put("type", step.type);
            stepMap.put("selector", step.selector);
            stepMap.put("value", step.value);
            if (step.pin != null && !step.pin.isBlank()) {
                stepMap.put("pin", step.pin);
            }
            if (step.certCn != null && !step.certCn.isBlank()) {
                stepMap.put("cert_cn", step.certCn);
            }
            steps.add(stepMap);
        }
        tokenRequest.put("steps", steps);
        tokenRequest.put("mtls_enabled", cfg.mtlsEnabled);
        if (cfg.mtlsHostname != null && !cfg.mtlsHostname.isBlank()) {
            tokenRequest.put("mtls_hostname", cfg.mtlsHostname);
        }
        if (cfg.mtlsPin != null && !cfg.mtlsPin.isBlank()) {
            tokenRequest.put("mtls_pin", cfg.mtlsPin);
        }
        if (cfg.mtlsCertCn != null && !cfg.mtlsCertCn.isBlank()) {
            tokenRequest.put("mtls_cert_cn", cfg.mtlsCertCn);
        }
        tokenRequest.put("force", false);

        ObjectMapper mapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT);
        String tokenJson = mapper.writeValueAsString(tokenRequest);

        StringBuilder sb = new StringBuilder();
        sb.append("import re\n");
        sb.append("import json\n");
        sb.append("import urllib2\n\n");
        sb.append("jwt_re = re.compile(r'^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$')\n\n");
        sb.append("base_url = \"").append(cfg.apiBaseUrl).append("\"\n\n");
        sb.append("token_request = json.loads(r'''").append(tokenJson).append("''')\n\n");
        sb.append("token_url = base_url + \"/token\"\n");
        sb.append("token_body = json.dumps(token_request)\n");
        sb.append("req = urllib2.Request(token_url, token_body)\n");
        sb.append("req.add_header(\"Content-Type\", \"application/json\")\n");
        sb.append("req.add_header(\"Accept\", \"text/plain\")\n");
        sb.append("resp = urllib2.urlopen(req, timeout=20)\n");
        sb.append("body = resp.read().strip()\n");
        sb.append("resp.close()\n\n");
        sb.append("token = body\n");
        sb.append("output = token\n");
        return sb.toString();
    }

    private void initAutoUpdate() {
        autoUpdateTimer = new Timer(1000, e -> {
            if (suppressAutoUpdate) {
                return;
            }
            updateConfiguration();
        });
        autoUpdateTimer.setRepeats(false);

        addAutoUpdateListeners();
    }

    private void initApiWarningMonitor() {
        apiWarningTimer = new Timer(10000, e -> refreshApiWarningAsync());
        apiWarningTimer.setRepeats(true);
        apiWarningTimer.start();
        refreshApiWarningAsync();
    }

    private void refreshApiWarningAsync() {
        if (apiWarningLabel == null || !apiWarningCheckInProgress.compareAndSet(false, true)) {
            return;
        }
        runAsync("api-warning-check", () -> {
            boolean pending = initialApiStartupPending.get();
            boolean running = apiServiceManager.isRunning();
            SwingUtilities.invokeLater(() -> {
                if (apiStartStopButton != null) {
                    updateStartStopButton(apiStartStopButton);
                }
                if (apiWarningLabel != null) {
                    apiWarningLabel.setText(
                            (!pending && running)
                                    ? ""
                                    : "Warning: API service is not running. Go to the API tab to start or fix it.");
                    apiWarningLabel.setVisible(!pending && !running);
                }
            });
            apiWarningCheckInProgress.set(false);
        });
    }

    private void scheduleAutoUpdate() {
        if (suppressAutoUpdate) {
            return;
        }
        autoUpdateTimer.restart();
    }

    private void addAutoUpdateListeners() {
        addAutoUpdateListener(authenticationUrlField);
        addAutoUpdateListener(apiBaseUrlField);
        if (pythonPathField != null) {
            addAutoUpdateListener(pythonPathField);
        }
        if (apiInstallProxyField != null) {
            addAutoUpdateListener(apiInstallProxyField);
        }
        addAutoUpdateListener(jsonPathField);
        addAutoUpdateListener(cookieNameField);
        addAutoUpdateListener(authenticationServerSubstringField);
        addAutoUpdateListener(sessionRegexField);
        if (browserProxyField != null) {
            addAutoUpdateListener(browserProxyField);
        }

        headlessCheckbox.addActionListener(e -> scheduleAutoUpdate());
        if (mtlsEnabledCheckbox != null) {
            mtlsEnabledCheckbox.addActionListener(e -> scheduleAutoUpdate());
        }
        if (mtlsHostnameField != null) {
            addAutoUpdateListener(mtlsHostnameField);
        }
        if (mtlsPinField != null) {
            mtlsPinField.getDocument().addDocumentListener(new SimpleDocumentListener(this::scheduleAutoUpdate));
        }
        if (mtlsCertCnField != null) {
            addAutoUpdateListener(mtlsCertCnField);
        }

        parsingTabs.addChangeListener(e -> scheduleAutoUpdate());
        refreshFrequencySpinner.addChangeListener(e -> scheduleAutoUpdate());
        sessionStatusSpinner.addChangeListener(e -> scheduleAutoUpdate());
        sessionStatusRadio.addActionListener(e -> scheduleAutoUpdate());
        sessionRegexRadio.addActionListener(e -> scheduleAutoUpdate());
        if (sessionAutoRecoveryCheckbox != null) {
            sessionAutoRecoveryCheckbox.addActionListener(e -> scheduleAutoUpdate());
        }
        if (requestHandlingModeCombo != null) {
            requestHandlingModeCombo.addActionListener(e -> scheduleAutoUpdate());
        }
        if (singleUrlPrefixField != null) {
            addAutoUpdateListener(singleUrlPrefixField);
        }

        for (JCheckBox box : toolCheckboxes.values()) {
            box.addActionListener(e -> scheduleAutoUpdate());
        }
    }

    private void updateRequestHandlingModeControls() {
        if (requestHandlingModeCombo == null || singleUrlPrefixField == null || singleUrlPrefixLabel == null) {
            return;
        }
        String mode = selectedRequestModeValue();
        boolean single = "single_url".equals(mode);
        singleUrlPrefixField.setVisible(single);
        singleUrlPrefixLabel.setVisible(single);
        singleUrlPrefixField.setEnabled(single);
    }

    private String selectedRequestModeValue() {
        if (requestHandlingModeCombo == null) {
            return "burp_scope";
        }
        RequestModeOption selected = (RequestModeOption) requestHandlingModeCombo.getSelectedItem();
        return selected == null ? "burp_scope" : selected.value;
    }

    private void selectRequestMode(String value) {
        if (requestHandlingModeCombo == null) {
            return;
        }
        String target = (value == null || value.isBlank()) ? "burp_scope" : value;
        for (int i = 0; i < requestHandlingModeCombo.getItemCount(); i++) {
            RequestModeOption option = requestHandlingModeCombo.getItemAt(i);
            if (option != null && option.value.equals(target)) {
                requestHandlingModeCombo.setSelectedIndex(i);
                return;
            }
        }
        requestHandlingModeCombo.setSelectedIndex(0);
    }

    private static final class RequestModeOption {
        private final String label;
        private final String value;

        private RequestModeOption(String label, String value) {
            this.label = label;
            this.value = value;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    private void addAutoUpdateListener(JTextField field) {
        field.getDocument().addDocumentListener(new SimpleDocumentListener(this::scheduleAutoUpdate));
    }

    private static final class SimpleDocumentListener implements javax.swing.event.DocumentListener {
        private final Runnable onChange;

        private SimpleDocumentListener(Runnable onChange) {
            this.onChange = onChange;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }
    }
}

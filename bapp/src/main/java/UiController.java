import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Owns the native Swing editor, serialized revision-checked storage and explicit background actions. */
public final class UiController {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final MontoyaApi api;
    private final ConfigManager projects;
    private final UserLibraryStore library;
    private final SecretStore secrets;
    private final JourneyRegistry registry;
    private final AuthenticationCoordinator coordinator;
    private final Pkcs11IdentityManager identities;
    private final AtomicReference<Config.Controls> applied;
    private final Diagnostics diagnostics;
    private final ThreadPoolExecutor io = executor("bpsh-config-io", 1, 32), nativeActions = executor("bpsh-cert-action", 1, 4);
    private final EnumMap<JourneyDefinition.Scope, Long> scopeEpochs = new EnumMap<>(JourneyDefinition.Scope.class);
    private volatile Map<JourneyDefinition.Scope, Long> visibleEpochs = Map.of();
    private UUID projectRevision;
    private UserLibraryStore.Version libraryVersion = UserLibraryStore.Version.absent();
    private final EnumMap<JourneyDefinition.Scope, String> storageErrors = new EnumMap<>(JourneyDefinition.Scope.class);
    private volatile boolean closed, initialized;
    private boolean suppress;
    private boolean editorLoading;
    private boolean dirty;
    private final JTabbedPane journeyScopes = new JTabbedPane();
    private final JTabbedPane mainTabs = new JTabbedPane();
    private final JTextArea collectionFeedback = feedback("Journey collection status");
    private final CredentialsPanel credentials = new CredentialsPanel();
    private Timer settingsDebounce, automaticDebounce, journeyDebounce, journeyRetry, deviceDebounce;
    private boolean journeySaveInFlight, saveRequested, savePaused;
    private int saveRetries;
    private long editVersion;
    private Runnable afterJourneySave;
    private SecretStore.Key afterSaveOwner;
    private final JTabbedPane wizard = new JTabbedPane();
    private final Map<SecretStore.Key, Integer> journeySteps = new LinkedHashMap<>();
    private final EnumMap<JourneyDefinition.Scope, SecretStore.Key> lastJourneyByScope = new EnumMap<>(JourneyDefinition.Scope.class);
    private final CardLayout editorCards = new CardLayout();
    private final JPanel editorSurface = new JPanel(editorCards);
    private final JLabel draftState = new JLabel("No journey selected"), wizardProgress = new JLabel();
    private final JLabel batchSelection = new JLabel();
    private final JTextArea renameNotice = note("Renaming changes BPSH tags already used in requests.");
    private String draftAlias = "";
    private final JTextArea certificateDetails = new JTextArea("", 3, 45);
    private final SecurityDevicePicker devicePicker = new SecurityDevicePicker(this::deviceSelected, () -> discoverDevices(true));
    private volatile long deviceDiscoveryVersion;
    private boolean deviceDiscoveryRunning;
    private final JButton back = button("Back", () -> moveWizard(-1)), next = button("Next", () -> moveWizard(1));
    private final JButton testButton = button("Test login", () -> authenticate(false)), cancelButton = button("Cancel authentication", () -> selectedAction(true));
    private final JButton retryButton = button("Retry authentication", () -> authenticate(true));
    private final JButton clearTokenButton = new JButton("Clear cached credentials");
    private final JButton copyReferenceButton = new JButton("Copy BPSH tag");
    private final JButton reviewCertificate = new JButton("Open certificate settings");
    private final JButton chooseCertificateButton = new JButton("Choose certificate..."), inspectCertificateButton = new JButton("Inspect saved certificate");
    private final JButton retryCertificateButton = button("Retry certificate listing", () -> listCertificates(true));
    private boolean certificateListing, certificateRetryAvailable;
    private JPanel certificateFields, certificateSettings, certificateAdvanced, automaticFields;
    private final JToggleButton certificateAdvancedToggle = new JToggleButton();
    private JMenuItem reloadSelectedItem, exportSelectedItem, deleteSelectedItem;
    private Dialogs dialogs;
    private long editorEpoch;
    private long selectionEpoch;
    private long editingScopeEpoch, controlsScopeEpoch;
    private JPanel journeyEditor;
    private SecretStore.Key editing;
    private JourneyDefinition.Identity editingIdentity;
    private final Map<String, JTextField> fields = new LinkedHashMap<>();
    private final Map<String, JCheckBox> checks = new LinkedHashMap<>();
    private final Map<ToolType, JCheckBox> tools = new LinkedHashMap<>();
    private final JComboBox<JourneyDefinition.Scope> destination = new JComboBox<>(JourneyDefinition.Scope.values());
    private final DefaultListModel<Choice> savedModel = new DefaultListModel<>();
    private final JList<Choice> saved = new JList<>(savedModel);
    private final AutomaticRulesPanel automaticRules = new AutomaticRulesPanel();
    private JourneyDefinition.SlotKind slotKind = JourneyDefinition.SlotKind.INDEX;
    private String slotValue = "0";
    private final PlaceholderPasswordField pin = new PlaceholderPasswordField("Configured PKCS#11 PIN", 24);
    private boolean pinAvailable;
    private String selectedCertificateSha256 = "";
    private record CertificateDevice(String module, JourneyDefinition.SlotKind kind, String slot) {}
    private CertificateDevice selectedCertificateDevice;
    /** Public metadata confirmed by a successful selection in this editor, never restored from a saved fingerprint. */
    private Pkcs11IdentityManager.CertificateInfo loadedCertificate;
    private CertificateDevice displayedDevice;
    private record PendingPinFocus(SecretStore.Key key, long selection, long deviceVersion, String guidance, JComponent target) {}
    private PendingPinFocus pendingPinFocus;
    private final StepsPanel steps = new StepsPanel();
    private final SessionStatusBar status = new SessionStatusBar();
    private final JourneyEventLogPanel eventLog;
    private final JourneyCachePanel cacheView;
    private final CardLayout detailCards = new CardLayout();
    private final JPanel detailSurface = new JPanel(detailCards);
    private JSplitPane eventDock;
    private int eventDockHeight = 310;
    private Timer statusTimer;

    /** Keeps the scoped journey identity separate from its displayed name. */
    private record Choice(SecretStore.Key key, String label) {
        /** Returns the visible scope/name/alias label without accessing storage or secrets. */
        @Override public String toString() { return label; }
    }

    /** Captures a consistent EDT draft and owns all copied password buffers until its job finishes. */
    private record Draft(SecretStore.Key key, long scopeEpoch, long editorEpoch, long editVersion, Map<String, String> text, Map<String, Boolean> flags,
                         JourneyDefinition.SlotKind slotKind, String certificateSha256, StepsPanel.Snapshot steps, List<CredentialsPanel.Input> credentials, char[] pin) implements AutoCloseable {
        /** Wipes snapshots even when a queued job is rejected, superseded or discarded on unload. */
        @Override public void close() { steps.close(); if (pin != null) Arrays.fill(pin, '\0'); }
        /**
         * Returns metadata-only label; record-generated output would disclose passwords and selectors.
         *
         * @return Metadata-only label; record-generated output would disclose passwords and selectors.
         */
        @Override public String toString() { return "JourneyDraft[" + key + "]"; }
    }

    /** Wraps queued work so discarded jobs still close captured secret snapshots. */
    private final class Job implements Runnable {
        final AutoCloseable owner; final Work work;
        /**
         * Adopts captured secret buffers for a bounded background action, including its discarded-queue path.
         *
         * @param owner Optional captured buffers.
         * @param work Off-EDT action.
         */
        Job(AutoCloseable owner, Work work) { this.owner = owner; this.work = work; }
        /** Runs only while active and always releases owned inputs. */
        @Override public void run() { try { if (!closed) work.run(); } catch (Exception | LinkageError ex) { report(ex, owner instanceof Draft draft ? draft.editorEpoch() : -1, owner instanceof Draft draft ? draft.key() : null); } finally { discard(); } }
        /** Wipes captured values even if execution never began. */
        void discard() { if (owner != null) try { owner.close(); } catch (Exception ignored) { /* owned snapshots close idempotently */ } }
    }
    /** Represents checked background storage/browser setup work without exposing raw errors to Swing. */
    @FunctionalInterface private interface Work {
        /**
         * Runs one bounded background action whose errors are sanitized before display.
         * @throws Exception Classified by the controller before it reaches logs or Swing.
         */
        void run() throws Exception;
    }

    /** Isolates modal decisions from storage actions so cancellation and preview flows can be exercised locally. */
    interface Dialogs {
        /** @param parent Burp suite frame. @param save Whether to choose an export destination. @return Chosen file, or null after cancellation. */
        Path file(Component parent, boolean save);
        /** Chooses one or several journey exports; simple test hosts may supply one file. */
        default List<Path> importFiles(Component parent) { Path chosen = file(parent, false); return chosen == null ? List.of() : List.of(chosen); }
        /** Keeps middleware browsing independent of the journey import/export folder. */
        default Path middleware(Component parent) { return file(parent, false); }
        /** Selects an optional PEM CA bundle independently of middleware navigation. */
        default Path trustedCa(Component parent) { return file(parent, false); }
        /** @param parent Burp suite frame. @param content Plain text or owned preview component. @param title Task title. @return True only after explicit OK. */
        boolean confirm(Component parent, Object content, String title);
        /** Gives production dialogs a concrete action label while preserving injectable modal decisions. */
        default boolean confirmAction(Component parent, Object content, String title, String action) { return confirm(parent, content, title); }
        /** @param parent Burp suite frame. @param text Plain-text information. */
        void inform(Component parent, String text);
        /** Shows explicit read-only public certificate inspection without a replacement action. */
        default void inspect(Component parent, Component content) { confirm(parent, content, "Saved certificate details"); }
        /** @param text Literal reference copied only after an explicit user action; never a captured credential. */
        default void copyText(String text) { Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new java.awt.datatransfer.StringSelection(text), null); }
    }

    /** Presents standard parented Swing dialogs; it performs no storage or authentication work. */
    private static final class SwingDialogs implements Dialogs {
        private final RememberingFileChooser journeys, middleware, trustedCa;
        SwingDialogs(burp.api.montoya.persistence.Preferences preferences) {
            journeys = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.JOURNEYS);
            middleware = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.MIDDLEWARE);
            trustedCa = new RememberingFileChooser(preferences, RememberingFileChooser.Purpose.TRUSTED_CA);
        }
        /** @return Selected path, preserving the native chooser's cancellation behavior. */
        @Override public Path file(Component parent, boolean save) {
            var chooser = journeys.create(false); int result = save ? chooser.showSaveDialog(parent) : chooser.showOpenDialog(parent);
            journeys.remember(chooser, result == JFileChooser.APPROVE_OPTION);
            return result == JFileChooser.APPROVE_OPTION ? chooser.getSelectedFile().toPath() : null;
        }
        @Override public List<Path> importFiles(Component parent) {
            var chooser = journeys.create(true); chooser.setDialogTitle("Import journeys");
            boolean approved = chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION; journeys.remember(chooser, approved);
            if (!approved) return List.of();
            var files = chooser.getSelectedFiles();
            if (files.length == 0 && chooser.getSelectedFile() != null) return List.of(chooser.getSelectedFile().toPath());
            return Arrays.stream(files).map(java.io.File::toPath).distinct().toList();
        }
        @Override public Path middleware(Component parent) {
            var chooser = middleware.create(false);
            boolean approved = chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION;
            middleware.remember(chooser, approved);
            return approved ? chooser.getSelectedFile().toPath() : null;
        }
        @Override public Path trustedCa(Component parent) { var chooser = trustedCa.create(false); chooser.setDialogTitle("Choose trusted CA PEM bundle"); boolean approved = chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION; trustedCa.remember(chooser, approved); return approved ? chooser.getSelectedFile().toPath() : null; }
        /** @return Whether the operator accepted this task-specific confirmation. */
        @Override public boolean confirm(Component parent, Object content, String title) { return JOptionPane.showConfirmDialog(parent, dialogContent(parent, content), title, JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION; }
        @Override public boolean confirmAction(Component parent, Object content, String title, String action) { return JOptionPane.showOptionDialog(parent, dialogContent(parent, content), title, JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{action, "Cancel"}, "Cancel") == 0; }
        /** Displays plain-text information over the same suite frame as other extension dialogs. */
        @Override public void inform(Component parent, String text) { JOptionPane.showMessageDialog(parent, text, "Browser Powered Session Handler", JOptionPane.INFORMATION_MESSAGE); }
        @Override public void inspect(Component parent, Component content) { JOptionPane.showMessageDialog(parent, dialogContent(parent, content), "Saved certificate details", JOptionPane.INFORMATION_MESSAGE); }
    }

    /**
     * Keeps wrapping confirmations and scrollable previews inside a compact Burp window.
     * @param parent Owning suite frame; null is supported for isolated component checks.
     * @param value Plain text or an owned preview component.
     * @return Original component with bounded preferred dimensions, or wrapping plain-text guidance.
     */
    private static Object dialogContent(Component parent, Object value) {
        Object content = value instanceof String text ? note(text) : value;
        if (parent == null || !(content instanceof JComponent component)) return content;
        int width = Math.max(240, parent.getWidth() - 160), height = Math.max(160, parent.getHeight() - 180);
        var preferred = component.getPreferredSize();
        component.setPreferredSize(new Dimension(Math.min(width, preferred.width), Math.min(height, preferred.height)));
        return component;
    }

    /**
     * Composes UI ownership without reading storage or creating any browser/native operation.
     * @param api Host UI/persistence boundary.
     * @param projects Native project revision writer.
     * @param library Native user-library CAS store and watcher.
     * @param secrets Separate session-value owner.
     * @param registry Native immutable publications.
     * @param coordinator Shared acquisition/cancellation policy.
     * @param identities Native certificate listing and PIN suppression.
     * @param applied Current validated project controls used by hooks.
     * @param diagnostics Safe rate-limited output.
     */
    public UiController(MontoyaApi api, ConfigManager projects, UserLibraryStore library, SecretStore secrets, JourneyRegistry registry,
                        AuthenticationCoordinator coordinator, Pkcs11IdentityManager identities, AtomicReference<Config.Controls> applied, Diagnostics diagnostics) {
        this.api = api; this.projects = projects; this.library = library; this.secrets = secrets; this.registry = registry;
        this.dialogs = new SwingDialogs(api == null ? null : api.persistence().preferences());
        this.coordinator = coordinator; this.identities = identities; this.applied = applied; this.diagnostics = diagnostics;
        this.eventLog = new JourneyEventLogPanel(coordinator.events(), () -> { status.setLogOpen(false); showEventDock(); });
        this.eventLog.onStep(this::canRevealStep, target -> revealStep(target, null));
        this.cacheView = new JourneyCachePanel(() -> { status.setCacheOpen(false); showEventDock(); }, message -> {
            var entry = currentEditorEntry();
            if (entry != null) coordinator.events().append(entry.identity().key(), Instant.now(), JourneyEventLog.Level.WARNING, message);
        });
        for (var scope : JourneyDefinition.Scope.values()) scopeEpochs.put(scope, 0L);
    }

    /**
     * Builds the saved-journey editor on the EDT; timers only snapshot local fields or read safe metadata.
     * @return Complete native suite-tab component.
     */
    public Component buildUi() {
        JPanel root = new JPanel(new BorderLayout(10, 8)); root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        var sidebar = new JPanel(new BorderLayout(5, 8)); saved.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION); literalJourneyLabels();
        saved.setFocusable(true); saved.setRequestFocusEnabled(true);
        saved.addMouseListener(new java.awt.event.MouseAdapter() {
            // Host styling can change focusability after buildUi; restore keyboard selection on interaction.
            @Override public void mousePressed(java.awt.event.MouseEvent event) { saved.setFocusable(true); saved.setRequestFocusEnabled(true); saved.requestFocusInWindow(); }
        });
        saved.setToolTipText("Select one journey to edit. Use Ctrl or Shift to select several journeys for deletion or export.");
        saved.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting() || suppress) return;
            if (saved.getSelectedValuesList().size() == 1) {
                var selected = saved.getSelectedValue().key();
                if (!selected.equals(editing)) leaveDraft(() -> open(selected));
                else { editorCards.show(editorSurface, "editor"); status.context(editing); }
            }
            refreshJourneyUi();
        });
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0)); actions.add(button("New journey", this::newJourney));
        var more = UiIcons.button(UiIcons.Action.MORE, "Journey actions", () -> {}); var menu = new JPopupMenu();
        reloadSelectedItem = menuItem(menu, "Reload selected", () -> { if (editing != null) open(editing); });
        reloadSelectedItem.setToolTipText("Reload saved settings, replacing this journey's local edits.");
        menuItem(menu, "Import journeys...", this::importJourneys); exportSelectedItem = menuItem(menu, "Export selected...", this::exportJourney);
        menuItem(menu, "Select all journeys", () -> { if (!savedModel.isEmpty()) saved.setSelectionInterval(0, savedModel.size() - 1); });
        menu.addSeparator(); deleteSelectedItem = menuItem(menu, "Delete selected...", this::delete);
        more.addActionListener(e -> menu.show(more, 0, more.getHeight())); actions.add(more);
        journeyScopes.addTab("Project", null, new JPanel(),
                "Saved journeys stay with this Burp project. Temporary projects keep them only for this session.");
        journeyScopes.addTab("User", null, new JPanel(),
                "Journeys saved locally for your user account, available across Burp projects.");
        journeyScopes.setPreferredSize(new Dimension(220, 35));
        journeyScopes.addChangeListener(e -> { if (!suppress) selectScope(journeyScopes.getSelectedIndex()); });
        var sidebarHeader = new JPanel(new BorderLayout(0, 5)); sidebarHeader.add(journeyScopes, BorderLayout.NORTH); sidebarHeader.add(actions, BorderLayout.SOUTH);
        sidebar.add(sidebarHeader, BorderLayout.NORTH); sidebar.add(new JScrollPane(saved), BorderLayout.CENTER);
        wizard.addTab("Setup", journeyForm()); wizard.addTab("Login steps", steps);
        wizard.addTab("Capture credentials", extractionForm()); wizard.addTab("Client certificate", tlsForm());
        wizard.addTab("Test & use", testAndUseForm()); wizard.addChangeListener(e -> { rememberJourneyStep(); refreshJourneyUi(); });
        var editor = new JPanel(new BorderLayout(6, 8)); journeyEditor = editor;
        draftState.setFont(draftState.getFont().deriveFont(Font.BOLD)); editor.add(draftState, BorderLayout.NORTH);
        editor.add(wizard, BorderLayout.CENTER); editor.add(journeyButtons(), BorderLayout.SOUTH);
        var empty = new JPanel(new GridBagLayout()); var welcome = new JPanel(new GridLayout(0, 1, 6, 10));
        welcome.add(new JLabel("Select a journey, or create one to get started."));
        welcome.add(new JLabel("Set up a browser login, test it, then insert its tag from a request context menu."));
        welcome.add(button("Create journey", this::newJourney)); empty.add(welcome);
        editorSurface.add(empty, "empty"); editorSurface.add(editor, "editor"); editorCards.show(editorSurface, "empty");
        var batch = new JPanel(new GridBagLayout()); var batchContent = new JPanel(new GridLayout(0, 1, 0, 10));
        batchContent.add(batchSelection); batchContent.add(new JLabel("Use Journey actions to delete or export them.")); batchContent.add(new JLabel("Select one journey to edit it.")); batch.add(batchContent); editorSurface.add(batch, "batch");
        var split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, sidebar, editorSurface); split.setResizeWeight(0.2); split.setDividerLocation(245);
        detailSurface.add(eventLog, "events"); detailSurface.add(cacheView, "cache");
        eventDock = new JSplitPane(JSplitPane.VERTICAL_SPLIT, split, detailSurface); eventDock.setResizeWeight(1); eventDock.setBorder(BorderFactory.createEmptyBorder());
        detailSurface.setVisible(false); eventDock.setDividerSize(0);
        var journeyFooter = new JPanel(new BorderLayout()); journeyFooter.add(status, BorderLayout.CENTER); journeyFooter.add(collectionFeedback, BorderLayout.SOUTH);
        var journeys = new JPanel(new BorderLayout()); journeys.add(eventDock, BorderLayout.CENTER); journeys.add(journeyFooter, BorderLayout.SOUTH);
        mainTabs.addTab("Journeys", journeys); mainTabs.addTab("Session handling", controlsForm()); mainTabs.addTab("Settings", settingsForm());
        root.add(mainTabs, BorderLayout.CENTER);
        status.onLogToggle(this::showEventDock);
        status.addAction(cancelButton); status.addAction(retryButton); status.addAction(reviewCertificate);
        reviewCertificate.addActionListener(e -> { mainTabs.setSelectedIndex(0); wizard.setSelectedIndex(3); pin.requestFocusInWindow(); });
        mainTabs.addChangeListener(e -> refreshJourneyUi());
        journeyDebounce = new Timer(500, e -> attemptSave()); journeyDebounce.setRepeats(false);
        journeyRetry = new Timer(1000, e -> attemptSave()); journeyRetry.setRepeats(false);
        deviceDebounce = new Timer(450, e -> discoverDevices(false)); deviceDebounce.setRepeats(false);
        statusTimer = new Timer(1000, e -> refreshJourneyUi()); statusTimer.start();
        settingsDebounce = new Timer(600, e -> saveControls(true)); settingsDebounce.setRepeats(false);
        automaticDebounce = new Timer(600, e -> saveControls(false)); automaticDebounce.setRepeats(false);
        credentials.setChangeListener(() -> { clearUnusedFields(); edited(); }); steps.setChangeListener(this::edited);
        root.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(KeyStroke.getKeyStroke("control S"), "saveJourney");
        root.getActionMap().put("saveJourney", new AbstractAction() {
            /** Flushes the current autosave or retries a stopped save without adding a manual-save control. */
            @Override public void actionPerformed(java.awt.event.ActionEvent e) { if (editing != null) save(false); }
        });
        friendly(destination);
        pin.setToolTipText("PIN used automatically for client-certificate login.");
        refreshModes(); refreshJourneyUi(); return root;
    }

    /** Enqueues native startup loading after the tab exists, with no login on extension startup. */
    public void start() {
        // Burp's theme pass can replace combo renderers after buildUi; restore labels without changing values.
        ui(() -> { friendly(destination); literalJourneyLabels(); automaticRules.refreshPresentation(); steps.refreshPresentation(); status.refreshPresentation(); eventLog.refreshPresentation(); });
        enqueue(io, null, () -> { reload(); library.watch(loaded -> enqueue(io, loaded, () -> libraryChanged(loaded)), error -> enqueue(io, null, () -> storageFailed(JourneyDefinition.Scope.LIBRARY, error))); });
    }

    /**
     * Returns journey identity and ordinary proxy form; secrets are distinct from nonsecret fields.
     *
     * @return Journey identity and ordinary proxy form; secrets are distinct from nonsecret fields.
     */
    private Component journeyForm() {
        var panel = form(); row(panel, "Display name", field("name", "Employee login"));
        renameNotice.setVisible(false); row(panel, "", renameNotice);
        row(panel, "Login URL", field("url", "https://login.example/login"));
        row(panel, "", check("headless", "Run browser in background"));
        row(panel, "", check("mtls", "Use a client certificate (PKCS#11)"));
        row(panel, "Proxy URL (optional)", field("proxy", "http://127.0.0.1:8080"));
        row(panel, "", note("Leave the proxy URL empty for a direct connection. Proxy authentication is not supported."));
        var remember = check("remember", "Remember secrets");
        remember.setToolTipText("Remembered PINs and secure inputs are saved locally. Leave unchecked to keep them for this session only.");
        remember.getAccessibleContext().setAccessibleDescription("Remembered PINs and secure inputs are saved locally. Leave unchecked to keep them for this session only.");
        row(panel, "", remember);
        var advanced = form(); row(advanced, "Browser action timeout (seconds)", field("navTimeout", "30"));
        row(advanced, "Final capture wait (seconds)", field("tokenWait", "3"));
        row(panel, "", disclosure("Advanced setup", advanced)); return scroll(panel);
    }

    /**
     * Returns explicit response/cookie selection, ordinary injection and finite lifetime controls.
     *
     * @return Explicit response/cookie selection, ordinary injection and finite lifetime controls.
     */
    private Component extractionForm() {
        var panel = form(); row(panel, "", credentials);
        var advanced = form();
        row(advanced, "Maximum cache age (seconds)", field("maxAge", "1800")); row(advanced, "Refresh before expiry (seconds)", field("skew", "10"));

        row(panel, "", disclosure("Credential cache", advanced));
        return scroll(panel);
    }

    /**
     * Returns native middleware/slot/fingerprint selection with separately owned PIN state.
     *
     * @return Native middleware/slot/fingerprint selection with separately owned PIN state.
     */
    private Component tlsForm() {
        var panel = form();

        certificateFields = form(); var module = new JPanel(new BorderLayout(5, 0));
        module.add(InlineValidation.wrap(field("module", "Absolute path to PKCS#11 middleware")), BorderLayout.CENTER);
        module.add(button("Browse...", () -> chooseFile("module")), BorderLayout.EAST); row(certificateFields, "Middleware file", module);
        row(certificateFields, "Security device", devicePicker);
        certificateSettings = form();
        row(certificateSettings, "PIN", pin); pin.getDocument().addDocumentListener(new DocumentChangeListener(this::pinChanged));
        var select = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0)); chooseCertificateButton.addActionListener(e -> listCertificates(false)); select.add(InlineValidation.wrap(chooseCertificateButton));
        inspectCertificateButton.setVisible(false); inspectCertificateButton.addActionListener(e -> listCertificates(false, true)); inspectCertificateButton.setToolTipText("Read public details for the saved selection using the configured device and PIN. Keeps the selected certificate unchanged.");
        select.add(inspectCertificateButton); select.add(retryCertificateButton); row(certificateSettings, "", select);
        certificateDetails.setEditable(false); certificateDetails.setLineWrap(true); certificateDetails.setWrapStyleWord(true); certificateDetails.setOpaque(false);
        row(certificateSettings, "Selected certificate", certificateDetails);
        certificateAdvanced = form();
        row(certificateAdvanced, "Additional authentication servers", field("origins", "https://identity.example"));
        var caInput = field("ca", "Path to a PEM CA file");
        var ca = new JPanel(new BorderLayout(5, 0)); ca.setToolTipText(caInput.getToolTipText()); ca.add(InlineValidation.wrap(caInput)); ca.add(button("Browse...", () -> chooseFile("ca")), BorderLayout.EAST); row(certificateAdvanced, "Trusted CA (optional)", ca);
        if (ca.getClientProperty("rowLabel") instanceof JLabel label) { label.setLabelFor(caInput); caInput.putClientProperty("rowLabel", label); }
        row(certificateSettings, "", disclosure("Advanced settings", certificateAdvanced, certificateAdvancedToggle));
        row(certificateFields, "", certificateSettings);

        row(panel, "", certificateFields); return scroll(panel);
    }

    /**
     * Returns explicit shared-cycle actions and native Copy tag; no API service controls remain.
     *
     * @return Explicit shared-cycle actions and native Copy tag; no API service controls remain.
     */
    private Component journeyButtons() {
        var navigation = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0)); navigation.add(back); navigation.add(next); navigation.add(wizardProgress);
        next.setMnemonic(java.awt.event.KeyEvent.VK_N); back.setMnemonic(java.awt.event.KeyEvent.VK_B);
        cancelButton.setToolTipText("Stop this journey's login and release requests waiting for it. Keep any token that is still valid.");
        var panel = new JPanel(new BorderLayout(6, 6)); panel.add(navigation, BorderLayout.NORTH); return panel;
    }

    /** Uses the shared status bar for test outcomes. @return Test/cache actions and tag guidance without duplicate result output. */
    private Component testAndUseForm() {
        var panel = form(); var tests = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        testButton.setText("Test login"); clearTokenButton.addActionListener(e -> selectedAction(false));
        tests.add(testButton); tests.add(clearTokenButton);
        tests.setBorder(BorderFactory.createTitledBorder("Test login")); row(panel, "", tests);
        retryButton.setToolTipText("Run the saved journey and resume recovery if credentials are captured. Previous requests are not resent. Check the device and PIN before retrying client-certificate login.");
        testButton.setToolTipText("Run the saved journey. A successful Test resumes paused recovery without resending previous requests.");
        var use = new JPanel(new BorderLayout(0, 6)); use.setBorder(BorderFactory.createTitledBorder("Use in requests"));
        var actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0)); actions.add(copyReferenceButton);
        copyReferenceButton.setToolTipText("Paste into a Burp request. The extension substitutes a valid token when the request is sent.");
        copyReferenceButton.addActionListener(e -> copyReferences()); use.add(actions, BorderLayout.NORTH);
        use.add(note("Paste a BPSH tag into a request, or right-click in the request and choose Add authentication token."));
        row(panel, "", use);
        return scroll(panel);
    }
    /** Flushes the current reference identity without authenticating or reading cached credentials. */
    private void copyReferences() {
        if (!readyEditor()) return;
        if (dirty || editingIdentity == null) { save(false, this::copyReferences); return; }
        if (!validateCredentialNames()) return;
        var entry = currentEditorEntry(); if (entry == null) return;
        try {
            var menu = referenceMenu(entry);
            menu.show(copyReferenceButton, 0, copyReferenceButton.getHeight());
        } catch (IllegalArgumentException error) { focusInvalidField(error.getMessage()); }
    }
    /** @param entry Exact saved owner. @return Named credential and explicit encoding choices, containing references only. */
    private JPopupMenu referenceMenu(JourneyRegistry.Entry entry) {
        var menu = new JPopupMenu(); var inputs = credentials.snapshot();
        if (inputs.size() > 1) {
            for (var input : inputs) {
                String name = input.name().trim().toLowerCase(java.util.Locale.ROOT);
                var credential = new JMenu(name); credential.putClientProperty("html.disable", true); menu.add(credential);
                referenceFormats(credential, entry, name);
            }
        } else referenceFormats(menu, entry, null);
        return menu;
    }
    /** @return Whether the required credential names are valid; otherwise reveals the first invalid field. */
    private boolean validateCredentialNames() {
        String error = credentials.validateNames();
        if (error == null) return true;
        String guidance = validationMessage(error, credentials.snapshot());
        focusInvalidField(error); status.error(guidance);
        var entry = currentEditorEntry();
        if (entry != null) coordinator.events().append(entry.identity().key(), Instant.now(), JourneyEventLog.Level.ERROR, guidance);
        return false;
    }
    /** @param parent Popup or credential submenu. @param entry Saved owner. @param token Optional named token. */
    private void referenceFormats(JComponent parent, JourneyRegistry.Entry entry, String token) {
        for (String format : AuthenticationTagMenu.FORMATS) {
            var item = new JMenuItem(format); parent.add(item);
            item.addActionListener(e -> {
                if (dirty || !registry.snapshot().isCurrent(entry.identity())) return;
                try {
                    var reference = AuthenticationTagMenu.tag(entry.definition().alias(), token, format);
                    dialogs.copyText(reference);
                    coordinator.events().append(entry.identity().key(), Instant.now(), JourneyEventLog.Level.INFO, "BPSH tag copied.");
                } catch (IllegalStateException | SecurityException | HeadlessException error) {
                    coordinator.events().append(entry.identity().key(), Instant.now(), JourneyEventLog.Level.ERROR, "Could not access the clipboard.");
                    status.setLogOpen(true); showEventDock();
                }
                refreshJourneyUi();
            });
        }
    }

    /** Adds a secondary popup action without giving maintenance tasks primary visual weight. @param menu Owned popup. @param title Action label. @param action EDT snapshot/action. @return Item whose enabled state follows the current selection. */
    private static JMenuItem menuItem(JPopupMenu menu, String title, Runnable action) { var item = new JMenuItem(title); item.addActionListener(e -> action.run()); menu.add(item); return item; }

    /** Collapses optional settings while retaining their field values and normal Swing keyboard behavior. @param title Disclosure action. @param content Optional settings. @return A native expandable section. */
    private static Component disclosure(String title, Component content) {
        return disclosure(title, content, new JToggleButton());
    }
    /** @param title Disclosure caption. @param content Optional settings. @param toggle Owner-retained disclosure control. @return Expandable settings group. */
    private static Component disclosure(String title, Component content, JToggleButton toggle) {
        var panel = new JPanel(new BorderLayout(0, 5)); toggle.setText(title); toggle.setHorizontalAlignment(SwingConstants.LEFT);
        content.setVisible(false); toggle.addActionListener(e -> { content.setVisible(toggle.isSelected()); panel.revalidate(); panel.repaint(); });
        panel.add(toggle, BorderLayout.NORTH); panel.add(content, BorderLayout.CENTER); return panel;
    }

    /** Selects a local middleware file without loading it or submitting a PIN. @param key Named path field to populate. */
    private void chooseFile(String key) { Path file = key.equals("ca") ? dialogs.trustedCa(parent()) : dialogs.middleware(parent()); if (file != null) fields.get(key).setText(file.toAbsolutePath().toString()); }

    /**
     * Returns ordinary policy and independent numeric-or-Unlimited waiter limits, saved only after validation.
     *
     * @return Ordinary policy and independent numeric-or-Unlimited waiter limits, saved only after validation.
     */
    private Component controlsForm() {
        var panel = form(); row(panel, "", check("enabled", "Automatically authenticate matching requests"));
        automaticFields = form(); row(automaticFields, "", automaticRules);
        var toolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT)); for (ToolType tool : Config.SUPPORTED_TOOLS) { var box = new JCheckBox(tool.name()); box.addActionListener(e -> controlsEdited()); tools.put(tool, box); toolPanel.add(box); } row(automaticFields, "Eligible HTTP tools", toolPanel); row(panel, "", automaticFields);
        automaticRules.onChange(this::controlsEdited); return scroll(panel);
    }
    /** Exposes advanced global waiting limits independently of journey setup. @return Explicit duration and capacity settings. */
    private Component settingsForm() {
        var panel = form(); row(panel, "Request wait (seconds)", field("control.request", "60"));
        row(panel, "Login attempt timeout (seconds)", field("control.attempt", "60")); row(panel, "Total login timeout (seconds)", field("control.cycle", "300"));
        row(panel, "Global waiting requests", check("globalUnlimited", "Unlimited")); row(panel, "Global limit", field("control.global", "Positive integer when enabled"));
        row(panel, "Per-journey waiting requests", check("perUnlimited", "Unlimited")); row(panel, "Per-journey limit", field("control.per", "Positive integer when enabled"));
 return scroll(panel);
    }
    /**
     * Moves through the wizard without replacing the draft; optional certificate setup is skipped when disabled.
     * @param direction Negative for Back, positive for Next; later pages remain directly accessible when revisiting.
     */
    private void moveWizard(int direction) {
        int current = wizard.getSelectedIndex(), target = current + direction;
        if (target == 3 && !checks.get("mtls").isSelected()) target += direction;
        if (target >= 0 && target < wizard.getTabCount()) wizard.setSelectedIndex(target);
    }

    /** Flushes the latest edits before navigation, retaining the editor if storage cannot commit them. */
    private void leaveDraft(Runnable proceed) {
        if (!dirty || editing == null) { proceed.run(); return; }
        restoreSavedSelection(); save(false, proceed);
    }

    /** Restores selection to the draft being protected without recursively requesting another navigation. */
    private void restoreSavedSelection() {
        suppress = true;
        try { saved.clearSelection(); for (int i = 0; i < savedModel.size(); i++) if (savedModel.get(i).key().equals(editing)) { saved.setSelectedIndex(i); break; } }
        finally { suppress = false; }
    }

    /** Captures the selected saved identities together; missing rows invalidate the whole selection. */
    private List<JourneyRegistry.Entry> selectedEntries() {
        var snapshot = registry.snapshot(); var entries = new ArrayList<JourneyRegistry.Entry>();
        for (var choice : saved.getSelectedValuesList()) {
            var entry = snapshot.entries().get(choice.key());
            if (entry == null) return List.of();
            entries.add(entry);
        }
        return List.copyOf(entries);
    }

    /** Restores a captured batch without triggering one editor-open operation per selected row. */
    private void selectSavedKeys(List<SecretStore.Key> keys) {
        boolean previous = suppress; suppress = true;
        try { saved.clearSelection(); for (int i = 0; i < savedModel.size(); i++) if (keys.contains(savedModel.get(i).key())) saved.addSelectionInterval(i, i); }
        finally { suppress = previous; }
        refreshJourneyUi();
    }

    /** Export never uses an unsaved selected draft or an unavailable saved generation. */
    private boolean canExportSelection(List<JourneyRegistry.Entry> entries) {
        return !entries.isEmpty() && !editorLoading && entries.stream().allMatch(e -> registry.snapshot().isCurrent(e.identity()))
                && !(dirty && entries.stream().anyMatch(e -> e.identity().key().equals(editing)));
    }

    /**
     * Tests whether saved-only actions refer to an active, unchanged saved definition.
     * @return False for new, dirty, unavailable or loading journeys; never resolves an edited alias as another account.
     */
    private boolean canUseSavedJourney() {
        return !dirty && currentEditorEntry() != null;
    }

    /**
     * Resolves only the saved generation actually loaded into the visible editor, including while it has edits.
     * @return The visible saved identity, or null when storage changed, selection is loading, or the draft is new.
     */
    private JourneyRegistry.Entry currentEditorEntry() {
        if (!initialized || editing == null || editingIdentity == null || editorLoading || closed
                || editingScopeEpoch != visibleEpochs.getOrDefault(editing.scope(), -1L)) return null;
        var snapshot = registry.snapshot(); var entry = snapshot.entries().get(editing);
        return entry != null && editingIdentity.equals(entry.identity()) && !snapshot.unavailableScopes().contains(editing.scope()) ? entry : null;
    }

    /**
     * Rejects a queued saved action if its captured identity was replaced before the worker executes it.
     * @param entry Saved identity approved while its definition was visible.
     * @throws IllegalStateException If a later publication made the approved identity obsolete or unavailable.
     */
    private void checkCurrent(JourneyRegistry.Entry entry) {
        if (!registry.snapshot().isCurrent(entry.identity())) throw new IllegalStateException("This journey changed after it was selected. Reload it, review the configuration, and try again.");
    }

    /** Refreshes only safe local save/authentication metadata and saved-reference controls on the EDT. */
    private void refreshJourneyUi() {
        if (closed) return;
        var selected = selectedEntries(); int selectionCount = saved.getSelectedIndices().length;
        status.setVisible(editing != null && selectionCount == 1); collectionFeedback.setVisible(!status.isVisible());
        if (exportSelectedItem != null) exportSelectedItem.setEnabled(canExportSelection(selected));
        if (deleteSelectedItem != null) {
            deleteSelectedItem.setText(selectionCount > 1 ? "Delete " + selectionCount + " journeys..." : "Delete selected...");
            deleteSelectedItem.setEnabled(!selected.isEmpty() && selected.stream().noneMatch(e -> registry.snapshot().unavailableScopes().contains(e.identity().scope())));
        }
        if (selectionCount > 1) {
            if (reloadSelectedItem != null) reloadSelectedItem.setEnabled(false);
            cacheView.clear(); status.cacheAvailable(false); eventLog.refresh(null, null); status.logCount(false, 0);
            batchSelection.setText(selectionCount + " journeys selected"); editorCards.show(editorSurface, "batch"); status.context(null); status.state(selectionCount + " journeys selected", "", false); refreshJourneyDock(); return;
        }
        editorCards.show(editorSurface, editing == null ? "empty" : "editor"); status.context(editing);
        var entry = editing == null ? null : registry.snapshot().entries().get(editing);
        boolean ready = initialized && editing != null && !editorLoading;
        boolean stale = ready && editingIdentity != null && currentEditorEntry() == null && !journeySaveInFlight;
        draftState.setText(!ready ? "Select or create a journey" : (stale ? "Storage changed: reload journey" : ""));
        wizardProgress.setVisible(false);
        back.setEnabled(ready && wizard.getSelectedIndex() > 0); next.setEnabled(ready && wizard.getSelectedIndex() < wizard.getTabCount() - 1);
        boolean active = false, recovery = false, tokenAvailable = false;
        if (entry != null) {
            var current = coordinator.status(entry.identity());
            active = Set.of(AuthenticationCoordinator.Phase.QUEUED, AuthenticationCoordinator.Phase.RUNNING, AuthenticationCoordinator.Phase.BACKOFF).contains(current.phase());
            recovery = current.failure() != null || current.phase() == AuthenticationCoordinator.Phase.COOLDOWN;
            tokenAvailable = current.usableToken();
            String message = current.phase() == AuthenticationCoordinator.Phase.PAUSED ? "Automatic recovery paused: " + entry.definition().displayName() : active ? switch (current.phase()) { case QUEUED -> "Waiting to sign in..."; case BACKOFF -> "Waiting to retry..."; default -> current.setupStage() == null ? "Signing in..." : current.setupStage().description(); }
                    : current.failure() != null ? current.failure().problem() : current.usableToken() ? current.acceptedUse() ? "Request accepted" : "Credentials captured; protected access unverified" : "Not authenticated";
            if (current.waitingRequests() > 0) message += " · " + current.waitingRequests() + (current.waitingRequests() == 1 ? " request waiting" : " requests waiting");
            String detail = !active && current.failure() != null ? current.failure().getMessage() + (current.usableToken() ? " Previously cached credentials are still available." : "") : "";
            if (current.phase() == AuthenticationCoordinator.Phase.PAUSED) status.clear();
            status.state(message, detail, active);
            reviewCertificate.setVisible(!active && current.failure() != null && checks.get("mtls").isSelected()
                    && (current.failure().phase() == AuthenticationFailure.Phase.PIN || current.failure().phase() == AuthenticationFailure.Phase.PROVIDER || current.failure().reason() == AuthenticationFailure.Cause.MISSING_SECRET && !pinAvailable));
        } else { status.state(!initialized ? "Loading journeys..." : editorLoading ? "Loading journey..." : ready ? "Configure this journey, then test login." : "Select or create a journey.", "", false); reviewCertificate.setVisible(false); }
        boolean canTest = ready && !stale && !active && editingScopeEpoch == visibleEpochs.getOrDefault(editing.scope(), -1L);
        cancelButton.setVisible(active); cancelButton.setEnabled(currentEditorEntry() != null && active); testButton.setEnabled(canTest);
        testButton.setText(active ? "Login running..." : "Test login"); copyReferenceButton.setEnabled(ready && !stale);
        chooseCertificateButton.setText(certificateListing ? "Reading certificates..." : "Choose certificate..."); chooseCertificateButton.setEnabled(ready && hasChosenDevice() && !certificateListing);
        refreshCertificatePresentation(); inspectCertificateButton.setEnabled(ready && !certificateListing);
        retryCertificateButton.setVisible(certificateRetryAvailable); retryCertificateButton.setEnabled(ready && !certificateListing);
        if (reloadSelectedItem != null) reloadSelectedItem.setEnabled(ready && editingIdentity != null);
        retryButton.setVisible(recovery && !active && !reviewCertificate.isVisible()); retryButton.setEnabled(canTest);
        reviewCertificate.setEnabled(currentEditorEntry() != null);
        clearTokenButton.setEnabled(currentEditorEntry() != null && tokenAvailable);
        int eventCount = eventLog.refresh(editing, entry == null ? null : entry.definition().alias()); status.logCount(editing != null, eventCount);
        status.cacheAvailable(currentEditorEntry() != null); refreshJourneyDock();
    }

    /**
     * Uses human-readable labels without changing enum identities or native JSON spellings.
     * @param combo Native enum-backed selection.
     */
    private static void friendly(JComboBox<?> combo) {
        combo.setRenderer(new DefaultListCellRenderer() {
            /** Renders an existing choice with native theme and selection colors. */
            @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                var cell = (JLabel) super.getListCellRendererComponent(list, display(value), index, selected, focus);
                cell.setToolTipText(null);
                return cell;
            }
        });
    }

    /** Keeps saved display names as literal text, including names beginning with Swing's HTML prefix. */
    private void literalJourneyLabels() {
        var renderer = new DefaultListCellRenderer(); renderer.putClientProperty("html.disable", Boolean.TRUE); saved.setCellRenderer(renderer);
    }

    /**
     * Converts internal discriminator names to task language for visible native controls.
     * @param value Existing enum or choice; persisted values are unaffected.
     * @return Safe user-facing label.
     */
    private static String display(Object value) {
        if (value == null) return "";
        return switch (value.toString()) {
            case "COMBINED" -> "JSON response and cookies"; case "JSON_PATH" -> "JSON response"; case "COOKIE" -> "Cookie"; case "BEARER" -> "Authorization: Bearer";
            case "STATUS_CODE" -> "HTTP status"; case "REGEX" -> "Response text pattern"; case "BOTH" -> "HTTP status or response text";
            case "BURP_SCOPE" -> "Burp target scope"; case "ALL_REQUESTS" -> "All requests"; case "SINGLE_URL" -> "URL prefix";
            case "INDEX" -> "Slot index"; case "ID" -> "Slot ID"; case "PROJECT" -> "This Burp project"; case "LIBRARY" -> "User library";
            case "IDLE" -> "Not started"; case "QUEUED" -> "Queued"; case "RUNNING" -> "Authenticating"; case "BACKOFF" -> "Waiting to retry";
            case "READY" -> "Ready"; case "FAILED" -> "Stopped"; case "COOLDOWN" -> "Automatic retries paused"; case "PAUSED" -> "Automatic recovery paused"; case "CLOSED" -> "Closed";
            default -> value.toString();
        };
    }

    /** Marks local editor changes without validating unfinished fields; it never performs file/native work on the EDT. */
    private void edited() {
        if (!suppress && !closed) { pendingPinFocus = null; clearCertificateForChangedDevice(); editorEpoch++; editVersion++; dirty = true; if (!savePaused && journeyDebounce != null) journeyDebounce.restart(); }
        refreshModes(); refreshJourneyUi();
    }
    /** A failed listing or a placeholder fingerprint is never a selected certificate. */
    private boolean hasSelectedCertificate() { return selectedCertificateSha256.matches("[0-9a-f]{64}") && !selectedCertificateSha256.equals("0".repeat(64)); }
    /** @return Whether this editor has actually read the selected certificate and still has its PIN/device context. */
    private boolean canInspectCertificate() {
        return pinAvailable && loadedCertificate != null && hasChosenDevice() && hasSelectedCertificate()
                && loadedCertificate.sha256().equals(selectedCertificateSha256) && java.util.Objects.equals(selectedCertificateDevice, certificateDevice());
    }
    /** Shows certificate UI only while this editor has an actual loaded selection. */
    private void refreshCertificatePresentation() {
        boolean loaded = canInspectCertificate(); inspectCertificateButton.setVisible(loaded); certificateDetails.setVisible(loaded);
        if (certificateDetails.getClientProperty("rowLabel") instanceof JLabel label) label.setVisible(loaded);
        String summary = loaded ? CertificatePresentation.summary(loadedCertificate) : "";
        if (!certificateDetails.getText().equals(summary)) certificateDetails.setText(summary);
    }
    private CertificateDevice certificateDevice() { return new CertificateDevice(fields.get("module").getText().trim(), slotKind, slotValue.trim()); }
    /** A certificate belongs to its selected middleware/slot; a changed device needs a new choice. */
    private void clearCertificateForChangedDevice() {
        if (displayedDevice != null && !displayedDevice.equals(certificateDevice())) {
            displayedDevice = null;
        }
        if (selectedCertificateDevice != null && !selectedCertificateDevice.equals(certificateDevice())) {
            selectedCertificateSha256 = ""; selectedCertificateDevice = null; loadedCertificate = null; certificateRetryAvailable = false;
            certificateDetails.setText("");
        }
    }
    /** Clears obsolete device-action guidance after its inputs change, without clearing a native PIN latch. */
    private void clearCertificateFeedback() {
        InlineValidation.clear(chooseCertificateButton);
        if (fields.get("module") != null) InlineValidation.clear(fields.get("module"));
        InlineValidation.clear(pin);
    }
    /** Starts an explicit action with its own result and recovery guidance. */
    private void beginJourneyAction() { editorEpoch++; status.clear(); }
    /**
     * Returns one immutable EDT snapshot with independent password buffers.
     *
     * @return One immutable EDT snapshot with independent password buffers.
     */
    private Draft capture() {
        Map<String, String> text = new LinkedHashMap<>(); fields.forEach((name, field) -> text.put(name, field.getText()));
        text.put("slot", slotValue);
        text.put("alias", draftAlias);
        Map<String, Boolean> flags = new LinkedHashMap<>(); checks.forEach((name, box) -> flags.put(name, box.isSelected()));
        return new Draft(editing, editingScopeEpoch, editorEpoch, editVersion, Map.copyOf(text), Map.copyOf(flags),
                slotKind, selectedCertificateSha256, steps.snapshot(), credentials.snapshot(),
                checks.get("mtls").isSelected() && pinAvailable ? pin.getPassword() : null);
    }

    /** Flushes pending edits immediately; Ctrl+S also retries a stopped save. */
    private void save(boolean test) { save(test, null); }
    /** Queues navigation or execution only after the latest version has been committed. */
    private void save(boolean test, Runnable afterSave) {
        if (!readyEditor()) return;
        journeyDebounce.stop(); journeyRetry.stop(); savePaused = false; saveRetries = 0;
        if (afterSave != null || test) {
            afterSaveOwner = editing;
            afterJourneySave = () -> { if (afterSave != null) afterSave.run(); if (test) authenticate(false); };
        }
        attemptSave();
    }
    /** Captures only when a writer is available, so edits replace pending work rather than queueing stale snapshots. */
    private void attemptSave() {
        if (closed || !initialized || editing == null || editorLoading || savePaused) return;
        if (journeySaveInFlight) { saveRequested = true; return; }
        if (!dirty && editingIdentity != null) { afterSave(); return; }
        journeyDebounce.stop(); journeySaveInFlight = true; saveRequested = false;
        Draft draft = capture();
        var job = new Job(draft, () -> {
            try {
                checkEpoch(draft.key().scope(), draft.scopeEpoch());
                JourneyDefinition changed = savedDefinition(draft);
                var current = registry.document(draft.key().scope()); boolean created = current.journeys().stream().noneMatch(j -> j.id().equals(changed.id()));
                var journeys = new ArrayList<>(current.journeys()); journeys.removeIf(j -> j.id().equals(changed.id())); journeys.add(changed);
                try (var prepared = registry.prepareEdit(draft.key().scope(), journeys, current.controls());
                     var values = new SecretStore.Values(changed.mtls() == null ? null : draft.pin(), draft.steps().secrets)) {
                    Map<UUID, SecretStore.Values> all = new LinkedHashMap<>(); prepared.secrets().forEach((id, secret) -> all.put(id, id.equals(changed.id()) ? values.copy() : secret.copy()));
                    try (var edited = new ConfigManager.NativeDocument(prepared.kind(), prepared.revision(), prepared.journeys(), prepared.retiredAliases(), prepared.controls(), all)) { persist(draft.key().scope(), edited); }
                }
                var committed = registry.snapshot().entries().get(draft.key());
                coordinator.events().append(draft.key(), Instant.now(), JourneyEventLog.Level.INFO, created ? "Journey created." : "Changes saved.");
                refreshChoices(); ui(() -> saved(draft, committed));
            } catch (Exception | LinkageError error) { ui(() -> saveFailed(draft, error)); }
        });
        try { io.execute(job); }
        catch (RuntimeException error) { job.discard(); saveFailed(draft, error); }
    }
    /** Updates saved ownership even when a newer local edit still needs another write. */
    private void saved(Draft draft, JourneyRegistry.Entry committed) {
        journeySaveInFlight = false; saveRetries = 0;
        if (draft.key().equals(editing) && draft.scopeEpoch() == editingScopeEpoch && committed != null) {
            editingIdentity = committed.identity();
            if (draft.editVersion() == editVersion) dirty = false;
        }
        refreshJourneyUi(); boolean flush = saveRequested || afterJourneySave != null; saveRequested = false;
        if (dirty && flush) attemptSave(); else if (!dirty) afterSave();
    }
    /** Runs only the continuation belonging to the editor whose latest changes are durable. */
    private void afterSave() {
        if (afterJourneySave == null || dirty || journeySaveInFlight) return;
        var nextAction = afterJourneySave; var owner = afterSaveOwner; afterJourneySave = null; afterSaveOwner = null;
        if (owner != null && owner.equals(editing)) nextAction.run();
    }
    /** Logs storage failures without adding save feedback or field-validation errors to the UI. */
    private void saveFailed(Draft draft, Throwable error) {
        journeySaveInFlight = false; saveRequested = false;
        String reason = error.getMessage() == null ? "" : error.getMessage();
        boolean conflict = reason.startsWith("Storage changed") || error instanceof ConfigManager.NativeFormatException && reason.startsWith("revision:")
                || error instanceof UserLibraryStore.LibraryException && reason.contains("changed since this edit");
        boolean temporary = error instanceof java.util.concurrent.RejectedExecutionException || error instanceof java.io.IOException && !(error instanceof java.nio.file.AccessDeniedException)
                && (!(error instanceof UserLibraryStore.LibraryException) || reason.contains("edit lock is busy"));
        if (temporary && saveRetries < 2 && draft.key().equals(editing)) {
            saveRetries++;
            coordinator.events().append(draft.key(), Instant.now(), JourneyEventLog.Level.WARNING, "Changes could not be saved temporarily. Local edits are retained; an automatic retry is pending.");
            journeyRetry.setInitialDelay(1000 * saveRetries); journeyRetry.restart();
        } else {
            savePaused = true; afterJourneySave = null; afterSaveOwner = null; journeyDebounce.stop(); journeyRetry.stop();
            String recovery = conflict ? "Storage changed outside this editor. Reload selected to use the saved version; local edits remain here until you reload."
                    : "Check storage access, then press Ctrl+S to retry. Local edits are retained.";
            coordinator.events().append(draft.key(), Instant.now(), JourneyEventLog.Level.ERROR, "Automatic saving stopped. " + recovery);
        }
        refreshJourneyUi();
    }

    /**
     * Builds and validates a native definition off the EDT without putting secret values in JSON.
     * @param d Captured immutable editor data; its caller retains ownership of password buffers.
     * @return Valid native definition with canonical wire discriminators and stable step identities.
     * @throws ConfigManager.NativeFormatException If any native field/relationship is invalid.
     * @throws IllegalArgumentException If a numeric editor value cannot be represented exactly.
     */
    private static JourneyDefinition definition(Draft d) {
        return editorDraft(d).compile(d.key().journeyId());
    }

    /** Captures nonsecret settings separately from PIN and secure-input buffers. */
    private static JourneyDraft editorDraft(Draft d) {
        return JourneyDraft.capture(d.text(), d.flags(), d.slotKind(), d.certificateSha256(), d.steps().inputs, d.credentials());
    }
    /** Saves unfinished input literally; field validation is presented only by execution actions. */
    private static JourneyDefinition savedDefinition(Draft d) {
        try { return definition(d); }
        catch (IllegalArgumentException ex) {
            var raw = editorDraft(d); String name = d.text().get("name");
            String label = name.isBlank() ? "Untitled journey" : name.substring(0, name.offsetByCodePoints(0, Math.min(128, name.codePointCount(0, name.length()))));
            String alias = d.text().get("alias"); if (alias.isBlank()) alias = "journey-" + d.key().journeyId();
            return raw.definition(d.key().journeyId(), label, alias, d.flags().get("remember"));
        }
    }

    /**
     * Persists before publishing; current session-only buffers survive the writer's redacted disk representation.
     * @param scope Explicit destination; there is no cross-scope winner or legacy fallback.
     * @param edited Whole validated scope preview with owned secret copies.
     */
    private void persist(JourneyDefinition.Scope scope, ConfigManager.NativeDocument edited) throws Exception {
        if (closed) return;
        if (scope == JourneyDefinition.Scope.PROJECT) {
            try (var committed = projects.saveNativeProject(edited, projectRevision)) { projectRevision = committed.revision(); if (!closed) { registry.replaceLoaded(scope, committed); coordinator.updateControls(committed.controls()); applied.set(committed.controls()); } }
        } else try (var committed = library.save(edited, libraryVersion)) { libraryVersion = committed.version(); if (!closed) registry.replaceLoaded(scope, committed.document()); }
        if (!closed) coordinator.configurationChanged();
    }

    /** Reloads strict native stores off the EDT; malformed files stay preserved and unavailable for authentication. */
    private void reload() {
        try {
            var loaded = projects.loadNativeProject(); projectRevision = loaded.map(ConfigManager.NativeDocument::revision).orElse(null);
            try (var document = loaded.orElseGet(() -> ConfigManager.NativeDocument.empty(ConfigManager.DocumentKind.PROJECT))) {
                registry.replaceLoaded(JourneyDefinition.Scope.PROJECT, document); applied.set(document.controls()); coordinator.updateControls(document.controls()); storageErrors.remove(JourneyDefinition.Scope.PROJECT); bump(JourneyDefinition.Scope.PROJECT);
            }
        } catch (Exception ex) { storageFailed(JourneyDefinition.Scope.PROJECT, ex); }
        try (var loaded = library.load()) { libraryVersion = loaded.version(); registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, loaded.document()); storageErrors.remove(JourneyDefinition.Scope.LIBRARY); bump(JourneyDefinition.Scope.LIBRARY); }
        catch (Exception ex) { storageFailed(JourneyDefinition.Scope.LIBRARY, ex); }
        if (closed) return; coordinator.configurationChanged(); refreshChoices(); String summary = storageErrors.isEmpty() ? "Native storage loaded. Select a journey or create one; no authentication starts on load." : String.join("\n", storageErrors.values());
        ui(() -> { applyControls(applied.get()); initialized = true; refreshJourneyUi(); status.setText(summary); });
    }
    /**
     * Publishes a genuinely external library revision and invalidates older editor drafts without applying own-write echoes.
     *
     * @param loaded Watcher-owned event, closed by its queued Job after publication.
     */
    private void libraryChanged(UserLibraryStore.Loaded loaded) {
        if (java.util.Objects.equals(loaded.version(), libraryVersion) && !registry.snapshot().unavailableScopes().contains(JourneyDefinition.Scope.LIBRARY)) return;
        if (closed) return; libraryVersion = loaded.version(); registry.replaceLoaded(JourneyDefinition.Scope.LIBRARY, loaded.document()); storageErrors.remove(JourneyDefinition.Scope.LIBRARY); bump(JourneyDefinition.Scope.LIBRARY); coordinator.configurationChanged(); refreshChoices(); ui(() -> status.setText("The user library changed on disk. Reload the selected journey before saving its older draft."));
    }
    /**
     * Preserves stored data, disables its scope and keeps the observed storage failure visible.
     *
     * @param scope Failed native scope.
     * @param error Preserved-file recovery issue.
     */
    private void storageFailed(JourneyDefinition.Scope scope, Exception error) { if (closed) return; registry.disableScope(scope); bump(scope); coordinator.configurationChanged(); storageErrors.put(scope, (scope == JourneyDefinition.Scope.PROJECT ? "Project" : "User") + " journey storage is unavailable. " + (error instanceof ConfigManager.NativeFormatException || error instanceof UserLibraryStore.LibraryException ? error.getMessage() : "The stored journeys could not be read.")); report(error); }
    /**
     * Advances the scope's external-load epoch so old visible drafts cannot overwrite a newer disk state.
     *
     * @param scope Scope whose external load invalidates earlier editor drafts.
     */
    private void bump(JourneyDefinition.Scope scope) { scopeEpochs.put(scope, scopeEpochs.get(scope) + 1); visibleEpochs = Map.copyOf(scopeEpochs); }
    /**
     * Rejects an editor based on an older external publication before any persistence mutation begins.
     *
     * @param scope Explicit edited destination.
     * @param expected Captured external-load generation.
     */
    private void checkEpoch(JourneyDefinition.Scope scope, long expected) { if (scopeEpochs.get(scope) != expected) throw new IllegalStateException("Storage changed after this draft opened. Reload the journey and reapply the edit."); }

    /** Refreshes only saved selection labels; background completion never overwrites edited fields. */
    private void refreshChoices() {
        var snapshot = registry.snapshot(); List<Choice> choices = snapshot.entries().values().stream().sorted(java.util.Comparator.comparing(e -> e.definition().canonicalAlias()))
                .map(e -> new Choice(e.identity().key(), e.definition().displayName())).toList();
        ui(() -> {
            suppress = true;
            journeySteps.keySet().removeIf(key -> !key.equals(editing) && !snapshot.entries().containsKey(key));
            lastJourneyByScope.values().removeIf(key -> !key.equals(editing) && !snapshot.entries().containsKey(key));
            var previousSelection = saved.getSelectedValuesList().stream().map(Choice::key).toList();
            savedModel.clear();
            choices.forEach(c -> { if (c.key().scope() == destination.getSelectedItem()) savedModel.addElement(c); });
            for (int i = 0; i < savedModel.size(); i++) if (previousSelection.contains(savedModel.get(i).key())) saved.addSelectionInterval(i, i);
            if (saved.isSelectionEmpty()) for (int i = 0; i < savedModel.size(); i++) if (savedModel.get(i).key().equals(editing)) { saved.setSelectedIndex(i); break; }
            automaticRules.setJourneys(snapshot.entries().values().stream().sorted(java.util.Comparator.comparing(e -> e.definition().canonicalAlias()))
                    .map(e -> new AutomaticRulesPanel.Option(new Config.JourneySelection(e.identity().scope(), e.identity().journeyId()), e.definition().displayName())).toList()); suppress = false; refreshJourneyUi();
        });
    }
    /**
     * Loads one saved selection off the EDT and prevents editing the previous journey while its replacement is pending.
     *
     * @param key Saved scoped journey whose current definition/session values should be opened.
     */
    private void open(SecretStore.Key key) {
        rememberJourneyStep();
        journeyDebounce.stop(); journeyRetry.stop(); savePaused = false; saveRetries = 0; editVersion++;
        long selection = ++selectionEpoch; editorEpoch++; editing = key; status.context(key); restoreSavedSelection(); editorLoading = true; editorCards.show(editorSurface, "editor"); enableTree(journeyEditor, false);
        enqueue(io, null, () -> { var entry = registry.snapshot().entries().get(key);
            if (entry == null) { SwingUtilities.invokeLater(() -> { if (!closed && selectionEpoch == selection) { editorLoading = false; editing = null; dirty = false; editorCards.show(editorSurface, "empty"); enableTree(journeyEditor, true); status.setText("This journey is no longer saved. Select an existing journey or create a new one."); } }); return; }
            long expected = scopeEpochs.get(key.scope()); var values = secrets.snapshot(key);
            SwingUtilities.invokeLater(() -> {
                try (values) {
                    if (closed || selectionEpoch != selection) return;
                    boolean sidebarFocus = saved.isFocusOwner();
                    editorLoading = false; enableTree(journeyEditor, true); editorEpoch++; editingScopeEpoch = expected; editingIdentity = entry.identity(); populate(entry.definition(), values); restoreJourneyStep(key);
                    if (sidebarFocus) saved.requestFocusInWindow();
                    resetScrolls(wizard); status.setText("Loaded " + entry.definition().alias() + ".");
                }
            });
        });
    }
    /** Remembers the displayed step by scoped UUID; loading/population cannot assign the previous form's step to its replacement. */
    private void rememberJourneyStep() {
        if (closed || suppress || editorLoading || editing == null || saved.getSelectedIndices().length > 1 || wizard.getSelectedIndex() < 0) return;
        journeySteps.put(editing, wizard.getSelectedIndex()); lastJourneyByScope.put(editing.scope(), editing);
    }
    /** @param key Journey being restored; a removed optional page falls back to its nearest preceding available step. */
    private void restoreJourneyStep(SecretStore.Key key) {
        int step = Math.min(journeySteps.getOrDefault(key, 0), wizard.getTabCount() - 1);
        while (step > 0 && !wizard.isEnabledAt(step)) step--;
        wizard.setSelectedIndex(step); rememberJourneyStep();
    }
    /** Saves the current edits and immediately creates a persisted journey in the selected collection. */
    private void newJourney() {
        leaveDraft(this::createJourney);
    }
    /**
     * Changes the visible journey collection only after the previous draft is saved or discarded.
     * @param index Requested Project/User tab index.
     */
    private void selectScope(int index) {
        int previous = destination.getSelectedItem() == JourneyDefinition.Scope.PROJECT ? 0 : 1;
        suppress = true; try { journeyScopes.setSelectedIndex(previous); } finally { suppress = false; }
        leaveDraft(() -> {
            rememberJourneyStep();
            suppress = true;
            try { destination.setSelectedItem(index == 0 ? JourneyDefinition.Scope.PROJECT : JourneyDefinition.Scope.LIBRARY); journeyScopes.setSelectedIndex(index); saved.clearSelection(); }
            finally { suppress = false; }
            suppress = true;
            try { editing = null; editingIdentity = null; editorEpoch++; selectionEpoch++; editorLoading = false; pin.setText(""); steps.clear(); dirty = false; } finally { suppress = false; } editorCards.show(editorSurface, "empty"); refreshChoices(); refreshJourneyUi();
            var previousJourney = lastJourneyByScope.get(destination.getSelectedItem());
            var snapshot = registry.snapshot();
            if (previousJourney != null && snapshot.entries().containsKey(previousJourney) && !snapshot.unavailableScopes().contains(previousJourney.scope())) open(previousJourney);
        });
    }
    /** Creates and persists a new journey without requiring a runnable configuration. */
    private void createJourney() {
        if (!initialized) return; var scope = (JourneyDefinition.Scope) destination.getSelectedItem();
        if (registry.snapshot().unavailableScopes().contains(scope)) { message("Resolve the storage error for the selected Project or User collection before creating a journey."); return; }
        rememberJourneyStep();
        String newName = "New journey";
        var usedAliases = registry.snapshot().entries().values().stream().map(e -> e.definition().canonicalAlias()).collect(java.util.stream.Collectors.toSet());
        for (int suffix = 2; usedAliases.contains(JourneyNames.alias(newName)); suffix++) newName = "New journey " + suffix;
        UUID id = UUID.randomUUID(); selectionEpoch++; editorLoading = false; enableTree(journeyEditor, true); editing = new SecretStore.Key(scope, id); status.context(editing); editingIdentity = null; editingScopeEpoch = visibleEpochs.getOrDefault(scope, -1L); editorEpoch++; saved.clearSelection();
        var journey = new JourneyDefinition(id, newName, JourneyNames.alias(newName), URI.create("https://login.example/login"), false, List.of(),
                new JourneyDefinition.Browser(false, null, 30_000, 3000), new JourneyDefinition.JsonExtraction(URI.create(""), "", ""),
                JourneyDefinition.Injection.perToken(List.of(new JourneyDefinition.TokenInjection(null, JourneyDefinition.InjectionType.BEARER, null))), new JourneyDefinition.Cache(1800, 10), null);
        try (var values = SecretStore.Values.empty()) { populate(journey, values); }
        suppress = true; try { fields.get("url").setText(""); } finally { suppress = false; }
        dirty = true; editorCards.show(editorSurface, "editor"); wizard.setSelectedIndex(0); rememberJourneyStep(); resetScrolls(wizard); refreshJourneyUi();
        save(false);
    }
    /**
     * Starts a newly opened journey at the top of each form without inheriting the previous owner's position.
     * @param component Editor subtree, including the nested step and result scrolling surfaces.
     */
    private static void resetScrolls(Component component) {
        if (component instanceof JScrollPane pane) pane.getViewport().setViewPosition(new Point());
        if (component instanceof Container container) for (var child : container.getComponents()) resetScrolls(child);
    }
    /**
     * Populates only one selected journey on the EDT, taking temporary copies of session values without logging them.
     *
     * @param j Immutable saved/new definition.
     * @param values Borrowed independent session values.
     */
    private void populate(JourneyDefinition j, SecretStore.Values values) {
        suppress = true;
        pendingPinFocus = null;
        loadedCertificate = null;
        renameNotice.setVisible(false);
        certificateRetryAvailable = false; InlineValidation.clear(chooseCertificateButton);
        displayedDevice = null;
        deviceDiscoveryVersion++; deviceDiscoveryRunning = false; devicePicker.reset();
        try {
            text("name", j.displayName()); draftAlias = j.alias(); text("url", j.authenticationUrl()); flag("headless", j.browser().headless()); flag("remember", j.rememberSecrets());
            text("navTimeout", secondsText(j.browser().navigationTimeoutMs())); text("tokenWait", secondsText(j.browser().tokenWaitTimeoutMs())); text("proxy", j.browser().proxy() == null ? "" : j.browser().proxy().url());
            credentials.setDefinition(j.extraction(), j.injection());
            text("maxAge", j.cache().maxAgeSeconds()); text("skew", j.cache().refreshSkewSeconds());
            var m = j.mtls(); flag("mtls", m != null); text("module", m == null ? "" : m.modulePath()); slotKind = m == null ? JourneyDefinition.SlotKind.INDEX : m.slot().kind(); slotValue = Long.toString(m == null ? 0 : m.slot().value()); selectedCertificateSha256 = m == null ? "" : m.certificateSha256();
            URI loginOrigin = ConfigManager.certificateLoginOrigin(j.authenticationUrl());
            text("origins", m == null ? "" : String.join(", ", m.origins().stream().filter(origin -> !origin.equals(loginOrigin)).map(URI::toString).toList())); text("ca", m == null ? "" : m.trustedCaBundlePath());
            char[] code = values.pin(); try { pin.setText(code == null ? "" : new String(code)); pinAvailable = code != null; } finally { if (code != null) Arrays.fill(code, '\0'); }
            steps.setSteps(j.steps(), values);
            if (j.draft() != null) {
                var raw = j.draft(); raw.text().forEach((key, value) -> { if (fields.containsKey(key)) text(key, value); });
                draftAlias = raw.text().get("alias"); raw.flags().forEach(this::flag);
                slotKind = raw.slotKind(); slotValue = raw.text().get("slot"); selectedCertificateSha256 = raw.certificateSha256();
                steps.setDraft(raw.steps(), values); credentials.setInputs(raw.credentials());
            }
            certificateAdvanced.setVisible(false); certificateAdvancedToggle.setSelected(false);
            selectedCertificateDevice = hasSelectedCertificate() ? certificateDevice() : null;
            certificateDetails.setText("");
            refreshModes();
        } finally { suppress = false; }
        dirty = false; savePaused = false; saveRetries = 0; refreshJourneyUi();
        scheduleDeviceDiscovery();
    }

    /**
     * Applies only the selected project-settings category while preserving the other applied category.
     * @param waitingOnly True for budgets/capacity, false for automatic-injection selection and scope.
     */
    private void saveControls(boolean waitingOnly) {
        if (!initialized) return; long captured = controlsScopeEpoch; long epoch = editorEpoch;
        Map<String, String> raw = new LinkedHashMap<>(); fields.forEach((name, field) -> raw.put(name, field.getText()));
        var selectedTools = tools.entrySet().stream().filter(e -> e.getValue().isSelected()).map(Map.Entry::getKey).toList();
        boolean enabled = checks.get("enabled").isSelected(), global = checks.get("globalUnlimited").isSelected(), per = checks.get("perUnlimited").isSelected();
        List<Config.AutomaticRule> rules;
        try { rules = waitingOnly || !enabled ? applied.get().rules() : automaticRules.snapshot(); }
        catch (IllegalArgumentException ex) { controlSaveFailed(waitingOnly, ex); return; }
        var job = new Job(null, () -> { try {
            checkEpoch(JourneyDefinition.Scope.PROJECT, captured);
            var current = applied.get();
            var cfg = waitingOnly
                    ? new Config.Controls(current.enabled(), current.rules(), current.tools(), seconds(raw, "control.request"), seconds(raw, "control.attempt"), seconds(raw, "control.cycle"), global ? null : number(raw, "control.global"), per ? null : number(raw, "control.per"))
                    : new Config.Controls(enabled, rules, selectedTools, current.requestWaitTimeoutMs(), current.attemptTimeoutMs(), current.cycleTimeoutMs(), current.maxWaitingRequestsGlobal(), current.maxWaitingRequestsPerJourney());
            if (cfg.cycleTimeoutMs() < Math.max(cfg.requestWaitTimeoutMs(), cfg.attemptTimeoutMs())) throw new IllegalArgumentException("Total login timeout must cover the request wait and login attempt timeout.");
            var doc = registry.document(JourneyDefinition.Scope.PROJECT);
            try (var edited = registry.prepareEdit(JourneyDefinition.Scope.PROJECT, doc.journeys(), cfg)) { persist(JourneyDefinition.Scope.PROJECT, edited); }
        } catch (Exception | LinkageError error) { controlSaveFailed(waitingOnly, error); } });
        try { io.execute(job); } catch (RuntimeException error) { job.discard(); controlSaveFailed(waitingOnly, error); }
    }
    /**
     * Displays validated applied project controls without saving, authenticating or inventing finite waiter caps.
     *
     * @param cfg Latest validated applied controls; population never saves or starts a login.
     */
    private void applyControls(Config.Controls cfg) {
        controlsScopeEpoch = visibleEpochs.getOrDefault(JourneyDefinition.Scope.PROJECT, -1L);
        suppress = true;
        try {
            flag("enabled", cfg.enabled()); automaticRules.setRules(cfg.rules()); text("control.request", secondsText(cfg.requestWaitTimeoutMs())); text("control.attempt", secondsText(cfg.attemptTimeoutMs())); text("control.cycle", secondsText(cfg.cycleTimeoutMs()));
            flag("globalUnlimited", cfg.maxWaitingRequestsGlobal() == null); flag("perUnlimited", cfg.maxWaitingRequestsPerJourney() == null); text("control.global", cfg.maxWaitingRequestsGlobal()); text("control.per", cfg.maxWaitingRequestsPerJourney());
            tools.forEach((tool, box) -> box.setSelected(cfg.tools().contains(tool))); refreshModes();
        } finally { suppress = false; }
    }
    /**
     * Saves new or edited drafts before testing their committed identity or retrying authentication.
     *
     * @param explicit Whether Retry explicitly acknowledges native PIN recovery.
     */
    private void authenticate(boolean explicit) {
        if (!readyEditor()) return;
        status.highlightLog(editing);
        if (dirty || editingIdentity == null) { save(false, () -> authenticate(explicit)); return; }
        if (!validateCredentialNames()) return;
        if (!canUseSavedJourney()) { status.error("The saved journey changed. Reload it before testing."); return; }
        beginJourneyAction(); var entry = currentEditorEntry(); long epoch = editorEpoch;
        enqueue(io, null, () -> { registry.snapshot().resolve(entry.identity().key()); checkCurrent(entry); test(entry, explicit, epoch); });
    }
    /** @param target Exact saved action observed by an attempt. @return Whether it still matches this unchanged editor. */
    private boolean canRevealStep(JourneyEventLog.StepTarget target) {
        var entry = currentEditorEntry(); return !dirty && entry != null && entry.identity().equals(target.journey()) && steps.containsStep(target.id());
    }
    /** @param target Exact failed action. @param guidance Optional safe inline error. */
    private void revealStep(JourneyEventLog.StepTarget target, String guidance) {
        revealStep(target, guidance, true);
    }
    /** @param target Exact failed action. @param guidance Safe inline error. @param missingSecret Whether the action's secret rather than selector needs attention. */
    private void revealStep(JourneyEventLog.StepTarget target, String guidance, boolean missingSecret) {
        if (!canRevealStep(target)) return; mainTabs.setSelectedIndex(0); wizard.setSelectedIndex(1);
        SwingUtilities.invokeLater(() -> { if (!closed && canRevealStep(target)) steps.revealStep(target.id(), guidance, missingSecret); });
    }
    /** @param guidance Observed missing-PIN problem; no PIN value is retained. */
    private void revealMissingPin(String guidance) {
        pendingPinFocus = new PendingPinFocus(editing, selectionEpoch, deviceDiscoveryVersion, guidance, pin);
        mainTabs.setSelectedIndex(0); wizard.setSelectedIndex(3); revealPendingPin();
    }
    /** Waits for device selection before showing the PIN, and discards focus requests superseded by navigation or edits. */
    private void revealPendingPin() {
        var request = pendingPinFocus; if (request == null) return;
        if (!currentPinFocus(request)) { pendingPinFocus = null; return; }
        if (!hasChosenDevice()) return;
        JComponent target = request.target(); InlineValidation.clear(devicePicker);
        InlineValidation.show(target, request.guidance()); pendingPinFocus = null;
        SwingUtilities.invokeLater(() -> {
            if (currentPinFocus(request) && target.isVisible() && target.isEnabled()) {
                target.scrollRectToVisible(new Rectangle(0, 0, target.getWidth(), target.getHeight())); target.requestFocusInWindow();
            }
        });
    }
    /** @param request Original explicit-test focus request. @return Whether its exact UI/device context is still current. */
    private boolean currentPinFocus(PendingPinFocus request) {
        return !closed && !editorLoading && request.key().equals(editing) && request.selection() == selectionEpoch
                && request.deviceVersion() == deviceDiscoveryVersion && mainTabs.getSelectedIndex() == 0 && wizard.getSelectedIndex() == 3;
    }
    /**
     * Joins bounded shared acquisition and applies its safe result only to the still-current visible editor.
     *
     * @param entry Applied generation.
     * @param explicit Explicit PIN recovery.
     * @param epoch Editor generation allowed to receive a completion message.
     */
    private void test(JourneyRegistry.Entry entry, boolean explicit, long epoch) {
        if (entry.definition().draft() != null) {
            try { entry.definition().draft().compile(entry.definition().id()); }
            catch (IllegalArgumentException error) {
                String guidance = validationMessage(error.getMessage(), entry.definition().draft().credentials());
                JourneyEventLog.StepTarget target = null;
                var match = java.util.regex.Pattern.compile("^steps\\[(\\d+)]").matcher(error.getMessage());
                if (match.find()) {
                    int index = Integer.parseInt(match.group(1));
                    if (index < entry.definition().steps().size()) target = new JourneyEventLog.StepTarget(entry.identity(), entry.definition().steps().get(index).id());
                }
                coordinator.events().append(entry.identity().key(), Instant.now(), JourneyEventLog.Level.ERROR, guidance, target);
                ui(epoch, () -> { status.highlightLog(entry.identity().key()); focusInvalidField(error.getMessage()); status.error(guidance); }); return;
            }
        }
        var ticket = coordinator.test(entry, explicit); ui(() -> {
            if (!registry.snapshot().isCurrent(entry.identity())) return;
            refreshJourneyUi();
        });
        ticket.future().whenComplete((result, error) -> {
            String message;
            if (error == null) message = "Credentials captured.";
            else { var safe = error instanceof AuthenticationFailure f ? f : error.getCause() instanceof AuthenticationFailure f ? f : null; if (safe != null) diagnostics.state(entry.definition().alias(), safe); message = safe == null ? "Login failed." : safe.getMessage(); }
            String safeResult = message; ui(() -> {
                if (!registry.snapshot().isCurrent(entry.identity())) return;
                status.highlightLog(entry.identity().key());
                if (editorEpoch == epoch && entry.identity().key().equals(editing)) {
                    if (error == null) status.clear(); else {
                        status.error(safeResult);
                        var failure = error instanceof AuthenticationFailure f ? f : error.getCause() instanceof AuthenticationFailure f ? f : null;
                        revealTestFailure(entry, failure);
                    }
                }
                refreshJourneyUi();
            });
        });
    }
    /** @param entry Exact tested generation. @param failure Safe observed outcome, with optional input identity. */
    private void revealTestFailure(JourneyRegistry.Entry entry, AuthenticationFailure failure) {
        if (failure == null || Set.of(AuthenticationFailure.Cause.CANCELLED, AuthenticationFailure.Cause.STALE, AuthenticationFailure.Cause.CLOSED).contains(failure.reason())) return;
        if (failure.input() != null) {
            var target = failure.input();
            if (target.input() == AuthenticationFailure.Input.MTLS_PIN) { revealMissingPin(failure.getMessage()); return; }
            String path = switch (target.input()) {
                case LOGIN_URL -> "authenticationUrl"; case PROXY_URL -> "browser.proxy";
                case MIDDLEWARE -> "mtls.modulePath"; case SECURITY_DEVICE -> "mtls.slot";
                case CERTIFICATE -> "mtls.certificateSha256"; case TRUSTED_CA -> "mtls.trustedCaBundlePath";
                case JSON_PATH -> "extraction.jsonPath"; case COOKIE_FILTERS -> "extraction.domain";
                case CAPTURE_SOURCE -> "extraction.type"; case MTLS_PIN -> throw new IllegalStateException();
            };
            if (path.startsWith("extraction") && target.credential() != null) path = "extraction.tokens[" + target.credential() + "].selector" + path.substring("extraction".length());
            mainTabs.setSelectedIndex(0); showInvalidField(path + ":", failure.getMessage(), true); return;
        }
        if (failure.step() != null) revealStep(new JourneyEventLog.StepTarget(entry.identity(), failure.step().id()), failure.problem(), failure.reason() == AuthenticationFailure.Cause.MISSING_SECRET);
        else if (failure.reason() == AuthenticationFailure.Cause.MISSING_SECRET && entry.definition().mtls() != null && !pinAvailable) revealMissingPin(failure.getMessage());
    }
    /**
     * Enqueues a selected shared Cancel or Invalidate operation without doing native work on the EDT.
     *
     * @param cancel True for shared Cancel, false for manual token/cycle invalidation.
     */
    private void selectedAction(boolean cancel) {
        if (!readyEditor()) return; var entry = currentEditorEntry();
        if (entry == null) { status.setText("Reload and review the saved journey before changing its authentication state."); return; }
        beginJourneyAction(); long epoch = editorEpoch;
        enqueue(io, null, () -> {
            checkCurrent(entry); boolean cancelled = cancel && coordinator.cancelAuthentication(entry.identity());
            if (!cancel) coordinator.invalidate(entry.identity());
            var resulting = coordinator.status(entry.identity()); boolean retained = resulting.usableToken();
            ui(epoch, () -> { status.setText(!cancel ? "Cached credentials cleared." : cancelled
                    ? resulting.phase() == AuthenticationCoordinator.Phase.PAUSED ? "Recovery cancelled. Automatic recovery is paused until Test login succeeds." : "Login cancelled. Automatic retries paused for 60 seconds." + (retained ? " The usable token was retained." : " No usable token is available.")
                    : "No login is running for this journey."); refreshJourneyUi(); });
        });
    }

    /**
     * Lists public certificate metadata on a separate bounded worker; only an explicit retry requests PIN recovery.
     *
     * @param recovery Explicit retry listing is the only listing action that clears an established native PIN latch.
     */
    private void listCertificates(boolean recovery) {
        listCertificates(recovery, false);
    }
    /** Device discovery is independent of certificate/PIN actions and ignores results for an obsolete middleware or journey. */
    private void scheduleDeviceDiscovery() {
        pendingPinFocus = null;
        deviceDiscoveryVersion++; deviceDiscoveryRunning = false; displayedDevice = null; devicePicker.reset();
        if (deviceDebounce != null) {
            deviceDebounce.stop();
            if (!closed && checks.get("mtls").isSelected() && !fields.get("module").getText().isBlank()) deviceDebounce.restart();
        }
        refreshModes(); refreshJourneyUi();
    }

    /** @param explicit Whether the operator explicitly requested a refresh, rather than finishing a middleware edit. */
    private void discoverDevices(boolean explicit) {
        if (!readyEditor() || !checks.get("mtls").isSelected() || fields.get("module").getText().isBlank() || deviceDiscoveryRunning) return;
        if (deviceDebounce != null) deviceDebounce.stop();
        long version = deviceDiscoveryVersion; Draft draft = capture();
        deviceDiscoveryRunning = true; displayedDevice = null; devicePicker.loading(); refreshModes(); refreshJourneyUi();
        boolean accepted = enqueue(nativeActions, draft, () -> {
            try {
                var tokens = identities.discoverTokens(draft.text().get("module").trim(), System.nanoTime() + TimeUnit.SECONDS.toNanos(60), () -> closed || version != deviceDiscoveryVersion);
                ui(() -> {
                    if (closed || editorLoading || version != deviceDiscoveryVersion || !draft.key().equals(editing)) return;
                    deviceDiscoveryRunning = false;
                    Long previous = null;
                    try { if (slotKind == JourneyDefinition.SlotKind.ID) previous = Long.valueOf(slotValue.trim()); } catch (NumberFormatException ignored) { /* choose a detected device instead of using obsolete draft metadata */ }
                    deviceSelected(devicePicker.devices(tokens, previous));
                });
            } catch (AuthenticationFailure error) {
                ui(() -> {
                    if (closed || editorLoading || version != deviceDiscoveryVersion || !draft.key().equals(editing)) return;
                    deviceDiscoveryRunning = false; displayedDevice = null; devicePicker.unavailable(error.getMessage()); refreshModes(); refreshJourneyUi();
                });
                if (explicit) throw error;
            }
        });
        if (!accepted) { deviceDiscoveryRunning = false; devicePicker.unavailable("Device discovery could not start. Refresh to try again."); refreshModes(); refreshJourneyUi(); }
    }

    /** @param token Explicitly chosen or sole automatically detected token; null means a choice is still required. */
    private void deviceSelected(Pkcs11IdentityManager.TokenInfo token) {
        if (closed) return;
        if (token == null) { displayedDevice = null; refreshModes(); refreshJourneyUi(); return; }
        var requestedPinFocus = pendingPinFocus;
        CertificateDevice previous = certificateDevice();
        slotKind = JourneyDefinition.SlotKind.ID; slotValue = Long.toString(token.slotId());
        if (!previous.equals(certificateDevice())) {
            suppress = true;
            try { pin.setText(""); pinAvailable = false; } finally { suppress = false; }
            clearCertificateFeedback(); edited();
        }
        displayedDevice = certificateDevice(); refreshModes(); refreshJourneyUi();
        pendingPinFocus = requestedPinFocus; revealPendingPin();
    }

    /** @return Whether middleware discovery established the currently selected named device. */
    private boolean hasChosenDevice() { return devicePicker.selected() != null && displayedDevice != null && displayedDevice.equals(certificateDevice()); }

    /** @param recovery Explicit PIN-latch recovery. @param inspectOnly Inspect the existing selection without replacing it. */
    private void listCertificates(boolean recovery, boolean inspectOnly) {
        if (!hasChosenDevice() || inspectOnly && !canInspectCertificate()) return;
        readCertificates(recovery, inspectOnly);
    }

    /** Lists certificates only on the one discovered device selected by the operator. */
    private void readCertificates(boolean recovery, boolean inspectOnly) {
        if (!readyEditor() || certificateListing) return; beginJourneyAction(); Draft draft = capture();
        certificateListing = true; InlineValidation.clear(chooseCertificateButton); refreshJourneyUi();
        boolean accepted = enqueue(nativeActions, draft, () -> {
            try {
            String module = draft.text().get("module").trim(); long slot = longNumber(draft.text().get("slot"), "slot");
            if (!Path.of(module).isAbsolute() || slot < 0 || draft.slotKind() == JourneyDefinition.SlotKind.INDEX && slot > Integer.MAX_VALUE)
                throw new AuthenticationFailure(AuthenticationFailure.Phase.PROVIDER, AuthenticationFailure.Cause.CONFIGURATION,
                        "The saved security-device selection is invalid.", "Use Choose certificate to detect and select the device again.");
            var definition = new JourneyDefinition.Mtls(module, new JourneyDefinition.Slot(draft.slotKind(), slot), "0".repeat(64), List.of(URI.create("https://localhost")), null);
            var certs = identities.listCertificates(definition, draft.pin(), recovery, System.nanoTime() + TimeUnit.SECONDS.toNanos(60), () -> closed);
            ui(draft.editorEpoch(), () -> {
                certificateRetryAvailable = false;
                if (certs.isEmpty()) { loadedCertificate = null; InlineValidation.show(chooseCertificateButton, "No client certificates with an accessible private key were found on this device."); return; }
                if (inspectOnly) {
                    var saved = certs.stream().filter(c -> c.sha256().equals(draft.certificateSha256())).findFirst();
                    if (saved.isEmpty()) { loadedCertificate = null; InlineValidation.show(chooseCertificateButton, "The saved certificate was not found on this device."); return; }
                    var certificate = saved.get(); loadedCertificate = certificate; String summary = CertificatePresentation.summary(certificate);
                    var inspection = new JPanel(new BorderLayout(0, 6)); inspection.add(note(summary)); inspection.add(disclosure("Technical details", note(CertificatePresentation.technical(certificate))), BorderLayout.SOUTH);
                    dialogs.inspect(parent(), inspection); return;
                }
                var model = new DefaultTableModel(new String[]{"Certificate", "Organization", "Email", "Issued by", "Valid from", "Valid until"}, 0) { /** Certificate metadata is display-only; selection retains its internal fingerprint. */ @Override public boolean isCellEditable(int row, int column) { return false; } };
                certs.forEach(c -> model.addRow(new Object[]{CertificatePresentation.name(c.subject()), CertificatePresentation.attribute(c.subject(), "O"), CertificatePresentation.attribute(c.subject(), "EMAILADDRESS"), CertificatePresentation.name(c.issuer()), CertificatePresentation.DATE.format(c.notBefore()), CertificatePresentation.DATE.format(c.notAfter())}));
                var table = new JTable(model); table.putClientProperty("certificateChoices", List.copyOf(certs)); table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                var renderer = new javax.swing.table.DefaultTableCellRenderer(); renderer.putClientProperty("html.disable", true); table.setDefaultRenderer(Object.class, renderer);
                if (!certs.isEmpty()) table.setRowSelectionInterval(0, 0);
                var pane = certificatePreview(table); var technical = note("");
                Runnable describe = () -> { int row = table.getSelectedRow(); technical.setText(row < 0 ? "No certificate selected." : CertificatePresentation.technical(certs.get(table.convertRowIndexToModel(row)))); };
                table.getSelectionModel().addListSelectionListener(e -> describe.run()); describe.run();
                var lower = new JPanel(new BorderLayout(0, 5)); var details = pane.getComponent(1); pane.remove(details); lower.add(details);
                lower.add(disclosure("Technical details", technical), BorderLayout.SOUTH); pane.add(lower, BorderLayout.SOUTH);
                if (dialogs.confirm(parent(), pane, "Choose the exact client certificate") && table.getSelectedRow() >= 0) {
                    var certificate = certs.get(table.convertRowIndexToModel(table.getSelectedRow())); selectedCertificateSha256 = certificate.sha256(); selectedCertificateDevice = certificateDevice(); loadedCertificate = certificate;
                    edited();
                }
            });
            } catch (AuthenticationFailure error) {
                ui(draft.editorEpoch(), () -> { loadedCertificate = null; certificateRetryAvailable = error.reason() == AuthenticationFailure.Cause.PIN_REJECTED || error.reason() == AuthenticationFailure.Cause.PIN_INDETERMINATE; InlineValidation.show(chooseCertificateButton, error.getMessage()); });
                throw error;
            } finally { ui(() -> { certificateListing = false; refreshJourneyUi(); }); }
        });
        if (!accepted) { certificateListing = false; refreshJourneyUi(); }
    }
    /**
     * Keeps complete public identity details readable when the host compresses the chooser columns.
     *
     * @param table Display-only certificate rows containing subject, issuer, serial and expiry.
     * @return Selection table and a wrapping, selectable description of its current row.
     */
    static JPanel certificatePreview(JTable table) {
        var details = note(""); details.setName("certificateChoiceDetails"); details.setRows(6);
        details.getAccessibleContext().setAccessibleName("Selected certificate details");
        Runnable describe = () -> {
            int row = table.getSelectedRow(); var text = new StringBuilder();
            if (row < 0) text.append("No certificate selected.");
            else for (int column = 0; column < table.getColumnCount(); column++) {
                if (column > 0) text.append('\n');
                text.append(table.getColumnName(column)).append(": ").append(table.getValueAt(row, column));
            }
            details.setText(text.toString()); details.setCaretPosition(0);
        };
        table.getSelectionModel().addListSelectionListener(event -> { if (!event.getValueIsAdjusting()) describe.run(); });
        describe.run();
        var panel = new JPanel(new BorderLayout(0, 8)); panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(new JScrollPane(details), BorderLayout.SOUTH); panel.setPreferredSize(new Dimension(950, 330)); return panel;
    }
    /** Captures the full intended selection before draft protection temporarily restores its editor row. */
    private void delete() {
        var keys = saved.getSelectedValuesList().stream().map(Choice::key).toList();
        if (keys.isEmpty()) { status.setText("Select one or more saved journeys to delete."); return; }
        if (keys.contains(editing)) leaveDraft(() -> deleteSaved(keys)); else deleteSaved(keys);
    }
    /** Deletes a reviewed selection in one revision-checked write; unrelated journeys and drafts survive. */
    private void deleteSaved(List<SecretStore.Key> keys) {
        var snapshot = registry.snapshot(); var scope = keys.getFirst().scope(); var entries = new ArrayList<JourneyRegistry.Entry>();
        for (var key : keys) {
            var entry = snapshot.entries().get(key);
            if (entry == null || key.scope() != scope || snapshot.unavailableScopes().contains(scope)) { status.setText("The selected journeys changed or their storage is unavailable. Review the selection again."); return; }
            entries.add(entry);
        }
        selectSavedKeys(keys); int count = entries.size(); long captured = visibleEpochs.getOrDefault(scope, -1L);
        var panel = new JPanel(new BorderLayout(6, 8));
        panel.add(note((count == 1 ? "Delete this saved journey?" : "Delete these " + count + " saved journeys?") + " Pending logins for them will be cancelled. This cannot be undone."), BorderLayout.NORTH);
        var names = new JList<>(entries.stream().map(e -> e.definition().displayName() + " (" + e.definition().alias() + ")").toArray(String[]::new));
        var renderer = new DefaultListCellRenderer(); renderer.putClientProperty("html.disable", Boolean.TRUE); names.setCellRenderer(renderer);
        var list = new JScrollPane(names); list.setPreferredSize(new Dimension(520, Math.min(240, Math.max(50, count * 24)))); panel.add(list);
        String action = count == 1 ? "Delete journey" : "Delete journeys";
        if (!dialogs.confirmAction(parent(), panel, count == 1 ? "Delete journey" : "Delete " + count + " journeys", action)) return;
        enqueue(io, null, () -> {
            checkEpoch(scope, captured);
            for (var entry : entries) {
                var current = registry.snapshot().entries().get(entry.identity().key());
                if (current == null || !current.identity().equals(entry.identity())) throw new IllegalStateException("This journey changed after it was selected. Review the selection and try again.");
            }
            var ids = keys.stream().map(SecretStore.Key::journeyId).collect(java.util.stream.Collectors.toSet()); var current = registry.document(scope);
            try (var edited = registry.prepareEdit(scope, current.journeys().stream().filter(j -> !ids.contains(j.id())).toList(), current.controls())) { persist(scope, edited); }
            refreshChoices(); ui(() -> {
                keys.forEach(journeySteps::remove); lastJourneyByScope.values().removeIf(keys::contains);
                if (keys.contains(editing)) { editing = null; editingIdentity = null; selectionEpoch++; editorLoading = false; status.context(null); dirty = false; editorEpoch++; pin.setText(""); steps.clear(); editorCards.show(editorSurface, "empty"); }
                refreshJourneyUi(); status.setText(count == 1 ? "Deleted journey. Select or create another journey." : "Deleted " + count + " journeys.");
            });
        });
    }

    /** Reads all selected files off the EDT, then reviews the exact subset before one destination write. */
    private void importJourneys() {
        if (!initialized) return; List<Path> files = dialogs.importFiles(parent()); if (files.isEmpty()) return;
        var scope = (JourneyDefinition.Scope) destination.getSelectedItem(); long expected = visibleEpochs.getOrDefault(scope, -1L);
        enqueue(io, null, () -> {
            var exports = new ArrayList<String>(); var candidates = new ArrayList<JourneyImportPanel.Item>(); long bytes = 0;
            for (Path file : files) {
                String json = readSmall(file); bytes += json.getBytes(StandardCharsets.UTF_8).length;
                if (bytes > (4 << 20)) throw new ConfigManager.NativeFormatException("Selected imports exceed 4 MiB; choose fewer files and retry.");
                int source = exports.size(); exports.add(json);
                try (var parsed = ConfigManager.parseNative(json, ConfigManager.DocumentKind.EXPORT)) {
                    for (var journey : parsed.journeys()) candidates.add(new JourneyImportPanel.Item(source, journey.id(), journey.displayName(), journey.alias(), file.getFileName().toString()));
                }
            }
            ui(() -> {
                var panel = new JourneyImportPanel(candidates, scope);
                if (dialogs.confirmAction(parent(), panel, "Import journeys into " + (scope == JourneyDefinition.Scope.PROJECT ? "Project" : "User"), "Import journeys")) {
                    var selection = panel.selection();
                    if (selection.isEmpty()) { status.setText("Select at least one journey to import."); return; }
                    enqueue(io, null, () -> { checkEpoch(scope, expected); try (var preview = JourneyTransfer.previewImport(exports, scope, registry, selection)) { persist(scope, preview); } refreshChoices(); ui(() -> status.setText("Imported " + selection.size() + (selection.size() == 1 ? " journey." : " journeys."))); });
                }
            });
        });
    }
    /** Exports the exact saved selection with independent unchecked secret inclusion. */
    private void exportJourney() {
        var entries = selectedEntries();
        if (!canExportSelection(entries)) { status.setText(entries.size() > 1 ? "Save changes to the selected journeys before exporting them." : "Save this journey before exporting it."); return; }
        var include = new JCheckBox("Include available secrets (readable; requires all configured values)");
        if (!dialogs.confirm(parent(), include, "Native export: secrets omitted by default")) return;
        Path file = dialogs.file(parent(), true); if (file == null) return; boolean secretsIncluded = include.isSelected();
        enqueue(io, null, () -> {
            for (var entry : entries) checkCurrent(entry); String json = JourneyTransfer.exportJourneys(entries, secrets, secretsIncluded);
            if (Files.exists(file)) ui(() -> { if (dialogs.confirm(parent(), "Replace the selected export file?", "Export")) enqueue(io, null, () -> writeExport(file, json, true)); });
            else writeExport(file, json, false);
        });
    }
    /**
     * Writes an explicitly chosen native export with private creation permissions and no runtime token/profile state.
     *
     * @param file Explicit user-chosen export path.
     * @param json Native export content, never logged.
     * @param replace Explicit overwrite acknowledgement.
     */
    private void writeExport(Path file, String json, boolean replace) throws Exception {
        if (!replace) Files.createFile(file, BrowserRuntimeManager.privateAttributes(file.toAbsolutePath().getParent(), false));
        Files.writeString(file, json, StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.WRITE, java.nio.file.StandardOpenOption.TRUNCATE_EXISTING); ui(() -> status.setText("Native export saved to the chosen path. Tokens, browser state and private keys were excluded."));
    }

    /** Captures the last edits on the EDT, then lets a final independent storage write finish during cleanup. */
    public void shutdown() {
        if (closed) return;
        var finalDraft = new AtomicReference<Draft>();
        Runnable clear = () -> {
            if (closed) return;
            if (initialized && editing != null && !editorLoading && (dirty || journeySaveInFlight)) finalDraft.set(capture());
            closed = true; editorEpoch++; selectionEpoch++; afterJourneySave = null; afterSaveOwner = null;
            if (journeyDebounce != null) journeyDebounce.stop(); if (journeyRetry != null) journeyRetry.stop();
            if (settingsDebounce != null) settingsDebounce.stop(); if (automaticDebounce != null) automaticDebounce.stop();
            if (deviceDebounce != null) deviceDebounce.stop(); deviceDiscoveryVersion++; pendingPinFocus = null;
            if (statusTimer != null) statusTimer.stop(); cacheView.clear(); pin.setText(""); steps.clear(); journeySteps.clear(); lastJourneyByScope.clear();
        };
        if (SwingUtilities.isEventDispatchThread()) clear.run(); else try { SwingUtilities.invokeAndWait(clear); }
        catch (Exception error) { closed = true; }
        for (Runnable task : nativeActions.shutdownNow()) if (task instanceof UiController.Job job) job.discard();
        var queued = new ArrayList<Runnable>(); io.getQueue().drainTo(queued);
        for (var task : queued) if (task instanceof UiController.Job job) job.discard();
        var closing = new ClosingSave(finalDraft.get());
        try { io.execute(closing); io.shutdown(); }
        catch (RuntimeException error) { closing.close(); io.shutdownNow(); }
    }
    /** Owns only captured settings/secrets; final persistence never accesses closed runtime services. */
    private final class ClosingSave implements Runnable, AutoCloseable {
        private final Draft draft;
        ClosingSave(Draft draft) { this.draft = draft; }
        @Override public void run() {
            try { if (draft != null) saveOnClose(draft); }
            catch (Exception | LinkageError error) { coordinator.events().append(draft.key(), Instant.now(), JourneyEventLog.Level.ERROR,
                    "Final automatic save could not complete. The previously saved journey was preserved."); }
            finally { close(); }
        }
        @Override public void close() { if (draft != null) draft.close(); library.close(); }
    }
    /** Merges into the last committed envelope while retaining its revision guard and secret-consent rules. */
    private void saveOnClose(Draft draft) throws Exception {
        var changed = savedDefinition(draft); var scope = draft.key().scope();
        checkEpoch(scope, draft.scopeEpoch());
        try (var loaded = scope == JourneyDefinition.Scope.LIBRARY ? library.load() : null;
             var current = scope == JourneyDefinition.Scope.PROJECT ? projects.loadNativeProject().orElseGet(() -> ConfigManager.NativeDocument.empty(ConfigManager.DocumentKind.PROJECT))
                     : loaded.document().withRevision(loaded.document().revision());
             var values = new SecretStore.Values(changed.mtls() == null ? null : draft.pin(), draft.steps().secrets)) {
            if (scope == JourneyDefinition.Scope.LIBRARY && !java.util.Objects.equals(loaded.version(), libraryVersion))
                throw new IllegalStateException("Storage changed before the final save.");
            var journeys = new ArrayList<>(current.journeys()); journeys.removeIf(j -> j.id().equals(changed.id())); journeys.add(changed);
            var all = new LinkedHashMap<UUID, SecretStore.Values>(); current.secrets().forEach((id, secret) -> { if (!id.equals(changed.id())) all.put(id, secret.copy()); });
            all.put(changed.id(), values.copy());
            try (var edited = new ConfigManager.NativeDocument(current.kind(), current.revision(), journeys, current.retiredAliases(), current.controls(), all)) {
                if (scope == JourneyDefinition.Scope.PROJECT) try (var saved = projects.saveNativeProject(edited, projectRevision)) { projectRevision = saved.revision(); }
                else try (var saved = library.save(edited, libraryVersion)) { libraryVersion = saved.version(); }
            }
        }
    }
    /** Allows the extension's off-EDT cleanup to wait for the final revision-checked save. */
    void awaitSaves(long milliseconds) {
        try {
            if (!io.awaitTermination(milliseconds, TimeUnit.MILLISECONDS)) for (var task : io.shutdownNow()) {
                if (task instanceof ClosingSave save) save.close(); else if (task instanceof UiController.Job job) job.discard();
            }
        } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
    }
    /**
     * Admits one bounded background UI action and wipes its captured inputs if the queue is closed or full.
     *
     * @param executor Owned bounded executor.
     * @param owner Optional captured values.
     * @param work Background action.
     */
    private boolean enqueue(ThreadPoolExecutor executor, AutoCloseable owner, Work work) {
        var job = new Job(owner, work); if (closed) { job.discard(); return false; }
        try { executor.execute(job); return true; } catch (RuntimeException ex) { job.discard(); ui(() -> status.setText("Too many actions are waiting. Let them finish, then try again.")); return false; }
    }
    /**
     * Converts known validation/storage/native errors to safe visible guidance and discards other raw exception details.
     *
     * @param error Known typed validation/storage/native exception; other messages are discarded.
     */
    private void report(Throwable error) { report(error, -1); }
    /**
     * Reports a safe action failure only to the draft that originated it, preventing stale validation feedback.
     * @param error Known typed failure; raw browser/provider errors are discarded.
     * @param epoch Draft epoch, or negative for a global storage/action failure.
     */
    private void report(Throwable error, long epoch) {
        report(error, epoch, null);
    }
    /** @param error Known typed failure. @param epoch Originating editor epoch, or -1. @param owner Captured journey owner; never inferred from the current selection. */
    private void report(Throwable error, long epoch, SecretStore.Key owner) {
        boolean generatedTagCollision = owner != null && error.getMessage() != null && error.getMessage().startsWith("Alias is already");
        String safe = generatedTagCollision ? "A journey already uses this generated tag. Choose a different journey name."
                : error instanceof AuthenticationFailure f ? f.getMessage() : error instanceof ConfigManager.NativeFormatException ? validationMessage(error.getMessage()) : error instanceof UserLibraryStore.LibraryException ? error.getMessage()
                : error instanceof IllegalArgumentException || error instanceof IllegalStateException ? safeLocal(error) : "The action failed.";
        diagnostics.state(null, error instanceof AuthenticationFailure f ? f : new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CONFIGURATION, safe, ""));
        SecretStore.Key attributed = owner != null ? owner : error instanceof AuthenticationFailure failure && failure.journey() != null ? failure.journey().key() : null;
        if (attributed != null) coordinator.events().append(attributed, Instant.now(), JourneyEventLog.Level.ERROR, safe);
        Runnable show = () -> { status.error(safe); showInvalidField(generatedTagCollision ? "displayName" : error.getMessage(), safe, false); };
        if (epoch < 0) ui(show); else ui(epoch, show);
    }

    /** Keeps journey controls out of empty/batch selections while retaining the chosen detail view. */
    private void refreshJourneyDock() {
        collectionFeedback.setText(status.isVisible() ? "" : status.getText());
        boolean open = status.isVisible() && (status.isLogOpen() || status.isCacheOpen());
        if (detailSurface.isVisible() != open) showEventDock(); else refreshCacheView();
    }
    /** Switches the journey-owned detail view; tab navigation keeps its open mode and divider unchanged. */
    private void showEventDock() {
        boolean open = status.isVisible() && (status.isLogOpen() || status.isCacheOpen());
        if (!open && detailSurface.isVisible()) eventDockHeight = Math.max(180, detailSurface.getHeight());
        detailCards.show(detailSurface, status.isCacheOpen() ? "cache" : "events");
        detailSurface.setVisible(open); eventDock.setDividerSize(open ? 7 : 0); refreshCacheView();
        eventDock.revalidate();
        if (open) { eventDock.setDividerLocation(Math.max(180, eventDock.getHeight() - eventDockHeight - 7)); SwingUtilities.invokeLater(() -> { if (!closed) eventLog.initializeDivider(); }); }
    }
    /** Clears displayed credentials on other tabs or ambiguous selection; returning inspects the current publication. */
    private void refreshCacheView() {
        var entry = saved.getSelectedIndices().length == 1 ? currentEditorEntry() : null;
        if (mainTabs.getSelectedIndex() != 0 || !status.isVisible() || !status.isCacheOpen()) cacheView.clear();
        else cacheView.refresh(entry, entry == null ? null : coordinator.peek(entry.identity()));
    }
    /** Creates wrapping tab-local feedback without interpreting user-controlled content as HTML. */
    private static JTextArea feedback(String accessibleName) {
        var area = new JTextArea(1, 0); area.setEditable(false); area.setLineWrap(true); area.setWrapStyleWord(true); area.setOpaque(false);
        area.getAccessibleContext().setAccessibleName(accessibleName); area.setVisible(false); return area;
    }
    /** Reports safe settings/storage guidance without changing the selected journey's status or event history. */
    private void controlSaveFailed(boolean waiting, Throwable error) {
        String safe = error instanceof ConfigManager.NativeFormatException ? validationMessage(error.getMessage())
                : error instanceof UserLibraryStore.LibraryException ? error.getMessage()
                : error instanceof IllegalArgumentException || error instanceof IllegalStateException ? safeLocal(error) : "Settings could not be saved. Check storage access and retry.";
        diagnostics.state(null, new AuthenticationFailure(AuthenticationFailure.Phase.SETUP, AuthenticationFailure.Cause.CONFIGURATION, safe));
        ui(() -> showInvalidField(error.getMessage(), safe, false));
    }
    /**
     * Presents validated field paths as short user-facing captions without echoing input values.
     * @param message Redacted codec field path and reason.
     * @return Human-readable field/row guidance.
     */
    private static String validationMessage(String message) {
        var step = java.util.regex.Pattern.compile("^steps\\[(\\d+)]\\.([^:]+):\\s*(.*)$").matcher(message);
        if (step.matches()) {
            String label = switch (step.group(2)) { case "selector" -> "CSS selector"; case "urlPattern" -> "URL pattern"; case "durationMs" -> "Duration"; case "value" -> "Text value"; case "state" -> "Load state"; default -> "Setting"; };
            return "Step " + (Integer.parseInt(step.group(1)) + 1) + ", " + label + ": " + step.group(3);
        }
        if (message.startsWith("controls.requestWaitTimeoutMs") || message.startsWith("requestWaitTimeoutMs")) return "Request wait must be between 1 and 600 seconds.";
        if (message.startsWith("controls.attemptTimeoutMs") || message.startsWith("attemptTimeoutMs")) return "Login attempt timeout must be between 1 and 300 seconds.";
        if (message.startsWith("controls.cycleTimeoutMs") || message.startsWith("cycleTimeoutMs")) return "Total login timeout must cover the request wait and login attempt timeout, up to 1800 seconds.";
        int colon = message.indexOf(':'); if (colon < 0) return message;
        String path = message.substring(0, colon), label = path;
        String leaf = path.substring(path.lastIndexOf('.') + 1);
        if (leaf.equals("navigationTimeoutMs")) return "Browser action timeout must be between 1 and 300 seconds.";
        if (leaf.equals("tokenWaitTimeoutMs")) return "Final capture wait must be between 0.001 and 300 seconds.";
        if (leaf.equals("certificateSha256")) return "Choose a client certificate before running this journey.";
        label = switch (leaf) {
            case "navTimeout" -> "Browser action timeout (seconds)";
            case "tokenWait" -> "Final capture wait (seconds)";
            case "maxAge", "maxAgeSeconds" -> "Maximum cache age (seconds)";
            case "skew", "refreshSkewSeconds" -> "Refresh before expiry (seconds)";
            case "recoveryStatus", "statusCode" -> "Failure status";
            case "displayName" -> "Display name"; case "alias" -> "Tag alias"; case "authenticationUrl" -> "Login URL";
            case "modulePath" -> "Middleware file"; case "slot" -> "Security device";
            case "origins" -> "Additional authentication servers";
            case "trustedCaBundlePath" -> "Trusted CA";
            case "maxWaitingRequestsGlobal", "global" -> "Global limit";
            case "maxWaitingRequestsPerJourney", "per" -> "Per-journey limit";
            case "request" -> "Request wait (seconds)"; case "attempt" -> "Login attempt timeout (seconds)";
            case "cycle" -> "Total login timeout (seconds)";
            case "urlPrefix" -> "URL prefix";
            default -> label;
        };
        if (path.startsWith("browser.proxy")) label = "Proxy URL";
        if (path.equals("recovery.pattern")) label = "RE2 expression";
        var row = java.util.regex.Pattern.compile("extraction\\.tokens\\[(\\d+)\\]").matcher(path);
        String prefix = row.find() ? "Token " + (Integer.parseInt(row.group(1)) + 1) + ", " : "";
        if (path.startsWith("extraction")) {
            if (path.endsWith("jsonPath")) label = "JSON path";
            else if (path.endsWith("startRegex")) label = "Start regex";
            else if (path.endsWith("endRegex")) label = "End regex";
            else if (path.endsWith("responseOrigin")) label = "Response origin";
            else if (path.endsWith("originUrl")) label = "Capture URL";
            else if (path.endsWith("pathSubstring")) label = "Path contains";
            else if (path.endsWith("domain")) label = "Cookie domain";
            else if (path.endsWith("path")) label = "Cookie path";
            else if (path.endsWith("name")) label = path.matches("extraction\\.tokens\\[\\d+]\\.name") ? "Credential name" : "Cookie name";
            else label = "Token selection";
            label = prefix + label;
        } else if (path.startsWith("injection")) label = "Inject into";
        return label + message.substring(colon);
    }
    /** @param message Redacted indexed field error. @param inputs Its exact configuration snapshot. @return Row/name context using only bounded valid credential names, never captured values or selectors. */
    private static String validationMessage(String message, List<CredentialsPanel.Input> inputs) {
        String guidance = validationMessage(message);
        var row = java.util.regex.Pattern.compile("^extraction\\.tokens\\[(\\d+)]").matcher(message);
        if (!row.find()) return guidance;
        int index = Integer.parseInt(row.group(1)); if (index >= inputs.size()) return guidance;
        String name = inputs.get(index).name().trim();
        String identity = "Credential " + (index + 1) + (CredentialNames.problem(name) == null ? " \"" + name + "\"" : "");
        if (message.startsWith("extraction.tokens[" + index + "].name:")) return identity + ": " + message.substring(message.indexOf(':') + 1).stripLeading();
        String prefix = "Token " + (index + 1) + ", ";
        return identity + ", " + (guidance.startsWith(prefix) ? guidance.substring(prefix.length()) : guidance);
    }
    /**
     * Reveals the field named by safe validation metadata when execution reports a configuration error.
     * @param message Validation description; values are never parsed or echoed here.
     */
    private void focusInvalidField(String message) {
        showInvalidField(message, message == null ? "Check this input." : validationMessage(message, credentials.snapshot()), true);
    }
    /**
     * Associates safe guidance with the relevant input; background validation never changes the selected page or focus.
     * @param message Known field path used only to locate an input.
     * @param guidance Sanitized visible explanation.
     * @param focus Whether this explicit action may reveal and focus the input.
     */
    private void showInvalidField(String message, String guidance, boolean focus) {
        if (message == null) return;
        if (message.contains("mtls.slot") || message.startsWith("slot:") || message.contains("certificateSha256") && !hasChosenDevice()) {
            if (fields.get("module").getText().isBlank()) { showInvalidField("mtls.modulePath:", "Choose a middleware file before selecting the security device and certificate.", focus); return; }
            if (focus && message.contains("certificateSha256")) pendingPinFocus = new PendingPinFocus(editing, selectionEpoch, deviceDiscoveryVersion, guidance, chooseCertificateButton);
            InlineValidation.show(devicePicker, guidance); if (focus) { wizard.setSelectedIndex(3); devicePicker.focusChoice(); } return;
        }
        if (message.contains("certificateSha256")) { InlineValidation.show(chooseCertificateButton, guidance); if (focus) { wizard.setSelectedIndex(3); InlineValidation.focus(chooseCertificateButton); } return; }
        if (message.startsWith("steps[")) { if (focus) wizard.setSelectedIndex(1); steps.showInvalid(message, guidance, focus); return; }
        if (message.startsWith("extraction") || message.startsWith("injection")) { if (focus) wizard.setSelectedIndex(2); credentials.showInvalid(message, guidance, focus); return; }
        Map<String, String> names = new LinkedHashMap<>();
        names.put("authenticationUrl", "url"); names.put("displayName", "name"); names.put("alias", "name");
        names.put("browser.proxy", "proxy"); names.put("navigationTimeout", "navTimeout"); names.put("tokenWait", "tokenWait");
        names.put("responseOrigin", "responseOrigin"); names.put("jsonPath", "jsonPath"); names.put("cookie", "cookieName");
        names.put("maxAge", "maxAge"); names.put("refreshSkew", "skew"); names.put("modulePath", "module");
        names.put("origins", "origins"); names.put("pattern", "pattern");
        names.put("trustedCaBundlePath", "ca");
        names.put("navTimeout", "navTimeout"); names.put("tokenWaitTimeoutMs", "tokenWait"); names.put("skew", "skew"); names.put("recoveryStatus", "recoveryStatus");
        names.put("requestWaitTimeoutMs", "control.request"); names.put("attemptTimeoutMs", "control.attempt"); names.put("cycleTimeoutMs", "control.cycle");
        names.put("control.request", "control.request"); names.put("control.attempt", "control.attempt"); names.put("control.cycle", "control.cycle");
        names.put("control.global", "control.global"); names.put("control.per", "control.per"); names.put("URL prefix", "control.prefix");
        names.put("Total login timeout", "control.cycle"); names.put("module", "module");
        for (var item : names.entrySet()) if (message.contains(item.getKey())) {
            JComponent target = fields.get(item.getValue()); if (target == null) return;
            InlineValidation.show(target, guidance); if (!focus) return;
            for (Component child = target; child.getParent() != null; child = child.getParent()) {
                Container parent = child.getParent();
                if (parent instanceof JTabbedPane tabs) { int index = tabs.indexOfComponent(child); if (index >= 0 && tabs.isEnabledAt(index)) tabs.setSelectedIndex(index); }
                if (!child.isVisible()) { child.setVisible(true); for (Component sibling : parent.getComponents()) if (sibling instanceof JToggleButton toggle) toggle.setSelected(true); }
            }
            InlineValidation.focus(target); return;
        }
    }
    /**
     * Allows only known local validation messages, preventing URI/parser/IO content from reaching the UI or log.
     *
     * @param error Local validation error.
     * @return Only constant known local guidance; raw URI/IO errors are never echoed.
     */
    private static String safeLocal(Throwable error) {
        if (error.getMessage() != null && (error.getMessage().startsWith("Journey alias is conflicting") || error.getMessage().startsWith("Journey alias is ambiguous")))
            return "A journey already uses this generated tag. Choose a different journey name.";
        String value = error.getMessage();
        if (value != null && value.matches("Rule [0-9]+: (enter an absolute HTTP\\(S\\) URL prefix\\.|failure status must be between 100 and 599\\.)")) return value;
        if (value != null && (value.startsWith("Alias is already") || value.startsWith("Storage changed") || value.startsWith("Storage is unavailable") || value.startsWith("Wait time requires") || value.startsWith("Field ") || value.startsWith("URL prefix must") || value.startsWith("Enter a valid duration") || value.startsWith("This journey changed") || value.startsWith("Total login timeout"))) return value;
        return "The action could not be completed for this journey.";
    }
    /**
     * Posts a display update to the EDT only while its lifecycle and optional captured editor epoch remain valid.
     *
     * @param task EDT display action; ignored after shutdown.
     */
    private void ui(Runnable task) { SwingUtilities.invokeLater(() -> { if (!closed) task.run(); }); }
    /**
     * Posts a display update to the EDT only while its lifecycle and optional captured editor epoch remain valid.
     *
     * @param epoch Captured editor generation.
     * @param task Display update for that exact editor.
     */
    private void ui(long epoch, Runnable task) { ui(epoch, task, null); }
    /**
     * Posts a display update to the EDT only while its lifecycle and optional captured editor epoch remain valid.
     *
     * @param epoch Captured editor generation.
     * @param task Exact-editor update.
     * @param discarded Optional owner closed if completion became stale.
     */
    private void ui(long epoch, Runnable task, AutoCloseable discarded) { SwingUtilities.invokeLater(() -> { if (!closed && editorEpoch == epoch) task.run(); else if (discarded != null) try { discarded.close(); } catch (Exception ignored) { /* drop obsolete owned values */ } }); }
    /**
     * Returns whether an explicit journey draft exists and startup loading finished.
     *
     * @return Whether an explicit journey draft exists and startup loading finished.
     */
    private boolean readyEditor() { if (initialized && editing != null && !editorLoading && !closed) return true; message("Select a saved journey or create one after storage loading finishes."); return false; }
    /**
     * Parents local guidance to the actual Burp suite frame for correct stacking and monitor placement.
     *
     * @param text User guidance displayed over the owning Burp suite frame.
     */
    private void message(String text) { dialogs.inform(parent(), text); }
    /**
     * Returns burp's actual suite frame, keeping dialogs on its monitor.
     *
     * @return Burp's actual suite frame, keeping dialogs on its monitor.
     */
    private Component parent() { return api == null ? journeyEditor : api.userInterface().swingUtils().suiteFrame(); }
    /**
     * Creates a fixed daemon action service with a finite queue and explicit overload rejection.
     *
     * @param name Thread label.
     * @param threads Fixed worker count.
     * @param queued Finite pending-action capacity.
     * @return Owned daemon executor.
     */
    private static ThreadPoolExecutor executor(String name, int threads, int queued) { return new ThreadPoolExecutor(threads, threads, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(queued), r -> { var t = new Thread(r, name); t.setDaemon(true); return t; }, new ThreadPoolExecutor.AbortPolicy()); }
    /**
     * Binds a local EDT snapshot/queue action without starting work merely by constructing the control.
     *
     * @param title Button label.
     * @param action EDT snapshot/queue action.
     * @return Bound local control.
     */
    private static JButton button(String title, Runnable action) {
        UiIcons.Action icon = switch (title) {
            case "New journey", "Create journey" -> UiIcons.Action.ADD; case "Back" -> UiIcons.Action.BACK; case "Next" -> UiIcons.Action.NEXT;
            case "Save" -> UiIcons.Action.SAVE; case "Test login", "Save and test" -> UiIcons.Action.PLAY;
            case "Cancel authentication" -> UiIcons.Action.STOP; case "Retry authentication", "Retry certificate listing" -> UiIcons.Action.RETRY;
            case "Clear cached token" -> UiIcons.Action.REMOVE; case "Copy tag" -> UiIcons.Action.COPY; case "Browse..." -> UiIcons.Action.FOLDER;
            default -> null;
        };
        if (icon != null) return UiIcons.button(icon, title, action);
        var button = new JButton(title); button.addActionListener(e -> action.run()); return button;
    }
    /**
     * Returns vertically filled form panel inside a scroll pane.
     *
     * @return Vertically filled form panel inside a scroll pane.
     */
    private static JPanel form() { return new JPanel(new GridBagLayout()); }
    /**
     * Adds an accessible label/control pair with stable form alignment and horizontal resizing.
     *
     * @param panel Form.
     * @param label Human-readable field label.
     * @param value Control or help component.
     */
    private static void row(JPanel panel, String label, Component value) {
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
    private static JScrollPane scroll(Component content) { var pane = new JScrollPane(new FormViewport(content)); pane.setBorder(BorderFactory.createEmptyBorder()); pane.getVerticalScrollBar().setUnitIncrement(18); return pane; }

    /** Keeps top-aligned forms at the visible width so fields and help wrap after a Burp window resize. */
    private static final class FormViewport extends JPanel implements Scrollable {
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
    /**
     * Displays wrapping plain-text help without interpreting user content as HTML.
     *
     * @param text Wrapping plain-text guidance.
     * @return Noneditable label-like content with no HTML rendering.
     */
    private static JTextArea note(String text) { var area = new JTextArea(text, Math.min(12, Math.max(2, text.length() / 90)), 45); area.setEditable(false); area.setLineWrap(true); area.setWrapStyleWord(true); area.setOpaque(false); return area; }
    /**
     * Registers a named local editor field whose document listener only schedules background validation.
     *
     * @param key Stable editor key.
     * @param placeholder Inline format guidance.
     * @return Named field observed only for local edits.
     */
    private JTextField field(String key, String placeholder) {
        var field = new PlaceholderTextField(placeholder, 30); field.setName(key); field.setToolTipText(fieldHelp(key)); fields.put(key, field);
        field.getDocument().addDocumentListener(new DocumentChangeListener(() -> {
            if (key.startsWith("control.")) controlsEdited(!key.equals("control.prefix"));
            else {
                if (!suppress && key.equals("module")) clearCertificateFeedback();
                if (!suppress && key.equals("module")) { pin.setText(""); pinAvailable = false; }
                if (key.equals("name") && !suppress) { draftAlias = JourneyNames.alias(field.getText()); var entry = editing == null ? null : registry.snapshot().entries().get(editing); renameNotice.setVisible(entry != null && !entry.definition().canonicalAlias().equals(draftAlias)); }
                edited();
                if (!suppress && key.equals("module")) scheduleDeviceDiscovery();
            }
        })); return field;
    }
    /**
     * Registers a named acknowledgement/option checkbox with no inline storage or native operation.
     *
     * @param key Stable flag key.
     * @param title Visible meaning, including persistence/recovery acknowledgements.
     * @return Named checkbox.
     */
    private JCheckBox check(String key, String title) { var box = new JCheckBox(title); box.setName(key); checks.put(key, box); box.addActionListener(e -> { if (Set.of("enabled", "globalUnlimited", "perUnlimited").contains(key)) { clearUnusedFields(); controlsEdited(!key.equals("enabled")); } else { clearUnusedFields(); edited(); } }); return box; }
    /** Marks project-policy edits without making the selected journey appear dirty or validating unrelated fields. */
    private void controlsEdited() { controlsEdited(false); }
    /** @param waiting Whether this edit belongs to waiting settings rather than automatic-injection rules. */
    private void controlsEdited(boolean waiting) {
        if (!suppress && !closed) {
            Timer timer = waiting ? settingsDebounce : automaticDebounce; if (timer != null) timer.restart();
        }
        refreshModes();
    }

    /** Clears values that cease to apply after an explicit mode/checkbox change, never during population. */
    private void clearUnusedFields() {
        if (suppress) return; suppress = true;
        try {
            if (checks.containsKey("globalUnlimited") && checks.get("globalUnlimited").isSelected()) clearField("control.global");
            if (checks.containsKey("perUnlimited") && checks.get("perUnlimited").isSelected()) clearField("control.per");
            boolean mtls = checks.containsKey("mtls") && checks.get("mtls").isSelected();
            if (!mtls) { pinAvailable = false; selectedCertificateSha256 = ""; loadedCertificate = null; }
            if (!mtls) {
                slotKind = JourneyDefinition.SlotKind.INDEX; slotValue = "0"; selectedCertificateDevice = null; displayedDevice = null; certificateRetryAvailable = false;
                deviceDiscoveryVersion++; deviceDiscoveryRunning = false; devicePicker.reset();
                if (deviceDebounce != null) deviceDebounce.stop(); clearCertificateFeedback();
                for (String key : List.of("module", "origins", "ca")) clearField(key);
            }
            if (!mtls) certificateDetails.setText("");
            if (!mtls) pin.setText("");
        } finally { suppress = false; }
    }
    /** @param key Optional constructed field whose irrelevant value is being discarded. */
    private void clearField(String key) { var field = fields.get(key); if (field != null && !field.getText().isEmpty()) field.setText(""); }
    /** @param key Constructed field. @param visible Whether both its caption and input apply. */
    private void visibleField(String key, boolean visible) {
        var field = fields.get(key); if (field == null) return; InlineValidation.visible(field, visible);
        Object caption = field.getClientProperty("rowLabel"); if (caption instanceof JLabel label) label.setVisible(visible);
    }
    /**
     * Converts user-facing seconds to exact milliseconds for the stable persisted format.
     * @param values Captured settings text.
     * @param key Known duration field.
     * @return Exact duration, preserving fractional seconds without rounding.
     */
    private static int seconds(Map<String, String> values, String key) {
        try { return new java.math.BigDecimal(values.get(key).trim()).multiply(java.math.BigDecimal.valueOf(1000)).intValueExact(); }
        catch (RuntimeException ex) { throw new ConfigManager.NativeFormatException(key + ": enter a valid duration in seconds."); }
    }
    /** @param milliseconds Persisted duration. @return Exact readable seconds without redundant zeros. */
    private static String secondsText(int milliseconds) { return java.math.BigDecimal.valueOf(milliseconds, 3).stripTrailingZeros().toPlainString(); }
    /** @param key Stable input identity. @return Short context-specific explanation shown on hover. */
    private static String fieldHelp(String key) {
        return switch (key) {
            case "name" -> "The request tag is generated from this name. Renaming the journey also changes its tag.";
            case "url" -> "First page opened by the authentication browser.";
            case "module" -> "Absolute path to your vendor's PKCS#11 library: DLL on Windows, SO on Linux, or dylib on macOS.";
            case "ca" -> "Add a PEM CA file if the login server's certificate isn't already trusted.";
            case "proxy" -> "Optional HTTP proxy, for example a Burp listener. Leave empty to connect directly.";
            case "navTimeout" -> "Maximum time for one browser action, in seconds. Fractional seconds are supported.";
            case "tokenWait" -> "Final time to wait for credentials after the steps finish, in seconds. Capture also runs throughout the journey. Fractional seconds are supported.";
            case "maxAge" -> "Maximum time to reuse cached credentials. An earlier token or cookie expiry takes precedence.";
            case "skew" -> "Start refreshing this many seconds before credentials expire.";
            case "recoveryStatus" -> "HTTP response status that means the session ended, for example 401.";
            case "pattern" -> "RE2 expression searched in response text, for example session.*expired. Lookaround and backreferences are unsupported.";
            case "control.prefix" -> "Only authenticate requests whose full URL starts with this value.";
            case "control.request" -> "How long a request may wait for authentication.";
            case "control.attempt" -> "Maximum duration of one login attempt, including browser setup.";
            case "control.cycle" -> "Maximum total time for login and automatic retries. Must cover the request wait and login attempt timeout.";
            case "control.global" -> "Maximum requests waiting for authentication across all journeys.";
            case "control.per" -> "Maximum requests waiting for this journey.";
            case "origins" -> "The HTTPS Login URL's server is included automatically. Add other HTTPS server addresses without page paths, separated by commas.";
            default -> null;
        };
    }
    /**
     * Observes local password-document changes without submitting a PIN or password.
     *
     */
    private void pinChanged() {
        if (!suppress) {
            loadedCertificate = null;
            clearCertificateFeedback();
            char[] value = pin.getPassword();
            try { pinAvailable = value.length > 0; } finally { Arrays.fill(value, '\0'); }
        }
        edited();
    }
    /** Enables only fields meaningful for the selected mode without erasing unrelated saved values. */
    private void refreshModes() {
        boolean mtls = checks.containsKey("mtls") && checks.get("mtls").isSelected();
        boolean librarySelected = mtls && fields.containsKey("module") && !fields.get("module").getText().isBlank();
        if (certificateFields != null) certificateFields.setVisible(mtls); if (wizard.getTabCount() > 3) wizard.setEnabledAt(3, mtls);
        if (!mtls && wizard.getSelectedIndex() == 3) wizard.setSelectedIndex(0);
        devicePicker.setVisible(librarySelected);
        if (devicePicker.getClientProperty("rowLabel") instanceof JLabel label) label.setVisible(librarySelected);
        boolean deviceChosen = librarySelected && hasChosenDevice();
        if (certificateSettings != null) certificateSettings.setVisible(deviceChosen);
        refreshCertificatePresentation();
        if (checks.containsKey("globalUnlimited")) visibleField("control.global", !checks.get("globalUnlimited").isSelected());
        if (checks.containsKey("perUnlimited")) visibleField("control.per", !checks.get("perUnlimited").isSelected());
        if (automaticFields != null) automaticFields.setVisible(checks.containsKey("enabled") && checks.get("enabled").isSelected());
        InlineValidation.visible(pin, deviceChosen); Object pinLabel = pin.getClientProperty("rowLabel"); if (pinLabel instanceof JLabel label) label.setVisible(deviceChosen);
        pin.setEnabled(!editorLoading && deviceChosen);
    }
    /**
     * Applies mode-specific field availability without re-enabling an editor whose selection is still loading.
     *
     * @param key Known field name when already constructed.
     * @param value Enabled state.
     */
    private void enabled(String key, boolean value) { if (fields.containsKey(key)) fields.get(key).setEnabled(value && (!editorLoading || key.startsWith("control."))); }
    /**
     * Disables the whole local journey editor during asynchronous selection changes, preventing wrong-identity saves.
     *
     * @param component Local editor tree.
     * @param enabled False while a saved selection is loading, preventing edits/saves against the previous journey's fields.
     */
    private static void enableTree(Component component, boolean enabled) { if (component == null) return; component.setEnabled(enabled); if (component instanceof Container container) for (Component child : container.getComponents()) enableTree(child, enabled); }
    /**
     * Populates a known field while the caller suppresses edit notifications.
     *
     * @param key Known field.
     * @param value Safe display value or null.
     */
    private void text(String key, Object value) { fields.get(key).setText(value == null ? "" : value.toString()); }
    /**
     * Populates a known option without synthesizing a user click or persistence action.
     *
     * @param key Known checkbox.
     * @param value Population state.
     */
    private void flag(String key, boolean value) { checks.get(key).setSelected(value); }
    /**
     * Adds only supplied optional native text; blank input remains absent rather than being coerced.
     *
     * @param object Native JSON node.
     * @param key Optional field.
     * @param value Blank means absent, never a coerced null.
     */
    private static void optional(ObjectNode object, String key, String value) { if (!value.isBlank()) object.put(key, value.trim()); }
    /**
     * Parses a captured integral editor value with a safe field-specific correction on failure.
     *
     * @param text Captured fields.
     * @param key Known integer input.
     * @return Exact integer without implicit truncation.
     */
    private static int number(Map<String, String> text, String key) { try { return Integer.parseInt(text.get(key).trim()); } catch (RuntimeException ex) { throw new ConfigManager.NativeFormatException(key + ": enter a whole number."); } }
    /**
     * Parses a slot integer exactly before native selector bounds and availability are checked.
     *
     * @param text Captured slot number.
     * @param key Safe field name.
     * @return Exact long; codec validates slot bounds.
     */
    private static long longNumber(String text, String key) { try { return Long.parseLong(text.trim()); } catch (RuntimeException ex) { throw new ConfigManager.NativeFormatException(key + ": enter a whole number."); } }
    /**
     * Reads only an explicitly chosen bounded UTF-8 native import without logging its contents.
     *
     * @param file Explicit import source.
     * @return Bounded strictly decoded native JSON, without logging its contents.
     */
    private static String readSmall(Path file) throws Exception {
        try (var input = Files.newInputStream(file)) {
            byte[] bytes = input.readNBytes((4 << 20) + 1);
            if (bytes.length > (4 << 20)) throw new ConfigManager.NativeFormatException("Native import exceeds 4 MiB; export fewer journeys and retry.");
            try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString(); }
            catch (java.nio.charset.CharacterCodingException ex) { throw new ConfigManager.NativeFormatException("Native import is not valid UTF-8; convert a native journey export to UTF-8 and retry."); }
        }
    }
}

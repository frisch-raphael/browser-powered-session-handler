package bpsh.burp.ui;

import bpsh.journey.JourneyCatalog;

import bpsh.authentication.credentials.TokenLifetime;
import bpsh.authentication.credentials.TokenSnapshot;
import bpsh.journey.JourneyDefinition;
import bpsh.authentication.http.HttpAuthenticationProgress;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

/** Explicit read-only inspection of one journey's usable cache; values never enter logs, persistence or diagnostics. */
final class JourneyCachePanel extends JPanel {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd MMM uuuu HH:mm:ss z").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter COMPACT_TIME = DateTimeFormatter.ofPattern("dd MMM, HH:mm:ss").withZone(ZoneId.systemDefault());
    private final JLabel empty = new JLabel("No usable cached credentials.");
    private final JLabel httpNote = new JLabel("Requests use the saved HTTP authentication identity for each allowed origin.");
    private final JPanel metadata = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    private final JLabel expires = new JLabel(), refresh = new JLabel(), cached = new JLabel();
    private final Model model = new Model();
    private final JTable table = new JTable(model);
    private final PlainRenderer renderer = new PlainRenderer();
    private final JPopupMenu menu = new JPopupMenu();
    private final JMenuItem copyName = new JMenuItem("Copy name"), copyValue = new JMenuItem("Copy value");
    private final Consumer<String> feedback, clipboard;
    private JourneyDefinition.Identity shown;
    private long version = -1;
    private List<HttpAuthenticationProgress> httpProgress = List.of();
    private bpsh.journey.HttpAuthentication shownHttp;

    /** @param close Hides the dock and releases its displayed credential references. */
    JourneyCachePanel(Runnable close) { this(close, message -> {}); }
    /** @param close Hides the dock. @param feedback Reports only safe clipboard failures, never the copied text. */
    JourneyCachePanel(Runnable close, Consumer<String> feedback) {
        this(close, feedback, text -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null));
    }
    /** @param close Hides the dock. @param feedback Safe clipboard-failure reporting. @param clipboard Explicit copy destination; tests use an owned clipboard. */
    JourneyCachePanel(Runnable close, Consumer<String> feedback, Consumer<String> clipboard) {
        super(new BorderLayout(8, 6)); setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        this.feedback = feedback; this.clipboard = clipboard;
        metadata.add(timing("Expires", expires)); metadata.add(Box.createHorizontalStrut(24));
        metadata.add(timing("Refresh due", refresh)); metadata.add(Box.createHorizontalStrut(24));
        metadata.add(timing("Cached", cached));
        metadata.setVisible(false);
        var actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0)); actions.add(UiIcons.button(UiIcons.Action.REMOVE, "Close journey cache", close));
        var summary = new JPanel(); summary.setLayout(new BoxLayout(summary, BoxLayout.Y_AXIS));
        metadata.setAlignmentX(Component.LEFT_ALIGNMENT); empty.setAlignmentX(Component.LEFT_ALIGNMENT); httpNote.setAlignmentX(Component.LEFT_ALIGNMENT);
        httpNote.setVisible(false); summary.add(metadata); summary.add(httpNote); summary.add(empty);
        var top = new JPanel(new BorderLayout(8, 0)); top.add(summary); top.add(actions, BorderLayout.EAST); add(top, BorderLayout.NORTH);
        getAccessibleContext().setAccessibleName("Journey cache"); metadata.getAccessibleContext().setAccessibleName("Cache lifetime");
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); table.setDefaultRenderer(Object.class, renderer); table.getAccessibleContext().setAccessibleName("Cached credentials");
        table.getColumnModel().getColumn(0).setPreferredWidth(80); table.getColumnModel().getColumn(0).setMaxWidth(110);
        table.getColumnModel().getColumn(1).setPreferredWidth(220); table.getColumnModel().getColumn(2).setPreferredWidth(700);
        copyName.addActionListener(e -> copy(true)); copyValue.addActionListener(e -> copy(false)); menu.add(copyName); menu.add(copyValue);
        table.getSelectionModel().addListSelectionListener(e -> updateCopyActions()); updateCopyActions();
        table.addMouseListener(new MouseAdapter() {
            /** Selects the clicked credential before opening its actions on platforms that trigger on press. */
            @Override public void mousePressed(MouseEvent event) { popup(event); }
            /** Supports platforms whose native popup trigger occurs on release. */
            @Override public void mouseReleased(MouseEvent event) { popup(event); }
        });
        table.getInputMap().put(KeyStroke.getKeyStroke("shift F10"), "cacheMenu");
        table.getInputMap().put(KeyStroke.getKeyStroke("CONTEXT_MENU"), "cacheMenu");
        table.getActionMap().put("cacheMenu", new AbstractAction() {
            /** Opens the same actions for the keyboard-selected credential. */
            @Override public void actionPerformed(java.awt.event.ActionEvent event) {
                int row = table.getSelectedRow(); if (row < 0) return;
                var cell = table.getCellRect(row, 1, true); menu.show(table, cell.x, cell.y + cell.height);
            }
        });
        add(new JScrollPane(table)); setPreferredSize(new Dimension(0, 310)); setMinimumSize(new Dimension(0, 180));
    }
    /** @param event Native popup gesture; blank rows clear selection and never expose another row's actions. */
    private void popup(MouseEvent event) {
        if (!event.isPopupTrigger()) return;
        int row = table.rowAtPoint(event.getPoint());
        if (row < 0) { table.clearSelection(); return; }
        table.setRowSelectionInterval(row, row); table.requestFocusInWindow(); menu.show(table, event.getX(), event.getY());
    }
    /** Enables copy only while a current displayed credential is selected. */
    private void updateCopyActions() { int row = table.getSelectedRow(); boolean enabled = row >= 0 && row < model.rows.size() && model.rows.get(table.convertRowIndexToModel(row)).copyable(); copyName.setEnabled(enabled); copyValue.setEnabled(enabled); }
    /** @param name Whether to copy the configured token name or actual cookie name, rather than its captured value. */
    private void copy(boolean name) {
        int row = table.getSelectedRow(); if (row < 0 || row >= model.rows.size()) return;
        var credential = model.rows.get(table.convertRowIndexToModel(row));
        if (!credential.copyable()) return;
        try { clipboard.accept(name ? credential.copyName() : credential.value()); }
        catch (IllegalStateException | SecurityException | HeadlessException error) { feedback.accept("Could not access the clipboard. Try copying again."); }
    }
    /**
     * Displays only a matching, usable publication supplied by the coordinator; no acquisition or secret-store access occurs.
     * @param entry Reviewed saved journey, or null when selection is absent/stale.
     * @param snapshot Current usable atomic publication, or null when absent/expired/invalidated.
     */
    void refresh(JourneyCatalog.Entry entry, TokenSnapshot snapshot) {
        refresh(entry,snapshot,List.of());
    }
    /** Adds current HTTP observations independently of reusable token and cookie publications. */
    void refresh(JourneyCatalog.Entry entry, TokenSnapshot snapshot, List<HttpAuthenticationProgress> observations) {
        refresh(entry,snapshot,observations,null);
    }
    /** A draft can expose its validated recording identity without compiling unfinished capture settings. */
    void refresh(JourneyCatalog.Entry entry, TokenSnapshot snapshot, List<HttpAuthenticationProgress> observations,
            bpsh.journey.HttpAuthentication recordedSettings) {
        getAccessibleContext().setAccessibleDescription(entry == null ? null : "Cached credentials for " + entry.definition().alias());
        if (entry == null) { clear(); return; }
        var httpSettings = entry.definition().httpAuthenticationEnabled() ? entry.definition().httpAuthentication() :
                entry.definition().draft() != null && entry.definition().draft().flags().get("httpAuthentication") ? recordedSettings : null;
        if (snapshot != null && !entry.identity().equals(snapshot.identity())) snapshot = null;
        long incoming = snapshot == null ? -1 : snapshot.version();
        if (entry.identity().equals(shown) && version == incoming && httpProgress.equals(observations) && java.util.Objects.equals(shownHttp,httpSettings)) return;
        clear(); shown = entry.identity(); version = incoming; httpProgress = List.copyOf(observations); shownHttp = httpSettings;
        var rows = new ArrayList<Credential>();
        if (snapshot != null) {
            metadata.setVisible(true); updateTiming(snapshot.lifetime());
            var extraction = snapshot.extraction() == null ? entry.definition().extraction() : snapshot.extraction();
            if (extraction instanceof JourneyDefinition.CombinedExtraction combined) {
                for (var token : combined.tokens()) add(rows, token.name(), token.selector(), snapshot.namedTokens().get(token.name()));
            } else add(rows, extraction instanceof JourneyDefinition.CookieExtraction cookie ? cookie.name() : "Default", extraction, snapshot.value());
        }
        if (httpSettings != null) {
            addHttp(rows,entry,httpSettings,snapshot,observations); httpNote.setVisible(true);
        }
        model.rows = List.copyOf(rows); model.fireTableDataChanged(); empty.setVisible(rows.isEmpty());
        if (!rows.isEmpty()) table.setRowSelectionInterval(0, 0);
    }
    /** Drops every displayed value on close, expiry, invalidation, selection change or unload. */
    void clear() { menu.setVisible(false); shown = null; version = -1; shownHttp = null; httpProgress = List.of(); if (!model.rows.isEmpty()) { model.rows = List.of(); model.fireTableDataChanged(); } table.clearSelection(); updateCopyActions(); renderer.setText(""); renderer.setToolTipText(null); for (var label : List.of(expires, refresh, cached)) timingValue(label, "", null); metadata.setVisible(false); httpNote.setVisible(false); empty.setVisible(true); }

    private static void addHttp(List<Credential> rows,JourneyCatalog.Entry entry,bpsh.journey.HttpAuthentication settings,TokenSnapshot snapshot,List<HttpAuthenticationProgress> observations) {
        String account = settings.domain().isEmpty() ? settings.username() : settings.domain() + "\\" + settings.username();
        for (var origin : settings.origins().stream().sorted(java.util.Comparator.comparing(Object::toString)).toList()) {
            var progress = observations.stream().filter(p -> p.origin() == null || p.origin().equals(origin))
                    .max(java.util.Comparator.comparing(HttpAuthenticationProgress::time)).orElse(null);
            String result = "Not yet observed";
            Instant observed = null;
            int status = 0;
            if (progress != null) { result = httpStatus(progress.stage()); observed = progress.time(); status = progress.httpStatus(); }
            else if (snapshot != null) {
                var evidence = snapshot.httpObservations().stream().filter(e -> origin.equals(e.origin()))
                        .max(java.util.Comparator.comparing(bpsh.authentication.http.HttpAuthenticationEvidence::observedAt)).orElse(null);
                if (evidence != null) {
                    result = switch (evidence.status()) { case ACCEPTED -> "Accepted"; case REJECTED -> "Rejected"; case UNCONFIRMED -> "Unconfirmed"; };
                    if (evidence.observedIdentity() != null && !entry.identity().equals(evidence.observedIdentity())) result += " before the latest edit";
                    observed = evidence.observedAt();
                    status = evidence.httpStatus();
                }
            }
            String details = result + (status == 0 ? "" : " (HTTP " + status + ")") + (observed == null ? "" : " — " + TIME.format(observed));
            rows.add(new Credential("HTTP auth", settings.protocol() + " · " + account, "", origin.toString(), false, details));
        }
    }
    private static String httpStatus(HttpAuthenticationProgress.Stage stage) {
        return switch (stage) {
            case ACCEPTED -> "Accepted"; case CONNECTION_REUSED -> "Accepted; connection reused";
            case REJECTED -> "Rejected"; case UNCONFIRMED -> "Unconfirmed"; case CANCELLED -> "Cancelled";
            case STARTED -> "Starting"; case NEGOTIATE_SENT -> "Negotiating"; case CHALLENGE_RECEIVED -> "Challenge received";
            case AUTHENTICATE_SENT, BASIC_SENT -> "Waiting for server confirmation";
            case TIMED_OUT -> "Timed out"; case INVALID_CHALLENGE -> "Invalid NTLM challenge";
            case RESPONSE_FAILED -> "Authentication response failed"; case CONNECTION_CLOSED -> "Connection closed during authentication";
            case TLS_FAILED -> "TLS failed"; case CONNECTION_FAILED -> "Connection failed"; case CAPACITY -> "Capacity exhausted";
            case SETUP_FAILED -> "Setup failed"; case MISSING_SECRET -> "Missing password or PIN";
            case ORIGIN_BLOCKED -> "Origin not allowed"; case AUTHORIZATION_CONFLICT -> "Application Authorization conflict";
            case PROXY_AUTH_REQUIRED -> "Proxy authentication required"; case FAILED -> "Exchange failed";
            case APPLICATION_DENIED -> "Application access denied"; case SERVER_ERROR -> "Server error";
        };
    }
    /** Displays fixed acquisition and deadline timestamps for this cache publication. */
    private void updateTiming(TokenLifetime.Window lifetime) {
        timestamp(expires, lifetime.acquiredAt().plusNanos(lifetime.usableNanos()), "Expires");
        timestamp(refresh, lifetime.acquiredAt().plusNanos(lifetime.refreshNanos()), "Refresh due");
        timestamp(cached, lifetime.acquiredAt(), "Cached at");
    }
    /** @param label Timing value. @param instant Fixed timestamp. @param caption Meaning of the timestamp. */
    private static void timestamp(JLabel label, Instant instant, String caption) { timingValue(label, COMPACT_TIME.format(instant), caption + ": " + TIME.format(instant)); }
    /** @param caption Timing meaning. @param value Fixed timestamp. @return Compact native label/value pair. */
    private static JPanel timing(String caption, JLabel value) {
        var group = new JPanel(new BorderLayout(0, 2)); group.add(new JLabel(caption), BorderLayout.NORTH); group.add(value);
        value.setFont(value.getFont().deriveFont(Font.BOLD)); value.getAccessibleContext().setAccessibleName(caption);
        return group;
    }
    /** @param label Timing value. @param value Compact timestamp. @param exact Plain-text full timestamp, also exposed to assistive technology. */
    private static void timingValue(JLabel label, String value, String exact) {
        label.setText(value); label.getAccessibleContext().setAccessibleDescription(exact);
        var group = (JPanel) label.getParent(); group.setToolTipText(exact);
        for (var child : group.getComponents()) if (child instanceof JLabel part) part.setToolTipText(exact);
    }
    /** @param rows Owned display list. @param name User-defined credential name. @param source Configured source. @param value Captured value; null is omitted. */
    private static void add(List<Credential> rows, String name, JourneyDefinition.Extraction source, String value) { if (value != null) rows.add(new Credential(source instanceof JourneyDefinition.CookieExtraction ? "Cookie" : "Token", source instanceof JourneyDefinition.CookieExtraction cookie && !cookie.name().equals(name) ? name + " (" + cookie.name() + ")" : name, source instanceof JourneyDefinition.CookieExtraction cookie ? cookie.name() : name, value)); }
    /** Owns an inspection-only value whose diagnostic representation is deliberately redacted. */
    private record Credential(String type, String name, String copyName, String value, boolean copyable, String details) {
        Credential(String type, String name, String copyName, String value) { this(type,name,copyName,value,true,null); }
        /** @return Metadata-free diagnostic label without any captured credential. */ @Override public String toString() { return "CachedCredential[redacted]"; }
    }
    /** Read-only rows for the explicitly opened cache viewer. */
    private static final class Model extends AbstractTableModel {
        List<Credential> rows = List.of();
        /** @return Captured configured credential count. */ @Override public int getRowCount() { return rows.size(); }
        /** @return Type, name and value columns. */ @Override public int getColumnCount() { return 3; }
        /** @param column Visible column. @return User-facing caption. */ @Override public String getColumnName(int column) { return switch (column) { case 0 -> "Type"; case 1 -> "Name"; default -> "Value"; }; }
        /** @param row Captured credential. @param column Visible column. @return Inspection-only value or label, never used as a log message. */ @Override public Object getValueAt(int row, int column) { var credential = rows.get(row); return switch (column) { case 0 -> credential.type(); case 1 -> credential.name(); default -> credential.value(); }; }
    }
    /** Treats token/cookie text as literal data, including HTML-looking values. */
    private static final class PlainRenderer extends DefaultTableCellRenderer {
        /** @return Native themed cell with literal text; HTTP status details are available on hover over its origin. */ @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focus, int row, int column) {
            putClientProperty("html.disable", true); super.getTableCellRendererComponent(table, value, selected, focus, row, column); setText(String.valueOf(value));
            var credential = ((Model)table.getModel()).rows.get(table.convertRowIndexToModel(row));
            setToolTipText(table.convertColumnIndexToModel(column) == 2 ? credential.details() : null); return this;
        }
    }
}

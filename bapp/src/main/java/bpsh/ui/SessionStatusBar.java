package bpsh.ui;

import java.awt.*;
import java.util.Objects;
import java.util.function.LongSupplier;
import javax.swing.*;

/** Journey dock/action toolbar; controller state is retained without displaying a status message. */
final class SessionStatusBar extends JPanel {
    private final JToggleButton eventLog = new ActivityButton("Event log");
    private final JToggleButton cache = new JToggleButton("Journey cache");
    private final JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
    private final LongSupplier clock;
    private Runnable toggleLog = () -> {};
    private Object context;
    private String state = "Loading journeys...", stateDetails = "", feedback;
    private long expires;
    private boolean persistent, wasActive;
    private final java.util.Set<Object> logAttention = new java.util.HashSet<>();

    /** Uses the controller's existing refresh timer to expire notices. */
    SessionStatusBar() { this(System::nanoTime); }
    /** @param clock Monotonic nanoseconds for deterministic notice expiry. */
    SessionStatusBar(LongSupplier clock) {
        super(new BorderLayout(8, 0)); this.clock = clock;
        getAccessibleContext().setAccessibleName("Journey actions");
        eventLog.setToolTipText("Show this journey's event history."); eventLog.addActionListener(e -> { if (eventLog.isSelected()) { cache.setSelected(false); logAttention.remove(context); } refreshLogAttention(); toggleLog.run(); });
        cache.setToolTipText("Inspect the selected journey's cached tokens, cookies and expiry without logging in."); cache.addActionListener(e -> { if (cache.isSelected()) eventLog.setSelected(false); toggleLog.run(); });
        var views = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0)); views.add(eventLog); views.add(cache);
        add(views, BorderLayout.WEST); add(actions, BorderLayout.EAST); refreshPresentation(); render();
    }
    /** @param button Owned context-sensitive action; caller controls its visibility. */
    void addAction(JButton button) { actions.add(button); }
    /** @param toggle Shows or hides the event dock using isLogOpen(). */
    void onLogToggle(Runnable toggle) { toggleLog = toggle; }
    /** @return Whether the journey event dock was requested. */
    boolean isLogOpen() { return eventLog.isSelected(); }
    /** @param open Dock visibility, synchronized when its close icon is used. */
    void setLogOpen(boolean open) { eventLog.setSelected(open); if (open) { cache.setSelected(false); logAttention.remove(context); } refreshLogAttention(); }
    /** @param owner Journey whose explicit test has log activity; never opens or switches the visible dock. */
    void highlightLog(Object owner) { if (owner != null && (!Objects.equals(owner, context) || !isLogOpen())) logAttention.add(owner); refreshLogAttention(); }
    /** @return Whether explicit cache inspection was requested. */
    boolean isCacheOpen() { return cache.isSelected(); }
    /** @param open Cache dock visibility; opening it closes the event-log view. */
    void setCacheOpen(boolean open) { cache.setSelected(open); if (open) eventLog.setSelected(false); }
    /** @param enabled Whether exactly one reviewed saved journey is selected. */
    void cacheAvailable(boolean enabled) { cache.setEnabled(enabled); }
    /** @param enabled Whether a journey owns the displayed history. @param count Unfiltered retained event count. */
    void logCount(boolean enabled, int count) { eventLog.setEnabled(enabled); eventLog.setText(count == 0 ? "Event log" : "Event log (" + count + ")"); }
    /** @param context Selected journey/page; old transient results never carry into another context. */
    void context(Object context) { if (!Objects.equals(this.context, context)) { this.context = context; feedback = null; wasActive = false; if (isLogOpen()) logAttention.remove(context); refreshLogAttention(); } }
    /** @param message Current safe state. @param guidance Full safe problem/recovery text. @param active Whether a new attempt supersedes old feedback. */
    void state(String message, String guidance, boolean active) {
        if (active && !wasActive) feedback = null;
        wasActive = active; state = message; stateDetails = guidance == null ? "" : guidance; render();
    }
    /** @param message Safe controller-observable confirmation, retained for four seconds without visible output. */
    void setText(String message) { feedback = message; persistent = false; expires = clock.getAsLong() + 4_000_000_000L; render(); }
    /** @param message Safe actionable error; its full explanation belongs to the event log or inline input guidance. */
    void error(String message) { feedback = message; persistent = true; render(); }
    /** Clears an obsolete action result. */
    void clear() { feedback = null; render(); }
    /** @return Current safe message for controller checks and accessible context, never visible toolbar text. */
    String getText() { return feedback != null && (persistent || expires - clock.getAsLong() > 0) ? feedback : stateDetails.isBlank() ? state : stateDetails; }
    /** @return Live journey state independently of confirmations. */
    String stateText() { return state; }
    /** Relayouts native buttons after a host font/theme change without reserving space for a message. */
    void refreshPresentation() { refreshLogAttention(); revalidate(); }
    /** Uses a native-theme accent and accessible description without adding a message or changing keyboard focus. */
    private void refreshLogAttention() {
        boolean highlighted = context != null && logAttention.contains(context) && !isLogOpen();
        eventLog.putClientProperty("bpsh.logAttention", highlighted);
        eventLog.setToolTipText(highlighted ? "Test login has new events. Open this journey's event log." : "Show this journey's event history.");
        eventLog.getAccessibleContext().setAccessibleDescription(highlighted ? "New test events available" : null); eventLog.repaint();
    }
    /** Paints an attention outline within the existing native button bounds, preserving its layout and focus behavior. */
    private static final class ActivityButton extends JToggleButton {
        /** @param text Existing native action label. */
        ActivityButton(String text) { super(text); }
        /** @param graphics Borrowed graphics; no layout or selection state is changed while painting. */
        @Override protected void paintComponent(Graphics graphics) {
            super.paintComponent(graphics);
            if (!Boolean.TRUE.equals(getClientProperty("bpsh.logAttention"))) return;
            var g = (Graphics2D) graphics.create();
            try {
                Color accent = UIManager.getColor("Component.focusColor");
                if (accent == null) accent = UIManager.getColor("List.selectionBackground");
                g.setColor(accent == null ? getForeground() : accent); g.setStroke(new BasicStroke(2));
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g.drawRoundRect(2, 2, Math.max(0, getWidth() - 5), Math.max(0, getHeight() - 5), 6, 6);
            } finally { g.dispose(); }
        }
    }
    /** Updates nonvisual context; visible feedback belongs to event history or inline field guidance. */
    private void render() {
        if (feedback != null && !persistent && expires - clock.getAsLong() <= 0) feedback = null;
        getAccessibleContext().setAccessibleDescription(getText());
    }
}

package bpsh.burp.ui;

import java.util.Objects;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** Adapts all Swing document changes to the same callback. */
final class DocumentChangeListener implements DocumentListener {
    private final Runnable onChange;

    DocumentChangeListener(Runnable onChange) {
        this.onChange = Objects.requireNonNull(onChange);
    }

    @Override
    public void insertUpdate(DocumentEvent event) { onChange.run(); }

    @Override
    public void removeUpdate(DocumentEvent event) { onChange.run(); }

    @Override
    public void changedUpdate(DocumentEvent event) { onChange.run(); }
}

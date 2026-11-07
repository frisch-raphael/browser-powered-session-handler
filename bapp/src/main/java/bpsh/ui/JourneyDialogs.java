package bpsh.ui;

import java.awt.*;
import java.nio.file.Path;
import java.util.List;
import javax.swing.*;

/** Isolates modal decisions from storage actions so cancellation and preview flows can be exercised locally. */
public interface JourneyDialogs {
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

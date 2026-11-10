package bpsh.burp.ui;

import javax.swing.JTabbedPane;

/** Tests address user-visible pages by name because optional pages have no fixed tab index. */
final class WizardTestPages {
    private WizardTestPages() { }
    static void select(JTabbedPane pane,String title) {
        int index=pane.indexOfTab(title);
        org.junit.jupiter.api.Assertions.assertTrue(index>=0,"Expected visible page: "+title);
        pane.setSelectedIndex(index);
    }
    static String selected(JTabbedPane pane) {return pane.getTitleAt(pane.getSelectedIndex());}
}

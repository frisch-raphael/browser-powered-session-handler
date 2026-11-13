package lab.auth.gui;

import java.util.List;
import javax.swing.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiSelectorsTest {
    @Test void historyRowSelectionUsesTheReadOnlyMethodHeaderAfterColumnReordering() {
        HostGuiSelectors.edt(()->{
            var table=new JTable(new javax.swing.table.DefaultTableModel(new Object[][]{{"1 dropdown","localhost","GET","/synthetic-nonce"}},
                    new Object[]{"#","Host","Method","URL"}){@Override public boolean isCellEditable(int row,int column){return false;}});
            assertEquals(2,HostGuiSelectors.historySelectionColumn(table,0));assertEquals(-1,table.getSelectedRow());
            table.moveColumn(2,0);assertEquals(0,HostGuiSelectors.historySelectionColumn(table,0));
            assertEquals("GET",table.getValueAt(0,HostGuiSelectors.historySelectionColumn(table,0)));
            table.moveColumn(0,3);assertEquals(3,HostGuiSelectors.historySelectionColumn(table,0));
            assertEquals(-1,table.getSelectedRow());return true;
        });
    }
    @Test void historySelectionNeverFallsBackToAnActionCellMissingAmbiguousOrEditableMethod() {
        HostGuiSelectors.edt(()->{
            var missing=new JTable(new javax.swing.table.DefaultTableModel(new Object[][]{{"1 dropdown","/synthetic-nonce"}},new Object[]{"#","URL"}){
                @Override public boolean isCellEditable(int row,int column){return false;}});
            assertEquals("GUI_HISTORY_METHOD_MISSING",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.historySelectionColumn(missing,0)).getMessage());
            var duplicate=new JTable(new javax.swing.table.DefaultTableModel(new Object[][]{{"GET","POST","/synthetic-nonce"}},new Object[]{"Method","Method","URL"}){
                @Override public boolean isCellEditable(int row,int column){return false;}});
            assertEquals("GUI_HISTORY_METHOD_AMBIGUOUS",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.historySelectionColumn(duplicate,0)).getMessage());
            var editable=new JTable(new Object[][]{{"GET","/synthetic-nonce"}},new Object[]{"Method","URL"});
            assertEquals("GUI_HISTORY_METHOD_EDITABLE",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.historySelectionColumn(editable,0)).getMessage());
            assertEquals("GUI_HISTORY_ROW_MISSING",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.historySelectionColumn(editable,-1)).getMessage());
            assertEquals("GUI_HISTORY_ROW_MISSING",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.historySelectionColumn(editable,1)).getMessage());
            return true;
        });
    }
    private enum UrlChoice { BURP_SCOPE, ALL_REQUESTS, SINGLE_URL }
    @Test void ownedComboPopupResolvesExactEnumItemWithoutKeyboardFocusOrModelMutation() {
        HostGuiSelectors.edt(()->{
            var combo=new JComboBox<>(UrlChoice.values());combo.setFocusable(false);
            var popup=showingPopup(combo);var list=new JList<>(combo.getModel()){@Override public boolean isShowing(){return true;}};popup.add(list);
            for(int i=0;i<UrlChoice.values().length;i++) {
                var choice=HostGuiSelectors.comboChoice(popup,combo,UrlChoice.values()[i].name());
                assertSame(list,choice.list());assertEquals(i,choice.row());
            }
            assertFalse(combo.isFocusable());assertSame(UrlChoice.BURP_SCOPE,combo.getSelectedItem());return true;
        });
    }
    @Test void comboPopupRejectsForeignOwnershipMissingItemsAndDuplicateTargets() {
        HostGuiSelectors.edt(()->{
            var combo=new JComboBox<>(new String[]{"same","same"});var popup=showingPopup(combo);
            popup.add(new JList<>(combo.getModel()){@Override public boolean isShowing(){return true;}});
            assertEquals("GUI_CONTROL_AMBIGUOUS",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.comboChoice(popup,combo,"same")).getMessage());
            assertEquals("GUI_CONTROL_MISSING",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.comboChoice(popup,combo,"missing")).getMessage());
            assertEquals("GUI_POPUP_CONTEXT",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.comboChoice(popup,new JComboBox<>(),"same")).getMessage());return true;
        });
    }
    @Test void fieldCaptionAndItsLabelledInputAreOneTargetWhileDistinctFieldsStayAmbiguous() {
        HostGuiSelectors.edt(()->{
            var panel=showingPanel();var password=new JPasswordField(){@Override public boolean isShowing(){return true;}};
            var caption=new JLabel("Secure value"){@Override public boolean isShowing(){return true;}};
            caption.setLabelFor(password);panel.add(caption);panel.add(password);
            assertEquals("Secure value",password.getAccessibleContext().getAccessibleName());
            assertSame(password,HostGuiSelectors.field(panel,"Secure value"));
            var other=new JPasswordField(){@Override public boolean isShowing(){return true;}};
            var otherCaption=new JLabel("Secure value"){@Override public boolean isShowing(){return true;}};
            otherCaption.setLabelFor(other);panel.add(otherCaption);panel.add(other);
            assertEquals("GUI_CONTROL_AMBIGUOUS",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.field(panel,"Secure value")).getMessage());return true;
        });
    }
    @Test void fieldCaptionCannotTargetHiddenOrForeignInputsAndNamedStatusRemainsReadable() {
        HostGuiSelectors.edt(()->{
            var panel=showingPanel();var hidden=new JTextField();panel.add(hidden);
            var caption=new JLabel("Value"){@Override public boolean isShowing(){return true;}};
            caption.setLabelFor(hidden);panel.add(caption);
            assertEquals("GUI_CONTROL_MISSING",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.field(panel,"Value")).getMessage());
            var foreign=new JTextField(){@Override public boolean isShowing(){return true;}};caption.setLabelFor(foreign);
            assertEquals("GUI_CONTROL_MISSING",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.field(panel,"Value")).getMessage());
            var status=new JLabel("Ready"){@Override public boolean isShowing(){return true;}};
            status.setName("authlab.observation.status");panel.add(status);
            assertSame(status,HostGuiSelectors.field(panel,"authlab.observation.status"));return true;
        });
    }
    @Test void customActionCaptionRequiresPublicMouseHandlingAndPreservesAmbiguity() {
        HostGuiSelectors.edt(()->{
            var panel=showingPanel();var caption=new JLabel("Send"){@Override public boolean isShowing(){return true;}};panel.add(caption);
            assertEquals("GUI_CONTROL_MISSING",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.actionControl(panel,"Send")).getMessage());
            var control=showingPanel();panel.remove(caption);control.add(caption);panel.add(control);
            control.addMouseListener(new java.awt.event.MouseAdapter(){});
            assertSame(caption,HostGuiSelectors.actionControl(panel,"Send"));assertTrue(HostGuiSelectors.actionEnabled(caption));
            control.setEnabled(false);assertFalse(HostGuiSelectors.actionEnabled(caption));control.setEnabled(true);
            panel.add(new JButton("Send"){@Override public boolean isShowing(){return true;}});
            assertEquals("GUI_CONTROL_AMBIGUOUS",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.actionControl(panel,"Send")).getMessage());return true;
        });
    }
    @Test void buttonCaptionDoesNotCreateASecondActionTargetInsideItsButton() {
        HostGuiSelectors.edt(()->{
            var panel=showingPanel();var button=new JButton("Send"){@Override public boolean isShowing(){return true;}};
            button.add(new JLabel("Send"){@Override public boolean isShowing(){return true;}});panel.add(button);
            assertSame(button,HostGuiSelectors.actionControl(panel,"Send"));return true;
        });
    }
    @Test void requestEditorNeedsNoSwingTabbedPaneAndRejectsReadOnlyOrAmbiguousFields() {
        HostGuiSelectors.edt(()->{
            var panel=new JPanel();var request=new JTextArea("GET / HTTP/1.1\nHost: localhost\n\n"){@Override public boolean isShowing(){return true;}};
            var response=new JTextArea("HTTP/1.1 401 Unauthorized\n\n"){@Override public boolean isShowing(){return true;}};
            response.setEditable(false);panel.add(request);panel.add(response);assertSame(request,HostGuiSelectors.requestEditor(panel));
            request.setEditable(false);assertEquals("GUI_REQUEST_EDITOR_READ_ONLY",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.requestEditor(panel)).getMessage());
            request.setEditable(true);panel.add(new JTextArea(request.getText()){@Override public boolean isShowing(){return true;}});
            assertEquals("GUI_CONTROL_AMBIGUOUS",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.requestEditor(panel)).getMessage());return true;
        });
    }
    @Test void nativeExtensionLoadingErrorsAreClassifiedWithoutPublishingTheStackTrace() {
        assertEquals("GUI_EXTENSION_HEAP_EXHAUSTED",HostGuiSelectors.extensionFailure("Error loading extension",List.of("java.lang.OutOfMemoryError: Java heap space\nPRIVATE_SENTINEL")));
        assertEquals("GUI_EXTENSION_LOAD_FAILED",HostGuiSelectors.extensionFailure("Error loading extension",List.of("PRIVATE_SENTINEL")));
        assertNull(HostGuiSelectors.extensionFailure("Other dialog",List.of("java.lang.OutOfMemoryError: Java heap space")));
    }
    @Test void journeyPopupCanBeOutsideTheFrameTreeAndStillBelongToItsExactInvoker() {
        HostGuiSelectors.edt(()->{
            var frame=showingPanel();var actions=new JButton("Journey actions");frame.add(actions);
            var popupWindow=showingPanel();var menu=showingPopup(actions);var item=new JMenuItem("Import journeys..."){
                @Override public boolean isShowing(){return true;}};
            menu.add(item);popupWindow.add(menu);
            assertFalse(HostGuiSelectors.all(frame).contains(menu),"The native popup is not a descendant of the suite frame");
            assertSame(menu,HostGuiSelectors.popupMenu(actions,List.of(frame,popupWindow)));
            assertSame(item,HostGuiSelectors.button(menu,"Import journeys..."));return true;
        });
    }
    @Test void popupWithTheSameCaptionButAnotherInvokerCannotBeSelected() {
        HostGuiSelectors.edt(()->{
            var actions=new JButton("Journey actions");var popupWindow=showingPanel();
            var other=showingPopup(new JButton("Other actions"));other.add(new JMenuItem("Import journeys..."));popupWindow.add(other);
            assertEquals("GUI_CONTROL_MISSING",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.popupMenu(actions,List.of(popupWindow))).getMessage());return true;
        });
    }
    @Test void duplicateShowingPopupsForOneInvokerAreAmbiguousAndHiddenPopupsAreIgnored() {
        HostGuiSelectors.edt(()->{
            var actions=new JButton("Journey actions");var first=showingPanel();var second=showingPanel();
            first.add(showingPopup(actions));second.add(showingPopup(actions));
            assertEquals("GUI_CONTROL_AMBIGUOUS",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.popupMenu(actions,List.of(first,second))).getMessage());
            var hidden=showingPanel();var hiddenMenu=new JPopupMenu(){@Override public boolean isShowing(){return false;}};
            hiddenMenu.setInvoker(actions);hidden.add(hiddenMenu);
            assertSame(first.getComponent(0),HostGuiSelectors.popupMenu(actions,List.of(first,hidden)));return true;
        });
    }
    @Test void nonfocusablePopupUsesItsNearestFocusableOwnerWithoutChangingItsTarget() {
        var frame=new FocusNode(true,null);var ownerPopup=new FocusNode(false,frame);var popup=new FocusNode(false,ownerPopup);
        assertSame(frame,HostGuiSelectors.focusWindow(popup,frame,node->node.owner,node->node.focusable));
        assertSame(ownerPopup,popup.owner,"Selecting the focus owner must not replace the popup target or ownership");
        var focusableOwner=new FocusNode(true,frame);var nested=new FocusNode(false,focusableOwner);
        assertSame(focusableOwner,HostGuiSelectors.focusWindow(nested,frame,node->node.owner,node->node.focusable));
    }
    @Test void ordinaryWindowsKeepTheirOwnFocusRequirementAndForeignPopupOwnershipIsRejected() {
        var frame=new FocusNode(true,null);var dialog=new FocusNode(true,frame);var disabled=new FocusNode(false,frame);
        assertSame(dialog,HostGuiSelectors.focusWindow(dialog,null,node->node.owner,node->node.focusable));
        assertEquals("GUI_FOCUS_FAILED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiSelectors.focusWindow(disabled,null,node->node.owner,node->node.focusable)).getMessage());
        var foreign=new FocusNode(true,null);var popup=new FocusNode(false,foreign);
        assertEquals("GUI_FOCUS_FAILED",assertThrows(HostGuiSelectors.Failure.class,
                ()->HostGuiSelectors.focusWindow(popup,frame,node->node.owner,node->node.focusable)).getMessage());
    }
    private static JPanel showingPanel(){return new JPanel(){@Override public boolean isShowing(){return true;}};}
    private static JPopupMenu showingPopup(java.awt.Component invoker){
        var menu=new JPopupMenu(){@Override public boolean isShowing(){return true;}};menu.setInvoker(invoker);return menu;
    }
    private static final class FocusNode {
        final boolean focusable;final FocusNode owner;
        FocusNode(boolean focusable,FocusNode owner){this.focusable=focusable;this.owner=owner;}
    }
    @Test void nativeUnloadConfirmationRequiresTheExactHeadingAndTargetExtension() {
        HostGuiSelectors.edt(()->{
            var panel=new JPanel();var heading=new JLabel("Unload extension"){@Override public boolean isShowing(){return true;}};
            var body=new JTextArea("Are you sure you want to unload \"Browser Powered Session\nHandler\"?"){@Override public boolean isShowing(){return true;}};
            body.setEditable(false);panel.add(heading);panel.add(body);panel.add(new JButton("Yes"));
            assertTrue(HostGuiSelectors.unloadConfirmation(panel,"Browser Powered Session Handler"));
            assertFalse(HostGuiSelectors.unloadConfirmation(panel,"Other extension"));
            heading.setText("Another confirmation");assertFalse(HostGuiSelectors.unloadConfirmation(panel,"Browser Powered Session Handler"));return true;
        });
    }
    @Test void extensionFilenameUsesFullPublicTableModelDespiteTruncatedRenderer() {
        HostGuiSelectors.edt(()->{
            var panel=new JPanel();String full=java.nio.file.Path.of("build","owned","assets","long-filename.jar").toAbsolutePath().toString();
            var table=new JTable(new Object[][]{{"Name","Browser Powered Session Handler"},{"Filename",full}},new Object[]{"Item","Detail"}){
                @Override public boolean isShowing(){return true;}};
            table.setDefaultRenderer(Object.class,(t,value,selected,focus,row,column)->new JLabel(column==1?"truncated...":String.valueOf(value)));
            panel.add(table);assertEquals(full,HostGuiSelectors.extensionFilename(panel));return true;
        });
    }
    @Test void nativePathComparisonAcceptsNormalizationAndOnlyNativeCaseSemantics() {
        var expected=java.nio.file.Path.of("build","owned","assets","file.jar").toAbsolutePath();
        assertTrue(HostGuiSelectors.filePathMatches(expected.getParent().resolve("unused/../file.jar").toString(),expected));
        assertFalse(HostGuiSelectors.filePathMatches("file.jar",expected));assertFalse(HostGuiSelectors.filePathMatches(expected+".bak",expected));
        boolean windows=System.getProperty("os.name").startsWith("Windows");
        assertEquals(windows,HostGuiSelectors.filePathMatches(expected.toString().toUpperCase(java.util.Locale.ROOT),expected));
    }
    @Test void boundedDiagnosticQueryDoesNotExecuteLaterAfterTimingOut() throws Exception {
        var entered=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);
        var queried=new java.util.concurrent.atomic.AtomicBoolean();
        SwingUtilities.invokeLater(()->{entered.countDown();try{release.await(2,java.util.concurrent.TimeUnit.SECONDS);}catch(InterruptedException stopped){Thread.currentThread().interrupt();}});
        try {
            assertTrue(entered.await(2,java.util.concurrent.TimeUnit.SECONDS));
            assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.edt(()->{queried.set(true);return true;},100));
        }finally{release.countDown();}
        HostGuiSelectors.edt(()->true);assertFalse(queried.get());
    }
    @Test void duplicateAndMissingControlsFailBeforeAnyInput() {
        HostGuiSelectors.edt(()->{
            var panel=new JPanel();panel.add(new JButton("Send"));panel.add(new JButton("Send"));
            assertEquals("GUI_CONTROL_AMBIGUOUS",assertThrows(HostGuiSelectors.Failure.class,
                    ()->HostGuiSelectors.find(panel,c->"Send".equals(HostGuiSelectors.label(c)),false)).getMessage());
            assertEquals("GUI_CONTROL_MISSING",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.unique(List.of())).getMessage());return true;
        });
    }
    @Test void namedAndLabelLinkedControlsUsePublicComponentState() {
        HostGuiSelectors.edt(()->{
            var panel=new JPanel();var field=new JTextField();field.setName("expected-input");panel.add(field);
            assertSame(field,HostGuiSelectors.find(panel,c->HostGuiSelectors.named(c,"expected-input"),false));
            assertFalse(HostGuiSelectors.named(field,"other-input"));return true;
        });
    }
    @Test void edtFailuresNeverRetainPrivateExceptionMessages() {
        var failure=assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.edt(()->{throw new IllegalStateException("SECRET_SENTINEL");}));
        assertEquals("GUI_EDT_QUERY_FAILED",failure.getMessage());assertNull(failure.getCause());
    }
    @Test void disabledAndHiddenControlsAreRejectedBeforeInput() {
        HostGuiSelectors.edt(()->{
            var button=new JButton("Send"){@Override public boolean isShowing(){return true;}};button.setSize(100,30);
            button.setEnabled(false);assertEquals("GUI_CONTROL_UNAVAILABLE",assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.requireAvailable(button)).getMessage());
            button.setEnabled(true);assertDoesNotThrow(()->HostGuiSelectors.requireAvailable(button));
            assertThrows(HostGuiSelectors.Failure.class,()->HostGuiSelectors.requireAvailable(new JButton("Hidden")));return true;
        });
    }
}

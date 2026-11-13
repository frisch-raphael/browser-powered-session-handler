package lab.auth.gui;

import com.google.gson.*;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.text.JTextComponent;
import lab.auth.*;
import static lab.auth.gui.HostGuiSelectors.*;

/** Finite real-input operations in one owned Burp JVM. No product classes are imported. */
public final class HostGuiDriver {
    interface Input {
        void click(Component component,Point relative);void keys(int... keys);void text(String text);
        default void bindOperationGuard(Runnable guard){}
        default void external(Runnable nativeGuard,Runnable action){throw new Failure("GUI_BROWSER_INPUT_UNSUPPORTED");}
        default void scroll(Component component,int units){throw new Failure("GUI_SCROLL_UNSUPPORTED");}
        default JsonObject pointerState(){return new JsonObject();}
    }
    private final LabHostGuiProtocol.Session session;
    private final Input input;
    private final Clock clock;
    private volatile Window frame;
    private HostGuiBrowserRuntime browserRuntime;
    private HostGuiBrowserRuntime browserRuntime(){if(browserRuntime==null)browserRuntime=new HostGuiBrowserRuntime(this);return browserRuntime;}
    private final Map<String,String> importedNames=new HashMap<>();
    private LabHostGuiProtocol.Command activeCommand;
    private JsonObject controlState=new JsonObject();
    private long deadline;
    public HostGuiDriver(LabHostGuiProtocol.Session session) throws AWTException {this(session,new RobotInput(),Clock.systemUTC());}
    HostGuiDriver(LabHostGuiProtocol.Session session,Input input,Clock clock){this.session=session;this.input=input;this.clock=clock;input.bindOperationGuard(this::check);}
    public void run() throws IOException,InterruptedException {
        Path commands=session.root().resolve("gui/commands");Files.createDirectories(commands);Files.createDirectories(session.root().resolve("gui/receipts"));
        long sequence=1;
        while(!Files.exists(session.root().resolve("cancel"))) {
            Path file=commands.resolve(String.format(Locale.ROOT,"%06d.json",sequence));
            if(!Files.isRegularFile(file)){Thread.sleep(100);continue;}
            var command=LabHostGuiProtocol.command(LabJson.read(file,65536),session);
            var claim=LabHostGuiProtocol.claim(session,command,sequence,clock.millis());
            if(claim.state()==LabHostGuiProtocol.ClaimState.AMBIGUOUS)throw new Failure("GUI_AMBIGUOUS_CLAIM");
            if(claim.state()==LabHostGuiProtocol.ClaimState.NEW) {
                long began=clock.millis();JsonObject observed=new JsonObject();String outcome="PASS",code="GUI_OPERATION_COMPLETED";
                try {deadline=command.deadlineEpochMs();observed=perform(command);}
                catch(Failure failed){outcome=failed.getMessage().equals("GUI_CANCELLED")?"CANCELLED":"FAIL";code=failed.getMessage();
                    if(frame!=null)try{observed=HostGuiDiagnostics.capture(frame);}catch(RuntimeException unavailable){/* Preserve the primary fixed failure. */}}
                catch(RuntimeException|IOException failed){outcome="FAIL";code="GUI_OPERATION_FAILED";}
                LabJson.writeNew(claim.receipt(),LabHostGuiProtocol.receipt(session,command,began,clock.millis(),outcome,code,observed));
                if(!outcome.equals("PASS")) {
                    HostGuiDiagnostics.privateProductSource(session.root(),command.operationId());
                    controlState.add("lastPointer",input.pointerState());
                    HostGuiDiagnostics.privateControls(session.root(),command.operationId(),frame,controlState);
                    HostGuiDiagnostics.privateFailureSignals(session.root(),command.operationId(),frame);
                    HostGuiDiagnostics.privateThreads(session.root(),command.operationId());
                    HostGuiDiagnostics.privateLoadingFrames(session.root(),command.operationId());
                    HostGuiDiagnostics.privateScreenshot(session.root(),command.operationId(),frame);
                    try{Files.writeString(claim.receipt().resolveSibling(command.operationId()+".diagnostics"),"",StandardOpenOption.CREATE_NEW);}
                    catch(IOException unavailable){/* Diagnostic completion is optional; the owner has a finite grace. */}
                    return;
                }
            }
            sequence++;
            if(command.operation()==LabHostGuiProtocol.Operation.CLOSE)return;
        }
    }
    JsonObject perform(LabHostGuiProtocol.Command command) throws IOException {
        deadline=command.deadlineEpochMs();activeCommand=command;controlState=new JsonObject();check();phase("START");var args=command.arguments();var result=new JsonObject();
        if(command.operation()==LabHostGuiProtocol.Operation.READY){ready();result.addProperty("ready",true);return result;}
        if(frame==null)throw new Failure("GUI_NOT_READY");
        switch(command.operation()) {
            case OPEN_TOOL -> {openTool(LabJson.text(args,"tool"));result.addProperty("tool",LabJson.text(args,"tool"));}
            case SET_INTERCEPT -> {intercept(args.get("enabled").getAsBoolean());result.addProperty("enabled",args.get("enabled").getAsBoolean());}
            case SET_PRODUCT_LOADED -> {boolean enabled=args.get("enabled").getAsBoolean();loaded(enabled);if(enabled){until(HostGuiDiagnostics::productSourceMatched,"GUI_EXTENSION_ARTIFACT_DEADLINE");result.addProperty("productSourceMatched",true);}result.addProperty("enabled",enabled);}
            case IMPORT_JOURNEY -> {importJourney(LabJson.owned(session.root(),LabJson.text(args,"path")),LabJson.text(args,"alias"));result.addProperty("imported",true);}
            case ENTER_SECRET -> {enterSecret(LabJson.text(args,"alias"),LabJson.text(args,"secret"));result.addProperty("secretEntered",true);}
            case TEST_BROWSER_LOGIN -> {result=browserRuntime().test(LabJson.text(args,"alias"));}
            case RECORD_BROWSER_LOGIN -> {result=browserRuntime().record(LabJson.text(args,"alias"),LabJson.text(args,"secret"));}
            case FINISH_BROWSER_RECORDING -> {result=browserRuntime().finish(LabJson.text(args,"alias"));}
            case BROWSER_SETTINGS -> {result=browserRuntime().settings(LabJson.text(args,"alias"),LabJson.text(args,"theme"),LabJson.text(args,"size"));}
            case TEST_LOGIN -> {result.addProperty("httpProtocol",testHttpLogin(LabJson.text(args,"alias")));result.addProperty("loginResult","HTTP_AUTHENTICATED");}
            case EDIT_RULES -> {boolean rejected=new HostGuiRules(this).apply(LabJson.owned(session.root(),LabJson.text(args,"path")));
                result.addProperty(rejected?"validationRejected":"rulesConfigured",true);}
            case CAPTURE_PROBE -> {new HostGuiProbe(this).capture(LabJson.text(args,"phase"),LabJson.owned(session.root(),LabJson.text(args,"path")));
                if(LabJson.text(args,"phase").equals("EXPORT"))HostGuiDiagnostics.privateFailureSignals(session.root(),command.operationId(),frame);
                result.addProperty("captureCompleted",true);}
            case ASSERT_UI -> {new HostGuiAssertions(this).verify(LabJson.text(args,"alias"),LabJson.text(args,"code"),args.has("nonce")?LabJson.text(args,"nonce"):null);
                result.addProperty("assertionObserved",true);result.addProperty("assertionCode",LabJson.text(args,"code"));
                if(args.has("nonce"))result.addProperty("nonce",LabJson.text(args,"nonce"));}
            case SET_REPEATER_REQUEST -> {
                openTool("REPEATER");String request=Files.readString(LabJson.owned(session.root(),LabJson.text(args,"path")));
                if(request.length()>65536||!request.contains(LabJson.text(args,"nonce")))throw new Failure("GUI_REQUEST_INPUT");
                var editor=rawRequestEditor();
                replace(editor,request);result.addProperty("nonce",LabJson.text(args,"nonce"));result.addProperty("length",request.length());
            }
            case SET_REPEATER_NONCE -> {
                openTool("REPEATER");String previous=LabJson.text(args,"previousNonce"),next=LabJson.text(args,"nonce");awaitNonce(previous);
                var editor=rawRequestEditor();String changed=HostGuiMessages.nonce(edt(editor::getText),previous,next);replace(editor,changed);
                result.addProperty("nonce",next);result.addProperty("length",changed.length());
            }
            case ASSERT_REPEATER_RESPONSE -> {
                openTool("REPEATER");String nonce=LabJson.text(args,"nonce");int expected=Math.toIntExact(LabJson.positive(args.get("status")));
                assertRepeaterResponse(nonce,expected);result.addProperty("nonce",nonce);result.addProperty("status",expected);
            }
            case SEND_REPEATER -> {
                openTool("REPEATER");String nonce=LabJson.text(args,"nonce");awaitNonce(nonce);
                click(awaitAction("Send"));result.addProperty("submitted",true);result.addProperty("nonce",nonce);
            }
            case COPY_TO_REPEATER -> {copyToRepeater(LabJson.text(args,"nonce"));result.addProperty("copied",true);}
            case FORWARD_INTERCEPTED_REQUEST -> {openTool("PROXY");awaitNonce(LabJson.text(args,"nonce"));click(awaitAction("Forward"));result.addProperty("forwarded",true);}
            case EDIT_INTERCEPTED_REQUEST -> {openTool("PROXY");awaitNonce(LabJson.text(args,"nonce"));var editor=rawRequestEditor();
                String request=Files.readString(LabJson.owned(session.root(),LabJson.text(args,"path")));if(request.length()>65536)throw new Failure("GUI_REQUEST_INPUT");replace(editor,request);result.addProperty("edited",true);}
            case CLOSE -> {click(edt(()->tabs(frame,"Proxy","Repeater","Extensions")));input.keys(KeyEvent.VK_ALT,KeyEvent.VK_F4);result.addProperty("closeRequested",true);}
            default -> throw new Failure("GUI_OPERATION_NOT_IMPLEMENTED");
        }
        check();return result;
    }
    private void ready() {
        var clicked=new IdentityHashMap<Component,String>();
        until(()->{
            var showing=edt(()->Arrays.stream(Window.getWindows()).filter(Window::isShowing).sorted(Comparator.comparingInt(w->w instanceof Dialog?0:1)).toList());
            boolean modal=edt(()->showing.stream().anyMatch(w->w instanceof Dialog d&&d.isModal()));
            for(Window window:showing) {
                if(modal&&!(window instanceof Dialog))continue;
                var matches=edt(()->all(window).stream().filter(c->c instanceof JTabbedPane p&&p.indexOfTab("Proxy")>=0&&p.indexOfTab("Repeater")>=0&&p.indexOfTab("Extensions")>=0).toList());
                if(matches.size()==1&&!(window instanceof Dialog)){frame=window;return true;}
                for(Component component:edt(()->all(window).stream().filter(c->c.isShowing()&&c.isEnabled()&&(c instanceof AbstractButton||c instanceof JLabel)).toList())) {
                    String label=edt(()->label(component));
                    boolean leave=window instanceof Dialog d&&"Delete old temporary files?".equals(edt(d::getTitle))&&label.equals("Leave");
                    if((Set.of("Next","Start Burp","Continue with Burp Suite Community Edition").contains(label)||leave)&&!label.equals(clicked.get(component))) {
                        clicked.put(component,label);click(component);return false;
                    }
                }
            }
            if(modal)throw new Failure("GUI_MODAL_UNSUPPORTED");
            return false;
        });
    }
    private void openTool(String tool) {
        String title=switch(tool){case "PROXY"->"Proxy";case "REPEATER"->"Repeater";case "EXTENSIONS"->"Extensions";default->"Browser Powered Session Handler";};
        select(edt(()->tabs(frame,"Proxy","Repeater","Extensions")),title);
    }
    private void select(JTabbedPane tabs,String title) {
        Point target=edt(()->{int index=tabs.indexOfTab(title);if(index<0)throw new Failure("GUI_TAB_MISSING");var bounds=tabs.getBoundsAt(index);return new Point(bounds.x+bounds.width/2,bounds.y+bounds.height/2);});
        input.click(tabs,target);until(()->edt(()->tabs.getSelectedIndex()>=0&&title.equals(tabs.getTitleAt(tabs.getSelectedIndex()))));
    }
    void click(Component component) {
        check();if(!edt(()->component.isShowing()&&component.isEnabled()))throw new Failure("GUI_CONTROL_UNAVAILABLE");
        input.click(component,edt(()->new Point(component.getWidth()/2,component.getHeight()/2)));
    }
    private Component awaitAction(String title) {
        final Component[] action={null};until(()->{
            try{action[0]=edt(()->actionControl(frame,title));return edt(()->actionEnabled(action[0]));}
            catch(Failure pending){if(pending.getMessage().equals("GUI_CONTROL_MISSING"))return false;throw pending;}
        });return action[0];
    }
    private void intercept(boolean enabled) {
        openTool("PROXY");select(edt(()->tabs(frame,"Intercept","HTTP history")),"Intercept");
        Component button=edt(()->find(frame,c->c instanceof AbstractButton&&Set.of("Intercept is on","Intercept is off","Intercept on","Intercept off").contains(label(c)),true));
        if(edt(()->label(button).endsWith(" on"))!=enabled)click(button);
        until(()->edt(()->label(button).endsWith(enabled?" on":" off")));
    }
    private void loaded(boolean enabled) {
        phase("SELECT_EXTENSION_ROW");
        openTool("EXTENSIONS");
        var tables=edt(()->all(frame).stream().filter(c->c instanceof JTable t&&t.isShowing()&&column(t,"Loaded")>=0).map(c->(JTable)c).toList());
        JTable table=unique(tables);int row=edt(()->{
            var rows=new ArrayList<Integer>();for(int r=0;r<table.getRowCount();r++)for(int c=0;c<table.getColumnCount();c++)
                if("Browser Powered Session Handler".equals(Objects.toString(table.getValueAt(r,c),""))){rows.add(r);break;}return unique(rows);
        });
        int column=edt(()->column(table,"Loaded"));
        clickCell(table,row,Math.min(column+1,edt(()->table.getColumnCount()-1)));
        String expected=session.root().resolve("assets/"+session.productSha256()+".jar").toString();
        phase("PATH_WITNESS");
        until(()->{
            try {String filename=edt(()->table.getSelectedRow()==row?extensionFilename(frame):null);
                return filePathMatches(filename,Path.of(expected));}
            catch(Failure pending){if(pending.getMessage().equals("GUI_CONTROL_MISSING"))return false;throw pending;}
        },"GUI_EXTENSION_PATH_DEADLINE");
        if(!edt(this::unloadDialogs).isEmpty())throw new Failure("GUI_UNEXPECTED_UNLOAD_CONFIRMATION");
        var loadedToggle=edt(()->(AbstractButton)button(frame,"Extension loaded"));
        boolean change=edt(()->Boolean.TRUE.equals(table.getValueAt(row,column)))!=enabled;
        if(change) {
            if(!enabled) {
                until(()->edt(()->tabs(frame,"Proxy","Repeater","Extensions").indexOfTab("Browser Powered Session Handler")>=0),"GUI_EXTENSION_STARTUP_DEADLINE");
                until(HostGuiDiagnostics::productSourceMatched,"GUI_EXTENSION_ARTIFACT_DEADLINE");
            }
            phase("WAIT_LOADED_CONTROL");
            controlState=edt(()->{
                var state=new JsonObject();state.addProperty("requestedLoaded",enabled);state.addProperty("wasLoaded",Boolean.TRUE.equals(table.getValueAt(row,column)));
                state.addProperty("enabledAtGateEntry",loadedToggle.isEnabled());state.addProperty("clickAttempted",false);return state;
            });
            until(()->edt(()->loadedToggle.isShowing()&&loadedToggle.isEnabled()
                    &&loadedToggle.isSelected()==Boolean.TRUE.equals(table.getValueAt(row,column))),"GUI_EXTENSION_CONTROL_DEADLINE");
            change=edt(()->Boolean.TRUE.equals(table.getValueAt(row,column)))!=enabled;
        }
        if(change) {
            phase("CLICK_LOADED");controlState=edt(()->{
                var state=new JsonObject();state.addProperty("requestedLoaded",enabled);state.addProperty("wasLoaded",Boolean.TRUE.equals(table.getValueAt(row,column)));
                state.addProperty("tableEditableBeforeClick",table.isCellEditable(row,column));state.addProperty("enabledBeforeClick",loadedToggle.isEnabled());
                state.addProperty("focusedBeforeClick",frame.isFocused());state.addProperty("clickAttempted",true);return state;
            });click(loadedToggle);
            if(!enabled) {
                phase("WAIT_UNLOAD_CONFIRMATION");final Window[] confirmation={null};
                until(()->edt(()->{var dialogs=unloadDialogs();if(dialogs.isEmpty())return false;confirmation[0]=unique(dialogs);return true;}),"GUI_UNLOAD_CONFIRMATION_DEADLINE");
                phase("CONFIRM_UNLOAD");click(edt(()->button(confirmation[0],"Yes")));
                until(()->edt(()->!confirmation[0].isShowing()),"GUI_UNLOAD_CONFIRMATION_DEADLINE");
            }
        }
        phase("WAIT_LOADED");
        until(()->edt(()->Boolean.TRUE.equals(table.getValueAt(row,column))==enabled),"GUI_EXTENSION_LOAD_DEADLINE");
        phase("WAIT_SUITE_TAB");
        until(()->edt(()->(tabs(frame,"Proxy","Repeater","Extensions").indexOfTab("Browser Powered Session Handler")>=0)==enabled),"GUI_EXTENSION_TAB_DEADLINE");
        if(enabled) {
            long[] stable={0};until(()->edt(()->{
                boolean present=tabs(frame,"Proxy","Repeater","Extensions").indexOfTab("Browser Powered Session Handler")>=0;
                if(!present){stable[0]=0;return false;}if(stable[0]==0)stable[0]=System.nanoTime();
                return System.nanoTime()-stable[0]>=Duration.ofSeconds(2).toNanos();
            }),"GUI_EXTENSION_TAB_DEADLINE");
        }
        if(!edt(this::unloadDialogs).isEmpty())throw new Failure("GUI_UNEXPECTED_UNLOAD_CONFIRMATION");
    }
    private List<Window> unloadDialogs(){return Arrays.stream(Window.getWindows()).filter(w->w!=frame&&w.isShowing()
            &&unloadConfirmation(w,"Browser Powered Session Handler")).toList();}
    void clickCell(JTable table,int row,int column){var rectangle=edt(()->table.getCellRect(row,column,true));input.click(table,new Point(rectangle.x+rectangle.width/2,rectangle.y+rectangle.height/2));}
    private void importJourney(Path path,String alias) {
        phase("IMPORT_MENU");
        openTool("PRODUCT");select(edt(()->tabs(frame,"Journeys","Session handling","Settings")),"Journeys");
        var actions=edt(()->find(frame,c->c instanceof AbstractButton&&named(c,"Journey actions"),true));
        until(()->edt(actions::isEnabled));click(actions);
        final JPopupMenu[] popup={null};
        until(()->{
            try{popup[0]=edt(()->popupMenu(actions));return true;}
            catch(Failure pending){if(pending.getMessage().equals("GUI_CONTROL_MISSING"))return false;throw pending;}
        });
        click(edt(()->button(popup[0],"Import journeys...")));
        phase("IMPORT_PICKER");
        chooseFile(path);
        phase("IMPORT_PREVIEW");
        final Dialog[] preview=new Dialog[1];
        until(()->{var dialogs=edt(()->Arrays.stream(Window.getWindows()).filter(w->w instanceof Dialog d&&d.isShowing()&&d.getTitle().startsWith("Import journeys into ")).map(w->(Dialog)w).toList());
            if(dialogs.size()!=1)return false;preview[0]=dialogs.getFirst();return true;});
        String displayName=edt(()->{
            JTable table=(JTable)find(preview[0],c->c instanceof JTable t&&column(t,"Tag alias")>=0&&column(t,"Journey")>=0,true);
            if(table.getRowCount()!=1||!alias.equals(table.getValueAt(0,column(table,"Tag alias"))))throw new Failure("GUI_IMPORT_IDENTITY");
            return Objects.toString(table.getValueAt(0,column(table,"Journey")),"");
        });
        click(edt(()->button(preview[0],"Import journeys")));
        phase("IMPORT_SAVED");
        until(()->edt(()->{
            int matches=0;for(Component component:all(frame))if(component instanceof JList<?> list&&list.isShowing())for(int i=0;i<list.getModel().getSize();i++)
                if(displayName.equals(Objects.toString(list.getModel().getElementAt(i),"")))matches++;
            if(matches>1)throw new Failure("GUI_JOURNEY_AMBIGUOUS");return matches==1;
        }));
        importedNames.put(alias,displayName);
    }
    void probeTab() {
        select(edt(()->tabs(frame,"Proxy","Repeater","Extensions")),"Auth lab probe");
        select(edt(()->tabs(frame,"Send once","Observe callbacks")),"Observe callbacks");
    }
    void chooseFile(Path path) {
        final JFileChooser[] chooser=new JFileChooser[1];
        until(()->{var candidates=edt(()->Arrays.stream(Window.getWindows()).filter(Window::isShowing).flatMap(w->all(w).stream())
                .filter(c->c instanceof JFileChooser&&c.isShowing()).map(c->(JFileChooser)c).toList());if(candidates.size()!=1)return false;chooser[0]=candidates.getFirst();return true;});
        var field=edt(()->(JTextComponent)find(chooser[0],c->c instanceof JTextField&&c.isShowing(),true));replace(field,path.toString());
        input.keys(KeyEvent.VK_ENTER);
    }
    void journey(String alias) {
        String displayName=displayName(alias);
        openTool("PRODUCT");select(edt(()->tabs(frame,"Journeys","Session handling","Settings")),"Journeys");
        select(edt(()->tabs(frame,"Project","User")),"Project");
        var list=edt(()->(JList<?>)find(frame,c->c instanceof JList<?> l&&java.util.stream.IntStream.range(0,l.getModel().getSize())
                .anyMatch(i->displayName.equals(Objects.toString(l.getModel().getElementAt(i),""))),true));
        int row=edt(()->{var matches=new ArrayList<Integer>();for(int i=0;i<list.getModel().getSize();i++)
            if(displayName.equals(Objects.toString(list.getModel().getElementAt(i),"")))matches.add(i);return unique(matches);});
        Point point=edt(()->{var cell=list.getCellBounds(row,row);return new Point(cell.x+cell.width/2,cell.y+cell.height/2);});
        if(edt(()->list.getVisibleRect().contains(point)))input.click(list,point);
        else {
            var visible=edt(()->list.getCellBounds(list.getFirstVisibleIndex(),list.getFirstVisibleIndex()).intersection(list.getVisibleRect()));
            input.click(list,new Point(visible.x+visible.width/2,visible.y+visible.height/2));input.keys(KeyEvent.VK_HOME);
            for(int i=0;i<row;i++){check();input.keys(KeyEvent.VK_DOWN);}
        }
        phase("VERIFY_SELECTED_JOURNEY");
        verifyJourneyEditor(frame,list,row,displayName,()->wizard("Setup"),this::until);
    }
    /** Verifies the visible editor after selection, including a journey that remembers another wizard page. */
    static void verifyJourneyEditor(Container root,JList<?> list,int row,String displayName,Runnable showSetup,
                                    java.util.function.Consumer<java.util.function.BooleanSupplier> await) {
        await.accept(()->edt(()->list.getSelectedIndex()==row));
        showSetup.run();
        await.accept(()->{try{return edt(()->list.getSelectedIndex()==row&&field(root,"name") instanceof JTextComponent name
                &&name.isEnabled()&&displayName.equals(name.getText()));}
            catch(Failure pending){if(pending.getMessage().equals("GUI_CONTROL_MISSING"))return false;throw pending;}});
    }
    void wizard(String page){select(edt(()->tabs(frame,"Setup","Test & use")),page);}
    private void enterSecret(String alias,String reference) throws IOException {
        phase("SELECT_JOURNEY");journey(alias);
        var secrets=LabJson.object(LabJson.read(session.root().resolve("fixture-secrets.json"),4096),"FORM_A","FORM_B","HTTP_A","HTTP_B");
        String value=LabJson.text(secrets,reference);
        if(value.isEmpty()||value.length()>128||value.chars().anyMatch(c->c<32||c>126))throw new Failure("GUI_FIXTURE_SECRET");
        JPasswordField password;
        phase("OPEN_SECRET_PAGE");
        if(reference.startsWith("HTTP_")) {
            wizard("HTTP authentication");phase("FIND_SECRET_FIELD");password=edt(()->(JPasswordField)field(frame,"httpPassword"));
        }else {
            wizard("Login steps");
            phase("SELECT_SECRET_STEP");
            var header=edt(()->(JToggleButton)find(frame,c->c instanceof JToggleButton&&label(c).startsWith("Step ")
                    &&label(c).contains("Enter secret")&&label(c).endsWith(" · #pass"),true));
            if(!edt(header::isSelected))click(header);
            phase("FIND_SECRET_FIELD");
            password=edt(()->(JPasswordField)field(frame,"Secure value"));
        }
        phase("TYPE_SECRET");
        click(password);input.keys(KeyEvent.VK_CONTROL,KeyEvent.VK_A);input.text(value);
        char[] expected=value.toCharArray();
        phase("VERIFY_SECRET");
        try{until(()->edt(()->{char[] typed=password.getPassword();try{return Arrays.equals(expected,typed);}finally{Arrays.fill(typed,'\0');}}));}
        finally{Arrays.fill(expected,'\0');}
        phase("OPEN_TEST_PAGE");wizard("Test & use");
    }
    void clickTestLogin(String alias) {
        journey(alias);wizard("Test & use");phase("FIND_TEST_LOGIN");
        final Component[] start={null};until(()->edt(()->{var buttons=all(frame).stream().filter(c->c instanceof AbstractButton&&c.isShowing()
                &&c.isEnabled()&&label(c).equals("Test login")).toList();if(buttons.isEmpty())return false;start[0]=unique(buttons);return true;}));
        phase("CLICK_TEST_LOGIN");click(start[0]);
    }
    Dialog awaitLoginDialog(String title) {
        final Dialog[] success={null};phase("WAIT_LOGIN_RESULT");until(()->edt(()->{
            var dialogs=Arrays.stream(Window.getWindows()).filter(w->w instanceof Dialog d&&d.isShowing()&&d.getTitle().equals(title)).map(w->(Dialog)w).toList();
            if(dialogs.size()>1)throw new Failure("GUI_MODAL_AMBIGUOUS");if(dialogs.size()==1){success[0]=dialogs.getFirst();return true;}
            var errors=all(frame).stream().filter(c->c instanceof JTextComponent&&c.isShowing()&&named(c,"Input error"))
                    .map(c->((JTextComponent)c).getText()).filter(text->!text.isBlank()).toList();
            if(!errors.isEmpty()) {
                controlState.add("loginFailureSignals",LabJson.JSON.toJsonTree(HostGuiDiagnostics.failureSignals(errors)));
                throw new Failure("GUI_TEST_LOGIN_FAILED");
            }return false;
        }));return success[0];
    }
    void closeLoginDialog(Dialog success) {
        var close=edt(()->success instanceof JDialog dialog?dialog.getRootPane().getDefaultButton():null);
        if(close==null)throw new Failure("GUI_DIALOG_ACTION_MISSING");click(close);until(()->edt(()->!success.isShowing()));
    }
    private String testHttpLogin(String alias) {
        clickTestLogin(alias);final Dialog[] success={awaitLoginDialog("HTTP authentication succeeded")};
        String protocol=edt(()->{
            var message=(JTextComponent)find(success[0],c->c instanceof JTextComponent&&named(c,"HTTP authentication succeeded"),true);
            String text=message.getText();
            if(text.contains("HTTP authentication succeeded — Basic."))return "BASIC";
            if(text.contains("HTTP authentication succeeded — NTLMv1."))return "NTLM_V1";
            if(text.contains("HTTP authentication succeeded — NTLMv2."))return "NTLM_V2";
            throw new Failure("GUI_HTTP_PROTOCOL_RESULT");
        });
        closeLoginDialog(success[0]);return protocol;
    }
    private void copyToRepeater(String nonce) {
        openTool("PROXY");select(edt(()->tabs(frame,"Intercept","HTTP history")),"HTTP history");
        JTable table=edt(()->(JTable)find(frame,c->c instanceof JTable t&&t.isShowing()&&column(t,"URL")>=0,true));
        HostGuiHistory.select(table,nonce,input,this::check,this::until);
        awaitNonce(nonce);input.keys(KeyEvent.VK_CONTROL,KeyEvent.VK_R);openTool("REPEATER");awaitNonce(nonce);
    }
    void unchangedRequest(String nonce,String alias) {
        openTool("PROXY");select(edt(()->tabs(frame,"Intercept","HTTP history")),"HTTP history");
        JTable table=edt(()->(JTable)find(frame,c->c instanceof JTable t&&column(t,"URL")>=0,true));
        int selected=HostGuiHistory.select(table,nonce,input,this::check,this::until);awaitNonce(nonce);
        var visible=(java.util.function.BooleanSupplier)()->edt(()->table.getSelectedRow()==selected&&selected<table.getRowCount()
                &&java.util.stream.IntStream.range(0,table.getColumnCount()).anyMatch(column->Objects.toString(table.getValueAt(selected,column),"").contains(nonce))
                &&all(frame).stream().anyMatch(c->c instanceof JTextComponent text&&!(c instanceof JPasswordField)&&c.isShowing()
                    &&HostGuiAssertions.unchangedMessage(alias,text.getText())));
        if(!visible.getAsBoolean()) {
            var notes=edt(()->find(frame,c->{
                if(!named(c,"Notes")&&!label(c).equals("Notes"))return false;
                var context=c.getAccessibleContext();var role=context==null?null:context.getAccessibleRole();
                return c instanceof AbstractButton||c instanceof JLabel||role==javax.accessibility.AccessibleRole.PAGE_TAB
                        ||role==javax.accessibility.AccessibleRole.PUSH_BUTTON||role==javax.accessibility.AccessibleRole.TOGGLE_BUTTON
                        ||role==javax.accessibility.AccessibleRole.CHECK_BOX;
            },true));
            boolean selectedNotes=edt(()->notes instanceof AbstractButton button&&button.isSelected()
                    ||notes.getAccessibleContext()!=null&&notes.getAccessibleContext().getAccessibleStateSet().contains(javax.accessibility.AccessibleState.SELECTED));
            if(!selectedNotes)click(notes);
        }
        until(visible);
    }
    private JTextComponent requireNonce(String nonce) {
        return edt(()->(JTextComponent)find(frame,c->c instanceof JTextComponent t&&!(t instanceof JPasswordField)&&t.isShowing()
                &&HostGuiMessages.request(t.getText())&&t.getText().contains(nonce),true));
    }
    private JTextComponent awaitNonce(String nonce) {
        var found=new JTextComponent[1];until(()->{try{found[0]=requireNonce(nonce);return true;}
            catch(Failure missing){if(missing.getMessage().equals("GUI_CONTROL_MISSING"))return false;throw missing;}});return found[0];
    }
    private JTextComponent rawRequestEditor() {
        return edt(()->requestEditor(frame));
    }
    private void assertRepeaterResponse(String nonce,int expected) {
        until(()->edt(()->{var results=all(frame).stream().filter(c->c instanceof JTextComponent&&!(c instanceof JPasswordField)&&c.isShowing())
                .map(c->HostGuiMessages.response(((JTextComponent)c).getText(),nonce)).filter(Objects::nonNull).toList();
            if(results.isEmpty())return false;int status=unique(results);if(status!=expected)throw new Failure("GUI_RESPONSE_STATUS_MISMATCH");return true;}));
    }
    void replace(JTextComponent component,String text) {
        click(component);input.keys(KeyEvent.VK_CONTROL,KeyEvent.VK_A);input.text(text);
        until(()->edt(()->component.getText().replace("\r\n","\n").equals(text.replace("\r\n","\n"))));
    }
    private void check(){if(Files.exists(session.root().resolve("cancel"))||Thread.currentThread().isInterrupted())throw new Failure("GUI_CANCELLED");
        if(clock.millis()>=deadline)throw new Failure("GUI_DEADLINE");
        String failure=edt(()->Arrays.stream(Window.getWindows()).filter(w->w instanceof Dialog d&&d.isShowing()&&d.getTitle().equals("Error loading extension"))
                .map(w->extensionFailure(((Dialog)w).getTitle(),all(w).stream().filter(c->c instanceof JTextComponent&&!(c instanceof JPasswordField))
                        .map(c->((JTextComponent)c).getText()).toList())).filter(Objects::nonNull).findFirst().orElse(null));
        if(failure!=null)throw new Failure(failure);
    }
    void until(java.util.function.BooleanSupplier condition){while(true){check();if(condition.getAsBoolean())return;try{Thread.sleep(100);}catch(InterruptedException stop){Thread.currentThread().interrupt();throw new Failure("GUI_CANCELLED");}}}
    private void until(java.util.function.BooleanSupplier condition,String timeoutCode) {
        try{until(condition);}catch(Failure failure){if(failure.getMessage().equals("GUI_DEADLINE"))throw new Failure(timeoutCode);throw failure;}
    }
    Window surface(){return frame;}
    Container productSurface(){return edt(()->(Container)tabs(frame,"Journeys","Session handling","Settings").getSelectedComponent());}
    void clickAt(Component component,Point relative){input.click(component,relative);}
    void captureRuntimeAppearance(){HostGuiDiagnostics.privateScreenshot(session.root(),activeCommand.operationId(),frame);}
    Container wizardSurface(){return edt(()->(Container)tabs(frame,"Setup","Test & use").getSelectedComponent());}
    Path root(){return session.root();}
    void keys(int... keys){input.keys(keys);}
    void type(String text){input.text(text);}
    void external(Runnable nativeGuard,Runnable action){input.external(nativeGuard,action);}
    String displayName(String alias){String name=importedNames.get(alias);if(name==null)throw new Failure("GUI_JOURNEY_NOT_IMPORTED");return name;}
    void productTab(String title){openTool("PRODUCT");select(edt(()->tabs(frame,"Journeys","Session handling","Settings")),title);}
    void combo(JComboBox<?> combo,String value) {
        if(edt(()->value.equals(comboKey(combo.getSelectedItem()))))return;
        click(combo);final ComboChoice[] chosen={null};
        until(()->{
            try{
                chosen[0]=edt(()->comboChoice(popupMenu(combo),combo,value));var choice=chosen[0];
                Point center=edt(()->{var cell=choice.list().getCellBounds(choice.row(),choice.row());
                    if(cell==null)throw new Failure("GUI_CONTROL_MISSING");return new Point(cell.x+cell.width/2,cell.y+cell.height/2);});
                if(!edt(()->choice.list().getVisibleRect().contains(center))) {
                    int units=edt(()->center.y<choice.list().getVisibleRect().y?-3:3);input.scroll(choice.list(),units);return false;
                }
                return true;
            }
            catch(Failure pending){if(pending.getMessage().equals("GUI_CONTROL_MISSING"))return false;throw pending;}
        },"GUI_COMBO_CHOICE_DEADLINE");
        var choice=chosen[0];Point target=edt(()->{
            if(choice.row()>=choice.list().getModel().getSize()||!value.equals(comboKey(choice.list().getModel().getElementAt(choice.row()))))
                throw new Failure("GUI_COMBO_CHOICE_CHANGED");
            var cell=choice.list().getCellBounds(choice.row(),choice.row());
            if(cell==null)throw new Failure("GUI_CONTROL_MISSING");return new Point(cell.x+cell.width/2,cell.y+cell.height/2);
        });
        input.click(choice.list(),target);
        until(()->edt(()->value.equals(comboKey(combo.getSelectedItem()))&&!combo.isPopupVisible()),"GUI_COMBO_SELECTION_DEADLINE");
    }
    void phase(String stage) {
        if(activeCommand==null)return;
        try {
            var state=LabHostGuiProtocol.identity(session);state.addProperty("operationId",activeCommand.operationId().toString());
            state.addProperty("sequence",activeCommand.sequence());state.addProperty("operation",activeCommand.operation().name());state.addProperty("stage",stage);
            Path directory=session.root().resolve("gui");Files.createDirectories(directory);Path temporary=directory.resolve("progress.tmp");
            Files.writeString(temporary,LabJson.JSON.toJson(state));Files.move(temporary,directory.resolve("progress.json"),StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
        }catch(IOException unavailable){throw new Failure("GUI_PROGRESS_UNAVAILABLE");}
    }

    static final class RobotInput implements Input {
        private static final int MAX_CAPTION_CANDIDATES=9;
        private static final int MAX_TARGET_POSITIONS=4;
        interface ClickPlan {
            default void check(){}
            default void expose(){}
            Point targetPoint();void move(Point point);boolean targetOwned(Point point);
            List<Point> captionPoints();boolean captionOwned(Point point);void focusGesture(Point point);void targetGesture(Point point);
        }
        /** No point is clicked without fresh ownership proof; only pointer movement may search. */
        static void guardedClick(boolean popup,ClickPlan plan) {
            var position=settledPosition(plan);Point target=position.point();boolean owned=position.owned();
            if(!popup) {
                plan.check();plan.expose();position=settledPosition(plan);target=position.point();owned=position.owned();
            }
            if(!owned) {
                if(popup)throw new Failure("GUI_CONTROL_OCCLUDED");
                boolean activated=false;
                for(Point caption:plan.captionPoints().stream().limit(MAX_CAPTION_CANDIDATES).toList()) {
                    plan.check();plan.move(caption);
                    if(!plan.captionOwned(caption))continue;
                    if(!plan.captionOwned(caption))throw new Failure("GUI_FOCUS_CAPTION_CHANGED");
                    plan.check();plan.focusGesture(caption);activated=true;break;
                }
                if(!activated)throw new Failure("GUI_FOCUS_CAPTION_UNAVAILABLE");
                target=settledPosition(plan).point();
            }
            if(!plan.targetOwned(target))throw new Failure("GUI_CONTROL_OCCLUDED");
            plan.check();plan.targetGesture(target);
        }
        private record Position(Point point,boolean owned) {}
        /** Repositions only before any press, retaining the exact component/window and original guard. */
        private static Position settledPosition(ClickPlan plan) {
            for(int attempt=0;attempt<MAX_TARGET_POSITIONS;attempt++) {
                plan.check();Point target=plan.targetPoint();plan.move(target);plan.check();
                try {return new Position(target,plan.targetOwned(target));}
                catch(Failure moved) {
                    if(!moved.getMessage().equals("GUI_CONTROL_CHANGED"))throw moved;
                    plan.check();
                    if(plan.targetPoint().equals(target))throw moved;
                }
            }
            throw new Failure("GUI_CONTROL_CHANGED");
        }
        static void guardedKeys(int[] keys,Runnable guard,java.util.function.IntConsumer press,java.util.function.IntConsumer release) {
            int pressed=0;
            try {for(int key:keys){guard.run();press.accept(key);pressed++;}}
            finally {for(int i=pressed-1;i>=0;i--)release.accept(keys[i]);}
        }
        static void guardedWheel(Runnable guard,java.util.function.BooleanSupplier owned,Runnable wheel) {
            guard.run();if(!owned.getAsBoolean())throw new Failure("GUI_CONTROL_OCCLUDED");guard.run();wheel.run();
        }
        /** A conservative left/central title region, excluding the icon, control strip and resize borders. */
        static List<Point> captionCandidates(Dimension size,Insets insets) {
            if(size.width<1||size.height<1||insets.top<1||insets.left<0||insets.right<0||insets.bottom<0)return List.of();
            int border=Math.max(insets.left,Math.max(insets.right,insets.bottom)),top=insets.top;
            if((long)top<border+9L||(long)top*3>size.height)return List.of();
            long left=(long)insets.left+2L*top,right=Math.min(size.width/2L,(long)size.width-insets.right-6L*top);
            if(right-left<24)return List.of();
            int low=border+4,high=top-5;
            int[] xs={(int)right,(int)(left+(right-left)*2/3),(int)(left+(right-left)/3)};
            int[] ys={Math.max(low,Math.min(high,top/2)),low,high};
            var points=new LinkedHashSet<Point>();for(int y:ys)for(int x:xs)points.add(new Point(x,y));return List.copyOf(points);
        }
        static boolean matchesOwnedPoint(Point observed,Point expected) {
            return observed!=null&&Math.abs((long)observed.x-expected.x)<=1&&Math.abs((long)observed.y-expected.y)<=1;
        }
        private static Point mousePosition(Component component) {
            return component instanceof Container container?container.getMousePosition(true):component.getMousePosition();
        }
        private static boolean ownsPointer(Component component,Point desired) {
            Point observed=mousePosition(component);
            return observed!=null&&component.contains(observed)&&(!(component instanceof JComponent swing)||swing.getVisibleRect().contains(observed))&&matchesOwnedPoint(observed,desired);
        }
        private static Point screenPoint(Component component,Point desired,Window window) {
            requireAvailable(component);if(!actionEnabled(component))throw new Failure("GUI_CONTROL_UNAVAILABLE");
            if(SwingUtilities.getWindowAncestor(component)!=window)throw new Failure("GUI_WINDOW_CHANGED");
            if(!component.contains(desired))throw new Failure("GUI_CONTROL_OUTSIDE_COMPONENT");
            if(component instanceof JComponent swing&&!swing.getVisibleRect().contains(desired))throw new Failure("GUI_CONTROL_CLIPPED");
            var point=component.getLocationOnScreen();point.translate(desired.x,desired.y);
            if(!window.getBounds().contains(point))throw new Failure("GUI_CONTROL_OUTSIDE_WINDOW");return point;
        }
        private static boolean hasOwnedPopup(Window owner) {
            var queue=new ArrayDeque<Window>();queue.add(owner);var seen=Collections.newSetFromMap(new IdentityHashMap<Window,Boolean>());
            while(!queue.isEmpty()) {
                Window window=queue.remove();if(!seen.add(window))continue;if(seen.size()>32)throw new Failure("GUI_WINDOW_LIMIT");
                if(all(window).stream().anyMatch(c->c instanceof JPopupMenu menu&&menu.isShowing()))return true;
                for(Window child:window.getOwnedWindows())if(child.isShowing())queue.add(child);
            }
            return false;
        }
        final Robot robot;
        Window focused;
        private Runnable operationGuard=()->{};
        private final HostGuiKeyboardFocus keyboardFocus=new HostGuiKeyboardFocus();
        private JsonObject lastPointer=new JsonObject();
        @Override public JsonObject pointerState(){return lastPointer.deepCopy();}
        @Override public void bindOperationGuard(Runnable guard){operationGuard=Objects.requireNonNull(guard);}
        RobotInput() throws AWTException{robot=new Robot();robot.setAutoDelay(20);}
        @Override public void click(Component component,Point relative) {
            operationGuard.run();lastPointer=new JsonObject();Point desired=new Point(relative);
            edt(()->{requireAvailable(component);return true;});
            Window window=edt(()->SwingUtilities.getWindowAncestor(component));
            if(window==null)throw new Failure("GUI_WINDOW_MISSING");
            Window owner=edt(()->focusWindow(component));boolean popup=edt(()->popupAncestor(component)!=null);
            lastPointer.addProperty("popupContext",popup);
            if(popup&&!edt(owner::isFocused))throw new Failure("GUI_FOCUS_FAILED");
            if(!popup&&edt(()->hasOwnedPopup(owner)))throw new Failure("GUI_POPUP_CONTEXT");
            guardedClick(popup,new ClickPlan() {
                Rectangle captionBounds;Insets captionInsets;
                boolean exposureRequested,exposureMeasured;
                final Set<Point> testedCaptions=new HashSet<>();
                private Point geometry() {
                    if(focusWindow(component)!=owner||(popupAncestor(component)!=null)!=popup)
                        throw new Failure("GUI_WINDOW_CHANGED");
                    if(!popup&&hasOwnedPopup(owner))throw new Failure("GUI_POPUP_CONTEXT");
                    return screenPoint(component,desired,window);
                }
                @Override public void check(){operationGuard.run();}
                @Override public void expose(){
                    operationGuard.run();edt(()->{operationGuard.run();geometry();owner.toFront();owner.requestFocus();return true;});
                    exposureRequested=true;lastPointer.addProperty("exposureRequested",true);
                }
                @Override public Point targetPoint(){return edt(this::geometry);}
                @Override public void move(Point point){operationGuard.run();robot.mouseMove(point.x,point.y);}
                @Override public boolean targetOwned(Point point){return edt(()->{
                    if(!geometry().equals(point))throw new Failure("GUI_CONTROL_CHANGED");
                    boolean owned=ownsPointer(component,desired);
                    if(!popup&&(!exposureRequested||!exposureMeasured)) {
                        String prefix=exposureRequested?"afterExposure":"beforeExposure";
                        lastPointer.addProperty(prefix+"TargetMouseOwned",owned);
                        lastPointer.addProperty(prefix+"WindowMouseOwned",window.getMousePosition(true)!=null);
                        if(exposureRequested)exposureMeasured=true;
                    }
                    return owned;
                });}
                @Override public List<Point> captionPoints(){return edt(()->{
                    boolean decorated=owner instanceof Frame frame&&!frame.isUndecorated()||owner instanceof Dialog dialog&&!dialog.isUndecorated();
                    Dimension size=owner.getSize();Insets insets=owner.getInsets();
                    lastPointer.addProperty("captionDecorationAvailable",decorated);
                    lastPointer.addProperty("captionWindowWidth",size.width);lastPointer.addProperty("captionWindowHeight",size.height);
                    lastPointer.addProperty("captionInsetTop",insets.top);lastPointer.addProperty("captionInsetLeft",insets.left);
                    lastPointer.addProperty("captionInsetBottom",insets.bottom);lastPointer.addProperty("captionInsetRight",insets.right);
                    lastPointer.addProperty("captionCandidateCount",0);lastPointer.addProperty("captionOwnershipTestedCandidates",0);
                    if(!decorated||!owner.isShowing()||!owner.isEnabled()||!owner.isFocusableWindow()||(owner instanceof Frame frame&&(frame.getExtendedState()&Frame.ICONIFIED)!=0))return List.of();
                    if(hasOwnedPopup(owner))throw new Failure("GUI_POPUP_CONTEXT");
                    Point origin=owner.getLocationOnScreen();captionBounds=new Rectangle(origin,owner.getSize());captionInsets=owner.getInsets();
                    var candidates=captionCandidates(owner.getSize(),captionInsets);lastPointer.addProperty("captionCandidateCount",candidates.size());
                    return candidates.stream().map(captionLocal->{var point=new Point(origin);point.translate(captionLocal.x,captionLocal.y);return point;}).toList();
                });}
                @Override public boolean captionOwned(Point point){return edt(()->{
                    if(!owner.isShowing()||!owner.isEnabled()||captionBounds==null||!new Rectangle(owner.getLocationOnScreen(),owner.getSize()).equals(captionBounds)||!owner.getInsets().equals(captionInsets))
                        throw new Failure("GUI_FOCUS_CAPTION_CHANGED");
                    if(hasOwnedPopup(owner))throw new Failure("GUI_POPUP_CONTEXT");
                    var local=new Point(point);local.translate(-captionBounds.x,-captionBounds.y);
                    if(!captionCandidates(owner.getSize(),captionInsets).contains(local))throw new Failure("GUI_FOCUS_CAPTION_CHANGED");
                    testedCaptions.add(new Point(point));lastPointer.addProperty("captionOwnershipTestedCandidates",testedCaptions.size());
                    return matchesOwnedPoint(owner.getMousePosition(true),local);
                });}
                @Override public void focusGesture(Point point){
                    if(!captionOwned(point))throw new Failure("GUI_FOCUS_CAPTION_CHANGED");
                    lastPointer.addProperty("focusCaptionOwnershipVerified",true);lastPointer.addProperty("focusGestureAttempted",true);
                    primaryGesture();edt(()->true);
                }
                @Override public void targetGesture(Point point){
                    var trace=new HostGuiPointerTrace(window,component);var toolkit=Toolkit.getDefaultToolkit();toolkit.addAWTEventListener(trace,AWTEvent.MOUSE_EVENT_MASK);
                    try {
                        edt(()->{trace.attachButtonObservation();return true;});
                        if(!targetOwned(point))throw new Failure("GUI_CONTROL_OCCLUDED");
                        lastPointer.addProperty("targetOwnershipVerified",true);lastPointer.addProperty("targetGestureAttempted",true);
                        primaryGesture();long observationEnd=System.nanoTime()+java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(250);
                        while(!trace.releaseObserved()&&System.nanoTime()<observationEnd) {
                            try{Thread.sleep(10);}catch(InterruptedException stopped){Thread.currentThread().interrupt();throw new Failure("GUI_CANCELLED");}
                        }
                        // AWT observers see release before Swing processes it; drain it before diagnosing action delivery.
                        edt(()->true);
                    }finally{toolkit.removeAWTEventListener(trace);trace.detachButtonObservation();var observed=trace.snapshot();lastPointer.entrySet().forEach(entry->observed.add(entry.getKey(),entry.getValue().deepCopy()));lastPointer=observed;}
                }
            });
            focused=owner;
        }
        private void primaryGesture(){operationGuard.run();try{robot.mousePress(InputEvent.BUTTON1_DOWN_MASK);}finally{robot.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);}}
        @Override public void keys(int... keys){
            guardedKeys(keys,()->keyboardFocus.verify(operationGuard,()->focused!=null&&edt(focused::isFocused)),robot::keyPress,robot::keyRelease);
        }
        @Override public void external(Runnable nativeGuard,Runnable action){operationGuard.run();keyboardFocus.external(nativeGuard,action);}
        @Override public void scroll(Component component,int units) {
            if(units==0||Math.abs(units)>3)throw new Failure("GUI_SCROLL_INPUT");
            operationGuard.run();Window window=edt(()->SwingUtilities.getWindowAncestor(component));
            Point desired=edt(()->{requireAvailable(component);
                if(focused==null||focusWindow(component)!=focused||!focused.isFocused())throw new Failure("GUI_FOCUS_FAILED");
                var visible=((JComponent)component).getVisibleRect();return new Point(visible.x+visible.width/2,visible.y+visible.height/2);
            });
            Point target=edt(()->screenPoint(component,desired,window));operationGuard.run();robot.mouseMove(target.x,target.y);
            guardedWheel(operationGuard,()->edt(()->{if(focusWindow(component)!=focused||!screenPoint(component,desired,window).equals(target))throw new Failure("GUI_CONTROL_CHANGED");return ownsPointer(component,desired);}),()->robot.mouseWheel(units));
        }
        @Override public void text(String text) {
            String shifted="~!@#$%^&*()_+{}|:\"<>?",unshifted="`1234567890-=[]\\;',./";
            for(char value:text.toCharArray()) {
                operationGuard.run();
                if(value=='\r')continue;if(value=='\n'){keys(KeyEvent.VK_ENTER);continue;}if(value=='\t'){keys(KeyEvent.VK_TAB);continue;}
                boolean shift=Character.isUpperCase(value);int index=shifted.indexOf(value);
                if(index>=0){value=unshifted.charAt(index);shift=true;}
                int code=KeyEvent.getExtendedKeyCodeForChar(Character.toUpperCase(value));
                if(value<32||value>126||code==KeyEvent.VK_UNDEFINED)throw new Failure("GUI_KEYBOARD_UNSUPPORTED");
                if(shift)keys(KeyEvent.VK_SHIFT,code);else keys(code);
            }
        }
    }
}

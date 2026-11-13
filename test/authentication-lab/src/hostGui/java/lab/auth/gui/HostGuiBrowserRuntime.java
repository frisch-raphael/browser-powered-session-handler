package lab.auth.gui;
import java.awt.*;
import java.util.function.*;
import javax.swing.*;
import javax.swing.text.JTextComponent;
import javax.swing.tree.*;
import java.awt.event.KeyEvent;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import com.google.gson.JsonObject;
import static lab.auth.gui.HostGuiSelectors.*;
/** Public native UI recipes; authentication remains owned by the product and controlled fixture. */
final class HostGuiBrowserRuntime {
 private final HostGuiDriver ui;
 private Recording recording;
 private record Recording(String alias,Dialog dialog,ProcessHandle browser,HostGuiBrowserWindow keyboard) {}
 HostGuiBrowserRuntime(HostGuiDriver ui){this.ui=ui;}
 JsonObject test(String alias) {
  ui.clickTestLogin(alias);Dialog success=ui.awaitLoginDialog("Credentials captured");
  boolean summary=edt(()->all(success).stream().anyMatch(c->c instanceof JTextComponent text&&c.isShowing()
          &&text.getText().contains("Journey: "+ui.displayName(alias))&&text.getText().contains("Captured 2 credentials:")));
  if(!summary)throw new Failure("GUI_BROWSER_CAPTURE_SUMMARY");ui.closeLoginDialog(success);
  var observed=new JsonObject();observed.addProperty("testUiConfirmed",true);return observed;
 }
 JsonObject record(String alias,String secret) throws java.io.IOException {
  if(recording!=null||!secret.equals("FORM_B"))throw new Failure("GUI_RECORDING_OWNER");
  ui.journey(alias);ui.wizard("Setup");String address=edt(()->((JTextComponent)field(ui.surface(),"url")).getText());
  URI uri;try{uri=URI.create(address);}catch(IllegalArgumentException invalid){throw new Failure("GUI_RECORDING_FIXTURE_URI");}
  if(!uri.getScheme().equals("http")||!Set.of("localhost","127.0.0.1").contains(uri.getHost())||uri.getPort()<1
          ||uri.getUserInfo()!=null||!uri.getPath().startsWith("/cases/BROW.basic.json/"))throw new Failure("GUI_RECORDING_FIXTURE_URI");
  ui.wizard("Login steps");clearSteps(ui.wizardSurface(),ui::click,ui::until);
  Set<Long> before;try(var children=ProcessHandle.current().descendants()){before=children.map(ProcessHandle::pid).collect(java.util.stream.Collectors.toSet());}
  ui.click(edt(()->find(ui.wizardSurface(),c->c instanceof AbstractButton&&named(c,"Record in browser"),true)));
  final Dialog[] dialog={null};ui.until(()->{
   dialog[0]=dialog("Record login steps");return dialog[0]!=null&&edt(()->all(dialog[0]).stream().anyMatch(c->c instanceof AbstractButton&&c.isShowing()&&c.isEnabled()&&label(c).equals("Stop recording")));
  });
  final ProcessHandle[] main={null};ui.until(()->{
   try(var children=ProcessHandle.current().descendants()) {
    var candidates=children.filter(h->!before.contains(h.pid())&&h.isAlive()&&h.info().command().orElse("").replace('\\','/').toLowerCase(Locale.ROOT).matches(".*/burpbrowser/[0-9]+(?:\\.[0-9]+){2,3}/chrome(?:\\.exe)?")
            &&h.parent().map(parent->parent.info().command().orElse("").replace('\\','/').toLowerCase(Locale.ROOT).matches(".*/node(?:\\.exe)?")).orElse(false)).toList();
    if(candidates.size()>1)throw new Failure("GUI_BROWSER_WINDOW_AMBIGUOUS");if(candidates.isEmpty())return false;main[0]=candidates.getFirst();return true;
   }
  });
  var keyboard=HostGuiBrowserWindow.owned(main[0],Path.of(System.getProperty("java.io.tmpdir")));boolean retained=false;
  try {
   String version=keyboard.version();var secrets=lab.auth.LabJson.object(lab.auth.LabJson.read(ui.root().resolve("fixture-secrets.json"),4096),"FORM_A","FORM_B","HTTP_A","HTTP_B");
   String password=lab.auth.LabJson.text(secrets,secret);if(password.isEmpty()||password.length()>128||password.chars().anyMatch(c->c<32||c>126))throw new Failure("GUI_FIXTURE_SECRET");
   keyboard.focus();
   ui.external(keyboard::requireForeground,()->{
    // A foreground browser may still focus its omnibox. Escape closes its
    // suggestions first, then restores the page's autofocus target.
    ui.keys(KeyEvent.VK_CONTROL,KeyEvent.VK_L);ui.keys(KeyEvent.VK_ESCAPE);ui.keys(KeyEvent.VK_ESCAPE);
    ui.keys(KeyEvent.VK_CONTROL,KeyEvent.VK_A);ui.type("user2");ui.keys(KeyEvent.VK_TAB);ui.type(password);ui.keys(KeyEvent.VK_ENTER);
   });
   recording=new Recording(alias,dialog[0],main[0],keyboard);retained=true;
   var observed=new JsonObject();observed.addProperty("initialStepsCleared",true);observed.addProperty("nativeStart",true);observed.addProperty("loginTyped",true);observed.addProperty("browserVersion",version);return observed;
  }finally{if(!retained)keyboard.close();}
 }
 JsonObject finish(String alias) {
  var active=recording;if(active==null||!active.alias().equals(alias)||!edt(active.dialog()::isShowing))throw new Failure("GUI_RECORDING_OWNER");
  try {
   edt(()->{active.dialog().toFront();return true;});
   ui.click(edt(()->button(active.dialog(),"Stop recording")));
   final Component[] apply={null};ui.until(()->edt(()->{
    var actions=all(active.dialog()).stream().filter(c->c instanceof AbstractButton&&c.isShowing()&&c.isEnabled()&&label(c).equals("Replace steps")).toList();
    if(actions.isEmpty())return false;apply[0]=unique(actions);return true;
   }));
   ui.click(apply[0]);ui.until(()->!edt(active.dialog()::isShowing)&&!active.browser().isAlive());
   ui.wizard("Login steps");if(steps(ui.wizardSurface())<1)throw new Failure("GUI_RECORDING_REPLACEMENT_MISSING");
   var result=new JsonObject();result.addProperty("nativeStop",true);result.addProperty("reviewReplaced",true);return result;
  }finally{recording=null;active.keyboard().close();}
 }
 JsonObject settings(String alias,String theme,String size) {
  nativeTheme(theme);int width=size.equals("compact")?960:1240;
  var screen=edt(()->ui.surface().getGraphicsConfiguration().getBounds());if(screen.width<width||screen.height<700)throw new Failure("GUI_VIEWPORT_UNAVAILABLE");
  edt(()->{ui.surface().setBounds(screen.x,screen.y,width,Math.min(850,screen.height-40));return true;});
  ui.productTab("Settings");final JTextField[] selected={null};ui.until(()->{
   var fields=edt(()->all(ui.productSurface()).stream().filter(c->c instanceof JTextField&&named(c,"Burp Browser executable")&&c.isShowing()).toList());
   if(fields.isEmpty())return false;selected[0]=(JTextField)unique(fields);return edt(()->themeVisible(theme,selected[0].getBackground()));
  });
  JTextField path=selected[0];var page=ui.productSurface();var browse=edt(()->(JComponent)button(page,"Browse"));var automatic=edt(()->(JComponent)button(page,"Restore automatic detection"));
  String literal="<html>not-a-burp-browser";ui.replace(path,literal);ui.clickTestLogin(alias);
  final JsonObject[] state={null};ui.until(()->{
   boolean noPopup=edt(()->Arrays.stream(Window.getWindows()).noneMatch(w->w instanceof Dialog&&w.isShowing()));
   state[0]=settingsEvidence(path,browse,automatic,literal,noPopup);
   return List.of("inlineError","focused","noPopup","literalPath","controlsVisible").stream().allMatch(k->state[0].get(k).getAsBoolean());
  });
  ui.captureRuntimeAppearance();var result=state[0];result.addProperty("theme",theme);result.addProperty("size",size);result.addProperty("width",edt(()->ui.surface().getWidth()));
  ui.click(automatic);ui.until(()->edt(()->!automatic.isEnabled()&&!path.getText().isEmpty()&&!path.getText().equals(literal)
          &&all(page).stream().anyMatch(c->c instanceof JTextArea text&&text.getText().startsWith("Automatic detection."))));return result;
 }
 private void nativeTheme(String theme) {
  ui.phase("OPEN_NATIVE_SETTINGS");
  var menu=edt(()->find(ui.surface(),c->c instanceof JMenu&&label(c).equals("Burp"),true));
  ui.click(menu);ui.click(edt(()->settingsEntry(popupMenu(menu))));
  final Window[] window={null};ui.until(()->{
   var windows=edt(()->Arrays.stream(Window.getWindows()).filter(Window::isShowing).filter(w->w instanceof Dialog d&&d.getTitle().equals("Settings")||w instanceof Frame f&&f.getTitle().equals("Settings")).toList());
   if(windows.isEmpty())return false;window[0]=unique(windows);return true;
  });
  final JTree[] tree={null};final TreePath[] display={null};
  ui.phase("FIND_NATIVE_DISPLAY");
  ui.until(()->edt(()->{
   for(Component component:all(window[0]))if(component instanceof JTree candidate&&candidate.isShowing()) {
    var path=displayPath(candidate);if(path!=null){tree[0]=candidate;display[0]=path;return true;}
   }return false;
  }));
  edt(()->{tree[0].expandPath(display[0].getParentPath());tree[0].scrollPathToVisible(display[0]);return true;});
  var cell=edt(()->tree[0].getPathBounds(display[0]));if(cell==null)throw new Failure("GUI_THEME_NAVIGATION");ui.clickAt(tree[0],new Point(cell.x+cell.width/2,cell.y+cell.height/2));
  ui.phase("FIND_NATIVE_THEME");final JRadioButton[] choice={null};ui.until(()->edt(()->{
   try{choice[0]=(JRadioButton)themeChoice(window[0],theme);return true;}
   catch(Failure pending){if(pending.getMessage().equals("GUI_CONTROL_MISSING"))return false;throw pending;}
  }));
  if(!edt(choice[0]::isSelected))ui.click(choice[0]);ui.until(()->edt(choice[0]::isSelected));
  ui.keys(KeyEvent.VK_ALT,KeyEvent.VK_F4);ui.until(()->!edt(window[0]::isShowing));
 }
 static Component themeChoice(Container root,String theme) {
  if(!Set.of("Light","Dark").contains(theme))throw new Failure("GUI_THEME_UNSUPPORTED");
  return find(root,c->c instanceof JRadioButton&&label(c).equals(theme),true);
 }
 static Component settingsEntry(Container menu) {
  return find(menu,c->c instanceof JMenuItem&&Set.of("Settings","Settings...","Settings\u2026").contains(label(c)),true);
 }
 private static TreePath displayPath(JTree tree) {
  var model=tree.getModel();var pending=new ArrayDeque<TreePath>();pending.add(new TreePath(model.getRoot()));int count=0;
  while(!pending.isEmpty()&&count++<256) {var path=pending.removeFirst();var node=path.getLastPathComponent();if(node.toString().equals("Display"))return path;for(int i=0;i<model.getChildCount(node);i++)pending.add(path.pathByAddingChild(model.getChild(node,i)));}return null;
 }
 private static Dialog dialog(String title) {
  return edt(()->{var found=Arrays.stream(Window.getWindows()).filter(w->w instanceof Dialog d&&w.isShowing()&&d.getTitle().equals(title)).map(w->(Dialog)w).toList();return found.isEmpty()?null:unique(found);});
 }

 static com.google.gson.JsonObject settingsEvidence(JTextField field,JComponent browse,JComponent automatic,String literal,boolean noPopup) {
  return edt(()->{
   var result=new com.google.gson.JsonObject();var group=field.getParent();
   boolean inline=group!=null&&all(group).stream().anyMatch(c->c instanceof javax.swing.text.JTextComponent text&&c.isShowing()
           &&named(c,"Input error")&&text.getText().toLowerCase(java.util.Locale.ROOT).contains("burp browser"));
   result.addProperty("inlineError",inline);result.addProperty("focused",field.isFocusOwner());result.addProperty("noPopup",noPopup);
   result.addProperty("literalPath",field.getText().equals(literal));
   result.addProperty("controlsVisible",java.util.List.of(field,browse,automatic).stream().allMatch(c->c.isShowing()&&c.getWidth()>0&&c.getHeight()>0
           &&c.getVisibleRect().contains(new Rectangle(0,0,c.getWidth(),c.getHeight()))));return result;
  });
 }
 static boolean themeVisible(String theme,Color background) {
  if(background==null)return false;int brightness=(background.getRed()+background.getGreen()+background.getBlue())/3;
  return theme.equals("Dark")?brightness<128:theme.equals("Light")&&brightness>128;
 }
 static int steps(Container root){return edt(()->(int)all(root).stream().filter(c->c instanceof JToggleButton&&label(c).startsWith("Step ")).count());}
 static int clearSteps(Container root,Consumer<Component> click,Consumer<BooleanSupplier> await) {
  int original=steps(root);if(original<1||original>256)throw new Failure("GUI_RECORDING_ORIGINAL_STEPS");
  for(int remaining=original;remaining>0;remaining--) {
   int before=steps(root);var remove=edt(()->find(root,c->c instanceof AbstractButton&&named(c,"Remove step 1"),true));
   click.accept(remove);await.accept(()->steps(root)<before);
  }
  if(steps(root)!=0||!edt(()->all(root).stream().anyMatch(c->named(c,"Configure login actions")&&c.isVisible())))throw new Failure("GUI_RECORDING_STEPS_NOT_EMPTY");
  return original;
 }
}

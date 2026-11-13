package lab.auth.gui;
import java.awt.*;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class HostGuiBrowserSettingsTest {
 static final String LITERAL="<html>not-a-burp-browser";
 static class Field extends JTextField {
  boolean focused=true;Field(){super(LITERAL);setSize(200,24);}
  @Override public boolean isFocusOwner(){return focused;}
  @Override public boolean isShowing(){return isVisible();}
  @Override public Rectangle getVisibleRect(){return new Rectangle(0,0,getWidth(),getHeight());}
 }
 static class Button extends JButton {
  boolean clipped;Button(){setSize(80,24);}
  @Override public boolean isShowing(){return isVisible();}
  @Override public Rectangle getVisibleRect(){return new Rectangle(0,0,getWidth()-(clipped?1:0),getHeight());}
 }
 record Controls(Field field,JPanel group,JTextArea error,Button browse,Button automatic) {}
 static Controls controls(){return HostGuiSelectors.edt(()->{
  var field=new Field();var group=new JPanel();var error=new JTextArea("Select the Burp Browser executable in Settings."){@Override public boolean isShowing(){return isVisible();}};
  error.getAccessibleContext().setAccessibleName("Input error");group.add(field);group.add(error);return new Controls(field,group,error,new Button(),new Button());
 });}
 static com.google.gson.JsonObject evidence(Controls c,boolean noPopup){return HostGuiBrowserRuntime.settingsEvidence(c.field(),c.browse(),c.automatic(),LITERAL,noPopup);}
 @Test void evidenceRequiresLocatedVisibleGuidanceFocusLiteralDataAndWholeControls() {
  var c=controls();var valid=evidence(c,true);
  for(String key:java.util.List.of("inlineError","focused","noPopup","literalPath","controlsVisible"))assertEquals(new com.google.gson.JsonPrimitive(true),valid.get(key),key);
  assertFalse(valid.toString().contains(LITERAL));
  c.field().focused=false;assertFalse(evidence(c,true).get("focused").getAsBoolean());c.field().focused=true;
  HostGuiSelectors.edt(()->{c.error().setVisible(false);return true;});assertFalse(evidence(c,true).get("inlineError").getAsBoolean());
  HostGuiSelectors.edt(()->{c.error().setVisible(true);c.group().remove(c.error());return true;});assertFalse(evidence(c,true).get("inlineError").getAsBoolean());
  HostGuiSelectors.edt(()->{c.group().add(c.error());return true;});c.browse().clipped=true;assertFalse(evidence(c,true).get("controlsVisible").getAsBoolean());c.browse().clipped=false;
  assertFalse(evidence(c,false).get("noPopup").getAsBoolean());
  HostGuiSelectors.edt(()->{c.field().setText("another value");return true;});assertFalse(evidence(c,true).get("literalPath").getAsBoolean());
 }
 @Test void themeMustActuallyReachTheNativeFieldPalette() {
  assertTrue(HostGuiBrowserRuntime.themeVisible("Dark",new Color(40,40,40)));assertTrue(HostGuiBrowserRuntime.themeVisible("Light",new Color(245,245,245)));
  assertFalse(HostGuiBrowserRuntime.themeVisible("Dark",Color.WHITE));assertFalse(HostGuiBrowserRuntime.themeVisible("Light",Color.BLACK));
 }
 @Test void nativeSettingsMenuUsesItsCaptionIncludingTheDialogEllipsis() {
  HostGuiSelectors.edt(()->{
   for(String caption:java.util.List.of("Settings","Settings...","Settings\u2026")) {
    var popup=new JPopupMenu();var entry=new JMenuItem(caption){@Override public boolean isShowing(){return true;}};
    popup.add(entry);popup.add(new JMenuItem("Project settings"));
    assertSame(entry,HostGuiBrowserRuntime.settingsEntry(popup));
   }
   return true;
  });
 }
 @Test void nativeSettingsMenuRejectsMissingAndAmbiguousEntries() {
  HostGuiSelectors.edt(()->{
   var popup=new JPopupMenu();popup.add(new JMenuItem("Settings..."));
   assertThrows(HostGuiSelectors.Failure.class,()->HostGuiBrowserRuntime.settingsEntry(popup));
   for(int i=0;i<2;i++)popup.add(new JMenuItem("Settings..."){@Override public boolean isShowing(){return true;}});
   assertThrows(HostGuiSelectors.Failure.class,()->HostGuiBrowserRuntime.settingsEntry(popup));return true;
  });
 }
 @Test void nativeDisplayThemeUsesTheVisibleRadioButtonAndRejectsOtherControls() {
  HostGuiSelectors.edt(()->{
   var root=new JPanel();var light=new JRadioButton("Light"){@Override public boolean isShowing(){return true;}};
   var dark=new JRadioButton("Dark"){@Override public boolean isShowing(){return true;}};
   var group=new ButtonGroup();group.add(light);group.add(dark);light.setSelected(true);root.add(light);root.add(dark);root.add(new JButton("Dark"));
   assertSame(light,HostGuiBrowserRuntime.themeChoice(root,"Light"));assertSame(dark,HostGuiBrowserRuntime.themeChoice(root,"Dark"));
   assertThrows(HostGuiSelectors.Failure.class,()->HostGuiBrowserRuntime.themeChoice(root,"Other"));
   root.add(new JRadioButton("Dark"){@Override public boolean isShowing(){return true;}});
   assertThrows(HostGuiSelectors.Failure.class,()->HostGuiBrowserRuntime.themeChoice(root,"Dark"));return true;
  });
 }
}

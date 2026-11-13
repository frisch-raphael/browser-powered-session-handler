package lab.auth.gui;
import java.awt.Component;
import java.util.*;
import java.util.function.*;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
/** Exercises the native step-removal recipe with real Swing callbacks, without opening windows. */
class HostGuiBrowserRuntimeTest {
 static final class Steps {
  final JPanel panel=new JPanel();final JTextArea empty=new JTextArea();int remaining;
  Steps(int count){remaining=count;empty.getAccessibleContext().setAccessibleName("Configure login actions");render();}
  void render(){panel.removeAll();empty.setVisible(remaining==0);panel.add(empty);for(int i=0;i<remaining;i++){panel.add(new JToggleButton("Step "+(i+1)));var remove=new JButton(){@Override public boolean isShowing(){return isVisible();}};remove.getAccessibleContext().setAccessibleName("Remove step "+(i+1));remove.addActionListener(e->{remaining--;render();});panel.add(remove);}}
 }
 @Test void clearsEveryOriginalStepBeforeRecordingCanReplaceIt() {
  var steps=HostGuiSelectors.edt(()->new Steps(3));
  int count=HostGuiBrowserRuntime.clearSteps(steps.panel,c->HostGuiSelectors.edt(()->{((AbstractButton)c).doClick(0);return true;}),condition->assertTrue(condition.getAsBoolean()));
  assertEquals(3,count);assertEquals(0,steps.remaining);assertTrue(steps.empty.isVisible());
 }
 @Test void anAlreadyEmptyEditorCannotClaimTheOriginalStepsWereCleared() {
  var steps=HostGuiSelectors.edt(()->new Steps(0));assertThrows(HostGuiSelectors.Failure.class,()->HostGuiBrowserRuntime.clearSteps(steps.panel,c->fail("No native gesture is allowed"),condition->{}));
 }
 @Test void noProgressCannotBeReportedAsACompletedRemoval() {
  var steps=HostGuiSelectors.edt(()->new Steps(2));assertThrows(AssertionError.class,()->HostGuiBrowserRuntime.clearSteps(steps.panel,c->{},condition->assertTrue(condition.getAsBoolean())));assertEquals(2,steps.remaining);
 }
}

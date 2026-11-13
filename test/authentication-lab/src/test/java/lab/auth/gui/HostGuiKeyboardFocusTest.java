package lab.auth.gui;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class HostGuiKeyboardFocusTest {
 @Test void externalScopeChecksTheNativeWindowBeforeEachKeyAndReleasesOnFocusLoss() {
  var focus=new HostGuiKeyboardFocus();var foreground=new AtomicBoolean(true);var pressed=new ArrayList<Integer>();var released=new ArrayList<Integer>();
  Runnable nativeGuard=()->{if(!foreground.get())throw new HostGuiSelectors.Failure("GUI_BROWSER_FOCUS");};
  assertThrows(HostGuiSelectors.Failure.class,()->focus.external(nativeGuard,()->HostGuiDriver.RobotInput.guardedKeys(new int[]{17,65},()->focus.verify(()->{},()->false),key->{pressed.add(key);foreground.set(false);},released::add)));
  assertEquals(List.of(17),pressed);assertEquals(List.of(17),released);
  assertDoesNotThrow(()->focus.verify(()->{},()->true));assertThrows(HostGuiSelectors.Failure.class,()->focus.verify(()->{},()->false));
 }
 @Test void revokedKeyDoesNotReadFocusAgainOrPressAKey() {
  var focus=new HostGuiKeyboardFocus();var checks=new AtomicInteger();
  assertThrows(HostGuiSelectors.Failure.class,()->focus.external(checks::incrementAndGet,()->focus.verify(()->{throw new HostGuiSelectors.Failure("GUI_CANCELLED");},()->true)));
  assertEquals(1,checks.get());
 }
}

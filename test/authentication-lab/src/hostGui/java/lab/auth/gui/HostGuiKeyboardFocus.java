package lab.auth.gui;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import static lab.auth.gui.HostGuiSelectors.*;
/** A recording scope never turns arbitrary unfocused keyboard input into an allowed action. */
final class HostGuiKeyboardFocus {
 private Runnable external;
 void external(Runnable nativeGuard,Runnable action) {
  if(external!=null)throw new Failure("GUI_BROWSER_SCOPE_NESTED");external=Objects.requireNonNull(nativeGuard);
  try{external.run();action.run();}finally{external=null;}
 }
 void verify(Runnable operationGuard,BooleanSupplier owned) {
  operationGuard.run();if(external!=null)external.run();else if(!owned.getAsBoolean())throw new Failure("GUI_FOCUS_FAILED");
 }
}

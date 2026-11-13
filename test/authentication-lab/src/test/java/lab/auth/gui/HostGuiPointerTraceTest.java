package lab.auth.gui;

import java.awt.event.*;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiPointerTraceTest {
    @Test void observesButtonModelAndActionEventsWithoutInvokingOrRetainingTheirData() {
        HostGuiSelectors.edt(()->{
            var scope=new JPanel();var target=new JButton("PRIVATE_SECRET");scope.add(target);
            var model=target.getModel();int actions=target.getActionListeners().length,changes=((DefaultButtonModel)model).getChangeListeners().length;
            var calls=new java.util.concurrent.atomic.AtomicInteger();target.addActionListener(event->calls.incrementAndGet());
            var trace=new HostGuiPointerTrace(scope,target);trace.attachButtonObservation();
            assertEquals(0,calls.get());model.setArmed(true);model.setPressed(true);model.setPressed(false);model.setArmed(false);
            var state=trace.snapshot();assertEquals(1,calls.get());assertTrue(state.get("actionEventObserved").getAsBoolean());
            assertTrue(state.get("modelArmedObserved").getAsBoolean());assertTrue(state.get("modelPressedObserved").getAsBoolean());
            assertFalse(state.get("disabledDuringGesture").getAsBoolean());assertFalse(state.toString().contains("PRIVATE_"));
            trace.detachButtonObservation();assertEquals(actions+1,target.getActionListeners().length);
            assertEquals(changes,((DefaultButtonModel)model).getChangeListeners().length);return true;
        });
    }
    @Test void distinguishesDeliveredPointerEventsFromAnInterruptedButtonGestureAndDetachesAfterFailure() {
        HostGuiSelectors.edt(()->{
            var scope=new JPanel();var target=new JButton("PRIVATE_SECRET");scope.add(target);var trace=new HostGuiPointerTrace(scope,target);
            int actions=target.getActionListeners().length,properties=target.getPropertyChangeListeners().length;
            try {
                trace.attachButtonObservation();var model=target.getModel();model.setArmed(true);model.setPressed(true);
                target.setEnabled(false);target.setEnabled(true);model.setPressed(false);
                target.setModel(new DefaultButtonModel());throw new IllegalStateException("PRIVATE_FAILURE");
            }catch(IllegalStateException expected){/* Exercise the same unconditional listener cleanup as real input. */}
            finally{trace.detachButtonObservation();}
            var state=trace.snapshot();assertFalse(state.get("actionEventObserved").getAsBoolean());
            assertTrue(state.get("disabledDuringGesture").getAsBoolean());assertTrue(state.get("buttonModelReplaced").getAsBoolean());
            assertEquals(actions,target.getActionListeners().length);assertEquals(properties,target.getPropertyChangeListeners().length);return true;
        });
    }
    @Test void tracksOnlyPrimaryButtonEventsOnTheExactOwnedTargetWithoutReturningData() {
        HostGuiSelectors.edt(()->{
            var scope=new JPanel();var target=new JButton("PRIVATE_SECRET");var child=new JLabel("PRIVATE_PATH");target.add(child);scope.add(target);
            var other=new JButton("PRIVATE_OTHER");scope.add(other);var foreign=new JButton("PRIVATE_FOREIGN");
            var trace=new HostGuiPointerTrace(scope,target);
            trace.eventDispatched(event(target,MouseEvent.MOUSE_PRESSED,MouseEvent.BUTTON3));
            trace.eventDispatched(event(foreign,MouseEvent.MOUSE_RELEASED,MouseEvent.BUTTON1));assertFalse(trace.releaseObserved());
            trace.eventDispatched(event(other,MouseEvent.MOUSE_RELEASED,MouseEvent.BUTTON1));assertTrue(trace.releaseObserved());
            assertFalse(trace.snapshot().get("releasedOnTarget").getAsBoolean());
            trace.eventDispatched(event(target,MouseEvent.MOUSE_PRESSED,MouseEvent.BUTTON1));
            trace.eventDispatched(event(child,MouseEvent.MOUSE_RELEASED,MouseEvent.BUTTON1));
            trace.eventDispatched(event(target,MouseEvent.MOUSE_CLICKED,MouseEvent.BUTTON1));
            var state=trace.snapshot();assertTrue(state.get("pressedOnTarget").getAsBoolean());assertTrue(state.get("releasedOnTarget").getAsBoolean());
            assertTrue(state.get("clickedOnTarget").getAsBoolean());assertFalse(state.toString().contains("PRIVATE_"));return true;
        });
    }
    private MouseEvent event(java.awt.Component source,int type,int button){return new MouseEvent(source,type,1,0,1,1,1,false,button);}
}

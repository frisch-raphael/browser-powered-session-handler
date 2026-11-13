package lab.auth.gui;

import com.google.gson.JsonObject;
import java.awt.*;
import java.awt.event.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.*;

/** Passive, gesture-scoped input diagnosis; no values, coordinates or authentication claims. */
final class HostGuiPointerTrace implements AWTEventListener {
    private final Container scope;
    private final Component target;
    private final AtomicBoolean pressed=new AtomicBoolean(),released=new AtomicBoolean(),clicked=new AtomicBoolean();
    private final AtomicBoolean pressedInScope=new AtomicBoolean(),releasedInScope=new AtomicBoolean();
    private final AtomicBoolean actionEvent=new AtomicBoolean(),armed=new AtomicBoolean(),modelPressed=new AtomicBoolean(),disabled=new AtomicBoolean(),modelReplaced=new AtomicBoolean();
    private AbstractButton button;
    private ButtonModel model;
    private final ActionListener actionListener=event->actionEvent.set(true);
    private final javax.swing.event.ChangeListener modelListener=event->observeModel();
    private final java.beans.PropertyChangeListener propertyListener=event->{
        if("model".equals(event.getPropertyName()))modelReplaced.set(true);
        if("enabled".equals(event.getPropertyName())&&Boolean.FALSE.equals(event.getNewValue()))disabled.set(true);
    };
    HostGuiPointerTrace(Container scope,Component target){this.scope=scope;this.target=target;}
    /** Observes only public Swing events during the one real gesture; it never invokes an action. */
    void attachButtonObservation() {
        if(!SwingUtilities.isEventDispatchThread())throw new IllegalStateException("EDT required");
        if(target instanceof AbstractButton candidate) {
            button=candidate;model=button.getModel();button.addActionListener(actionListener);
            button.addPropertyChangeListener(propertyListener);model.addChangeListener(modelListener);observeModel();
        }
    }
    /** Removes only our listeners; no component state is inspected, including on a failed EDT barrier. */
    void detachButtonObservation() {
        if(button!=null){button.removeActionListener(actionListener);button.removePropertyChangeListener(propertyListener);model.removeChangeListener(modelListener);}
    }
    private void observeModel(){if(model!=null){armed.compareAndSet(false,model.isArmed());modelPressed.compareAndSet(false,model.isPressed());if(!model.isEnabled())disabled.set(true);}}
    @Override public void eventDispatched(AWTEvent event) {
        if(!(event instanceof MouseEvent mouse)||mouse.getButton()!=MouseEvent.BUTTON1||!(mouse.getSource() instanceof Component source))return;
        boolean within=source==scope||SwingUtilities.isDescendingFrom(source,scope);
        if(!within)return;
        boolean onTarget=source==target||SwingUtilities.isDescendingFrom(source,target);
        if(mouse.getID()==MouseEvent.MOUSE_PRESSED){pressedInScope.set(true);if(onTarget)pressed.set(true);}
        if(mouse.getID()==MouseEvent.MOUSE_RELEASED){releasedInScope.set(true);if(onTarget)released.set(true);}
        if(mouse.getID()==MouseEvent.MOUSE_CLICKED&&onTarget)clicked.set(true);
    }
    boolean releaseObserved(){return releasedInScope.get();}
    JsonObject snapshot() {
        var state=new JsonObject();state.addProperty("pressedOnTarget",pressed.get());state.addProperty("releasedOnTarget",released.get());
        state.addProperty("clickedOnTarget",clicked.get());state.addProperty("pressedInOwnedWindow",pressedInScope.get());
        state.addProperty("releasedInOwnedWindow",releasedInScope.get());state.addProperty("buttonModelObserved",model!=null);
        state.addProperty("actionEventObserved",actionEvent.get());state.addProperty("modelArmedObserved",armed.get());
        state.addProperty("modelPressedObserved",modelPressed.get());state.addProperty("disabledDuringGesture",disabled.get());
        state.addProperty("buttonModelReplaced",modelReplaced.get());return state;
    }
}

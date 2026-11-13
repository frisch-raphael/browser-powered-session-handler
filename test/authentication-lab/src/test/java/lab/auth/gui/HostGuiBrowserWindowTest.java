package lab.auth.gui;
import java.time.Instant;import java.util.concurrent.atomic.*;import org.junit.jupiter.api.Test;import static org.junit.jupiter.api.Assertions.*;
class HostGuiBrowserWindowTest {
 @Test void foregroundAndBirthIdentityAreRequiredForEveryKeyboardBatch(){var original=new HostGuiBrowserWindow.Identity(123,Instant.ofEpochMilli(1000));var current=new AtomicReference<>(original);var foreground=new AtomicLong(123);var activations=new AtomicInteger();var target=new HostGuiBrowserWindow(original,current::get,foreground::get,activations::incrementAndGet);target.focus();assertEquals(1,activations.get());foreground.set(456);assertThrows(HostGuiSelectors.Failure.class,target::requireForeground);foreground.set(123);current.set(new HostGuiBrowserWindow.Identity(123,Instant.ofEpochMilli(2000)));assertThrows(HostGuiSelectors.Failure.class,target::requireForeground);}
}

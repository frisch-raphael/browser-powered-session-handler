package bpsh.journey;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Page names, trigger ownership and frame transitions are validated before launching a browser. */
class AuthStepSequenceTest {
    private static AuthStep.Definition step(AuthStep.Type type) {
        return new AuthStep.Definition(UUID.randomUUID(), type, "#target", null, null, null, null);
    }
    private static AuthStep.Definition popup(String name, UUID trigger) {
        return new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.EXPECT_POPUP, null, null, null, null, null, new AuthStep.Popup(name, trigger));
    }
    private static AuthStep.Definition select(String page) {
        return new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.SWITCH_PAGE, null, null, null, null, null, new AuthStep.PageTarget(page));
    }

    @Test void acceptsExplicitNestedFramesAndPopupReturnToInitialPage() {
        var click = step(AuthStep.Type.CLICK);
        assertDoesNotThrow(() -> AuthStepSequence.validate(List.of(step(AuthStep.Type.ENTER_FRAME), step(AuthStep.Type.ENTER_FRAME),
                popup("popup-1", click.id()), click, select("popup-1"), step(AuthStep.Type.CLOSE_PAGE), select("main"), step(AuthStep.Type.CLICK))));
    }

    @Test void switchResetsFrameDepthAndCloseRequiresAnExplicitSwitch() {
        var error = assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(List.of(step(AuthStep.Type.ENTER_FRAME), select("main"), step(AuthStep.Type.PARENT_FRAME))));
        assertTrue(error.getMessage().startsWith("steps[2].context:"));
        assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(List.of(step(AuthStep.Type.CLOSE_PAGE), step(AuthStep.Type.CLICK))));
        assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(List.of(step(AuthStep.Type.CLOSE_PAGE), select("main"))));
    }

    @Test void triggerMustBeTheImmediatelyFollowingSupportedAction() {
        var click = step(AuthStep.Type.CLICK);
        for (var sequence : List.of(List.of(popup("popup-1", click.id())),
                List.of(popup("popup-1", click.id()), step(AuthStep.Type.INPUT), click),
                List.of(popup("popup-1", UUID.randomUUID()), click))) {
            assertTrue(assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(sequence)).getMessage().contains("triggerStepId"));
        }
    }

    @Test void rejectsForwardMissingDuplicateAndReservedPageReferencesWithoutEchoingNames() {
        var click = step(AuthStep.Type.CLICK);
        assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(List.of(select("popup-1"), popup("popup-1", click.id()), click)));
        for (String name : List.of("main", "CANARY private URL", "1popup", "a".repeat(33))) {
            var error = assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(List.of(popup(name, click.id()), click)));
            assertFalse(error.getMessage().contains("CANARY"));
        }
        var second = step(AuthStep.Type.CLICK);
        assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(List.of(popup("popup-1", click.id()), click, popup("popup-1", second.id()), second)));
    }

    @Test void remapsTriggerReferencesInACompleteIdentityMap() {
        var click = step(AuthStep.Type.CLICK); var declaration = popup("popup-1", click.id());
        var ids = Map.of(click.id(), UUID.randomUUID(), declaration.id(), UUID.randomUUID());
        var copied = List.of(declaration.remap(ids), click.remap(ids));
        assertEquals(ids.get(click.id()), ((AuthStep.Popup) copied.getFirst().operation()).triggerStepId());
        assertDoesNotThrow(() -> AuthStepSequence.validate(copied));
    }

    @Test void refusesMismatchedPayloadsAndPreservesSafeDiagnosticStrings() {
        assertThrows(IllegalArgumentException.class, () -> new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.CLICK, "CANARY", null, null, null, null, new AuthStep.Checked(true)));
        var input = new AuthStep.Definition(UUID.randomUUID(), AuthStep.Type.SELECT_OPTIONS, "CANARY", null, null, null, null, new AuthStep.Options(List.of("CANARY")));
        assertFalse(input.toString().contains("CANARY")); assertFalse(input.operation().toString().contains("CANARY"));
        var frames = java.util.stream.IntStream.range(0, 17).mapToObj(i -> step(AuthStep.Type.ENTER_FRAME)).toList();
        assertThrows(ConfigurationException.class, () -> AuthStepSequence.validate(frames));
    }
}

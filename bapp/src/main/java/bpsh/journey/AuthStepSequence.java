package bpsh.journey;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Validates journey-local page references and explicit context transitions without browser APIs. */
public final class AuthStepSequence {
    private AuthStepSequence() {}

    /** @return Whether the supplied name is a portable journey-local page reference. */
    public static boolean pageName(String name) { return name != null && name.matches("[a-z][a-z0-9_-]{0,31}"); }

    /** Rejects invalid executable sequences with indexed, value-free correction guidance. */
    public static void validate(List<AuthStep.Definition> steps) {
        if (steps.size() > 256) throw new ConfigurationException("steps: maximum count is 256.");
        Set<UUID> ids = new HashSet<>(); Set<String> pages = new HashSet<>(); pages.add("main");
        Set<String> declared = new HashSet<>(pages);
        String current = "main"; int depth = 0;
        for (int i = 0; i < steps.size(); i++) {
            var step = steps.get(i);
            if (!ids.add(step.id())) fail(i, "id", "each step must have a unique identity");
            if (current == null && step.type() != AuthStep.Type.SWITCH_PAGE)
                fail(i, "pageRef", "add Switch page after closing a page");
            switch (step.type()) {
                case EXPECT_POPUP -> {
                    var popup = (AuthStep.Popup) step.operation();
                    if (!pageName(popup.pageRef()) || !declared.add(popup.pageRef()))
                        fail(i, "pageRef", "use a unique popup name starting with a lowercase letter, followed by lowercase letters, digits, hyphens or underscores (1–32 characters)");
                    if (declared.size() > 16) fail(i, "pageRef", "maximum count is 16 pages");
                    if (i + 1 >= steps.size() || !steps.get(i + 1).id().equals(popup.triggerStepId())
                            || !Set.of(AuthStep.Type.CLICK, AuthStep.Type.PRESS_KEY).contains(steps.get(i + 1).type()))
                        fail(i, "triggerStepId", "choose the Click element or Press key step immediately after this one");
                    pages.add(popup.pageRef());
                }
                case SWITCH_PAGE -> {
                    String target = ((AuthStep.PageTarget) step.operation()).pageRef();
                    if (!pages.contains(target)) fail(i, "pageRef", "choose Initial tab or an earlier declared popup that has not been closed");
                    current = target; depth = 0;
                }
                case CLOSE_PAGE -> { pages.remove(current); current = null; depth = 0; }
                case ENTER_FRAME -> { if (++depth > 16) fail(i, "selector", "maximum frame depth is 16"); }
                case PARENT_FRAME -> { if (depth == 0) fail(i, "context", "enter a frame before leaving it"); depth--; }
                case MAIN_FRAME -> depth = 0;
                default -> { }
            }
        }
    }

    private static void fail(int index, String field, String reason) {
        throw new ConfigurationException("steps[" + index + "]." + field + ": " + reason + ".");
    }
}

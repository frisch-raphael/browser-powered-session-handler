package bpsh.browser;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Pinned lexical boundaries prevent text and nested selectors from becoming frame transitions. */
class BrowserTargetsTest {
    @Test void quotedSeparatorsAndEscapesStayInsideTheirNativeComponent() {
        String owner = "css=iframe[name=\"outer >> frame\"]";
        String leaf = "internal:role=textbox[name=\"User >> name\"i] >> nth=0";
        var target = BrowserTargets.parse(owner + " >> internal:control=enter-frame >> " + leaf);
        assertEquals(List.of(owner), target.frames()); assertEquals(leaf, target.selector());
        assertFalse(target.anyFrame());
        assertEquals("css=#a\\>\\>b >> css=input", BrowserTargets.parse("css=#a\\>\\>b >> css=input").selector());
        assertEquals("text=Here's >> css=button", BrowserTargets.parse("text=Here's >> css=button").selector());
        assertEquals("*", BrowserTargets.parse("*").selector());
        assertEquals("//iframe", BrowserTargets.parse("//iframe").selector());
    }

    @Test void nestedSelectorsAreValidatedRecursivelyWithoutChangingStoredSource() throws Exception {
        var json = new ObjectMapper();
        String selector = "css=section >> internal:has=" + json.writeValueAsString("internal:text=\"a >> b\"i");
        assertEquals(selector, BrowserTargets.parse(selector).selector());
        String control = "css=section >> internal:has=" + json.writeValueAsString("css=iframe >> internal:control=enter-frame >> css=input");
        assertThrows(IllegalArgumentException.class, () -> BrowserTargets.parse(control));
        assertThrows(IllegalArgumentException.class, () -> BrowserTargets.parse("internal:has=\"css=input\""));
        assertThrows(IllegalArgumentException.class, () -> BrowserTargets.parse("css=section >> internal:has=[\"css=input\"]"));
    }

    @Test void rejectsUnsupportedAmbiguousAndIncompletePathsWithoutEchoingInput() {
        for (String selector : List.of("", "css=input >>", ">> css=input", "css=input >> >> css=button", "*css=input", "custom=CANARY",
                "css=[name=\"unfinished]", "css=input\\", "css=x >> internal:control=unknown >> css=y", "internal:control=enter-frame >> css=input",
                "css=iframe >> internal:control=enter-frame", "css=iframe >> internal:control=enter-frame >> internal:control=enter-frame >> css=x",
                "css=button >> left-of=CANARY", "css=x >> internal:control=any-frame >> css=y")) {
            var error = assertThrows(IllegalArgumentException.class, () -> BrowserTargets.parse(selector), selector);
            assertFalse(error.getMessage().contains("CANARY"));
        }
    }

    @Test void nativeAnyFrameRequiresActualSourceAncestryAndNeverBecomesAPersistedBroadSearch() {
        var target = BrowserTargets.parse("internal:control=any-frame >> internal:role=button[name=\"Continue\"i]");
        assertTrue(target.anyFrame()); assertTrue(target.frames().isEmpty());
        assertEquals("internal:role=button[name=\"Continue\"i]", target.selector());
        assertThrows(IllegalArgumentException.class, () -> BrowserTargets.resolve("internal:control=any-frame >> css=input", null));
        assertEquals(1, BrowserTargets.commonPrefix(List.of("#outer", "#inner-a"), List.of("#outer", "#inner-b")));
    }

    @Test void enforcesUtf8ComponentAndRecursionBounds() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> BrowserTargets.parse("css=" + "é".repeat(2047)));
        String allowed = String.join(" >> ", java.util.Collections.nCopies(256, "css=x"));
        assertDoesNotThrow(() -> BrowserTargets.parse(allowed));
        assertThrows(IllegalArgumentException.class, () -> BrowserTargets.parse(allowed + " >> css=x"));
        String nested = "css=x"; var json = new ObjectMapper();
        for (int i = 0; i < 17; i++) nested = "css=x >> internal:has=" + json.writeValueAsString(nested);
        String excessive = nested; assertThrows(IllegalArgumentException.class, () -> BrowserTargets.parse(excessive));
    }
}

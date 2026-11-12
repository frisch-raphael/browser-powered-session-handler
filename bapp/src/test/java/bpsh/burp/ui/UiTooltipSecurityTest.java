package bpsh.burp.ui;

import bpsh.support.IntegrationFixtures;
import java.awt.image.BufferedImage;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.swing.*;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.AttributeSet;
import javax.swing.text.Element;
import javax.swing.text.StyleConstants;
import javax.swing.text.View;
import javax.swing.text.html.CSS;
import javax.swing.text.html.HTML;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the actual Swing parser and resource loader, rather than only comparing escaped strings. */
class UiTooltipSecurityTest {
    @Test void hostileBodiesAndHeadingsRemainLiteralWithoutResourceElementsOrAttributes() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            for (String payload : payloads("http://127.0.0.1:1/unreachable")) {
                var owner = UiTooltips.label("Help");
                UiTooltips.set(owner, payload, 320, payload);
                var panel = JourneyForms.form(); JourneyForms.row(panel, "Caption", owner);
                for (var surface : new JComponent[]{owner, (JLabel) owner.getClientProperty("rowLabel")}) {
                    var tip = tooltip(surface);
                    assertLiteralDocument(tip, payload);
                    tip.updateUI(); assertLiteralDocument(tip, payload);
                }
            }
        });
    }

    @Test void rawReplacementCopiedStringsAndOwnerChangesCannotAcquireBuilderTrust() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var owner = UiTooltips.label("Help"); UiTooltips.set(owner, "Safe explanation", 320);
            var tip = tooltip(owner); assertInstanceOf(View.class, tip.getClientProperty(BasicHTML.propertyKey));
            String raw = "<html><img src='file:///private'><object classid='java.lang.String'></object></html>";
            owner.setToolTipText(raw); tip.setTipText(raw); assertPlain(tip);
            tip.updateUI(); assertPlain(tip);
            var caption = UiTooltips.label("Caption"); UiTooltips.copy(owner, caption); assertPlain(tooltip(caption));

            UiTooltips.set(owner, "Safe explanation", 320); tip.setTipText(owner.getToolTipText());
            assertInstanceOf(View.class, tip.getClientProperty(BasicHTML.propertyKey));
            var other = UiTooltips.label("Other"); other.setToolTipText(owner.getToolTipText());
            assertPlain(tooltip(other));
            tip.setComponent(other); assertPlain(tip); tip.updateUI(); assertPlain(tip);
            tip.setComponent(owner); assertInstanceOf(View.class, tip.getClientProperty(BasicHTML.propertyKey));
            UiTooltips.set(owner, null, 320); tip.setTipText(null); assertPlain(tip);
        });
    }

    @Test void renderingEscapedAndBypassedPayloadsMakesNoRequestsWhileUnsafeControlLoadsAnImage() throws Exception {
        var requests = new CopyOnWriteArrayList<String>(); var detected = new CountDownLatch(1);
        byte[] image = java.util.Base64.getDecoder().decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7");
        try (var origin = IntegrationFixtures.http().route("/", exchange -> {
            requests.add(exchange.getRequestURI().getPath()); detected.countDown();
            exchange.getResponseHeaders().set("Content-Type", "image/gif"); exchange.sendResponseHeaders(200, image.length);
            try (var output = exchange.getResponseBody()) { output.write(image); } finally { exchange.close(); }
        }).start()) {
            SwingUtilities.invokeAndWait(() -> {
                for (String payload : payloads(origin.url("/forbidden").toString())) {
                    var owner = UiTooltips.label("Help"); UiTooltips.set(owner, payload, 320, payload);
                    var tip = tooltip(owner); paint(tip); tip.updateUI(); paint(tip);
                    owner.setToolTipText("<html>" + payload + "</html>");
                    tip.setTipText(owner.getToolTipText()); assertPlain(tip); paint(tip);
                    tip.updateUI(); assertPlain(tip); paint(tip);
                }
                // Positive control uses precisely the same Swing HTML renderer and listener.
                var unsafe = new JToolTip(); unsafe.putClientProperty("html.disable", Boolean.FALSE);
                unsafe.setTipText("<html><img src='" + origin.url("/positive-control") + "'></html>"); paint(unsafe);
            });
            assertTrue(detected.await(5, TimeUnit.SECONDS), "The resource-loading detector must observe the unsafe control");
            assertEquals(List.of("/positive-control"), requests);
        }
    }

    private static List<String> payloads(String url) {
        return List.of(
            "<img src='" + url + "'>", "</div><IMG SRC=\"" + url + "\">",
            "<body background='" + url + "'>", "<style>@import url('" + url + "');</style>",
            "<link rel='stylesheet' href='" + url + "'>", "<div style=\"background-image:url('" + url + "')\">x</div>",
            "<object classid='javax.swing.JButton'><param name='text' value='injected'></object>",
            "<iframe src='" + url + "'></iframe>", "<base href='" + url + "'>", "<a href='" + url + "'>link</a>",
            "<form action='" + url + "'><input type='image' src='" + url + "'></form>",
            "<img src='file:///private'>", "<img src='file://server/share/private'>",
            "<script>alert('x')</script>", "&lt;img src='" + url + "'&gt;", "&#60;img src='" + url + "'&#62;",
            "&amp;lt;img&amp;gt;", "<@journey/> & \"quotes\" 'apostrophes'", "<!-- </div> -->");
    }

    private static JToolTip tooltip(JComponent owner) {
        var tip = owner.createToolTip(); tip.setTipText(owner.getToolTipText()); return tip;
    }

    private static void assertPlain(JToolTip tip) {
        assertEquals(Boolean.TRUE, tip.getClientProperty("html.disable"));
        assertNull(tip.getClientProperty(BasicHTML.propertyKey));
    }

    private static void assertLiteralDocument(JToolTip tip, String payload) {
        var view = assertInstanceOf(View.class, tip.getClientProperty(BasicHTML.propertyKey));
        try {
            String visible = view.getDocument().getText(0, view.getDocument().getLength());
            assertEquals(2, visible.split(java.util.regex.Pattern.quote(payload), -1).length - 1, visible);
        } catch (javax.swing.text.BadLocationException error) { throw new AssertionError(error); }
        assertSafeElement(view.getDocument().getDefaultRootElement());
        assertSafeView(view);
    }

    private static void assertSafeElement(Element element) {
        assertTrue(Set.of("html", "head", "body", "div", "p-implied", "content", "br").contains(element.getName()), element.getName());
        assertSafeAttributes(element.getAttributes());
        for (int i = 0; i < element.getElementCount(); i++) assertSafeElement(element.getElement(i));
    }

    private static void assertSafeAttributes(AttributeSet attributes) {
        var allowed = Set.of(StyleConstants.NameAttribute, CSS.Attribute.WIDTH, CSS.Attribute.FONT_WEIGHT, HTML.Tag.B, "CR", HTML.Attribute.ENDTAG);
        var names = attributes.getAttributeNames();
        while (names.hasMoreElements()) {
            Object key = names.nextElement(); assertTrue(allowed.contains(key), "Unexpected HTML attribute: " + key);
            if (attributes.getAttribute(key) instanceof AttributeSet nested) assertSafeAttributes(nested);
        }
    }

    private static void assertSafeView(View view) {
        assertFalse(view instanceof javax.swing.text.html.ImageView);
        assertFalse(view instanceof javax.swing.text.html.ObjectView);
        assertFalse(view instanceof javax.swing.text.html.FormView);
        for (int i = 0; i < view.getViewCount(); i++) assertSafeView(view.getView(i));
    }

    private static void paint(JToolTip tip) {
        var size = tip.getPreferredSize(); tip.setSize(size);
        var image = new BufferedImage(Math.max(1, size.width), Math.max(1, size.height), BufferedImage.TYPE_INT_ARGB);
        var graphics = image.createGraphics(); try { tip.paint(graphics); } finally { graphics.dispose(); }
    }
}

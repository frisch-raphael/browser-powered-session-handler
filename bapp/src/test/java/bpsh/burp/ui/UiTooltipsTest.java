package bpsh.burp.ui;

import bpsh.journey.persistence.JourneyDocument;
import bpsh.request.RequestSettings;
import java.awt.image.BufferedImage;
import javax.swing.*;
import javax.swing.plaf.ComponentUI;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.plaf.basic.BasicToolTipUI;
import javax.swing.text.View;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class UiTooltipsTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path root;

    /** Reproduces the installed Burp factory setting html.disable before delegating to its tooltip UI. */
    public static class HtmlDisabledToolTipUI extends BasicToolTipUI {
        public static ComponentUI createUI(JComponent component) {
            component.putClientProperty("html.disable",Boolean.TRUE);
            return new HtmlDisabledToolTipUI();
        }
    }

    @Test void formattedHelpSurvivesHostHtmlDisableThemeUpdatesAndEscapesLiteralMarkup() throws Exception {
        SwingUtilities.invokeAndWait(()->withHostDefaults(()->{
            String text="Wait for login.\n\nKeep <@journey/> and <img src='https://invalid.example/private'> literal & readable.";
            var baseline=new JToolTip();baseline.setTipText("<html><b>Selected policy</b><br>Wait for login.</html>");
            assertEquals(Boolean.TRUE,baseline.getClientProperty("html.disable"));assertNull(baseline.getClientProperty(BasicHTML.propertyKey));
            var control=UiTooltips.comboBox(new String[]{"Wait for login","Send immediately"});
            UiTooltips.set(control,text,340,"Selected policy");
            var panel=JourneyForms.form();JourneyForms.row(panel,"Automatic handling policy",control);
            var caption=(JLabel)control.getClientProperty("rowLabel");
            for(var owner:new JComponent[]{control,caption}) {
                var tip=render(owner);assertInstanceOf(HtmlDisabledToolTipUI.class,tip.getUI());
                var view=(View)tip.getClientProperty(BasicHTML.propertyKey);
                try {
                    String visible=view.getDocument().getText(0,view.getDocument().getLength());
                    assertTrue(visible.contains("Selected policy"));assertTrue(visible.contains("<@journey/>"));
                    assertTrue(visible.contains("<img src='https://invalid.example/private'>"));assertFalse(visible.contains("<div"));
                }catch(javax.swing.text.BadLocationException error){throw new AssertionError(error);}
                assertEquals(text,tip.getAccessibleContext().getAccessibleDescription());
                tip.updateUI();assertEquals(Boolean.FALSE,tip.getClientProperty("html.disable"));
                assertInstanceOf(View.class,tip.getClientProperty(BasicHTML.propertyKey));
            }
            assertEquals(HtmlDisabledToolTipUI.class.getName(),UIManager.get("ToolTipUI"));
            UiTooltips.set(control,null,340);assertNull(control.getToolTipText());assertNull(caption.getToolTipText());
            assertThrows(IllegalArgumentException.class,()->UiTooltips.set(control,"text",0));
        }));
    }

    @Test void literalDataRenderersKeepHtmlDisabledWhenTheirTooltipOptsIn() throws Exception {
        SwingUtilities.invokeAndWait(()->withHostDefaults(()->{
            var literal=new JLabel();literal.putClientProperty("html.disable",Boolean.TRUE);literal.setText("<html><b>saved value</b>");
            UiTooltips.set(literal,"Description with <literal> data",320);
            var tip=UiTooltips.create(literal);tip.setTipText(literal.getToolTipText());
            assertEquals(Boolean.TRUE,literal.getClientProperty("html.disable"));assertNull(literal.getClientProperty(BasicHTML.propertyKey));
            assertEquals(Boolean.FALSE,tip.getClientProperty("html.disable"));assertInstanceOf(View.class,tip.getClientProperty(BasicHTML.propertyKey));
            for(var owner:new JComponent[]{UiTooltips.checkBox("Option"),UiTooltips.textField(20),
                    UiTooltips.table(new javax.swing.table.DefaultTableModel()),new PlaceholderTextField("Hint",20),new PlaceholderPasswordField("Hint",20)}) {
                UiTooltips.set(owner,"Long formatted help\n\nSecond paragraph",320);render(owner);
            }
        }));
    }

    @Test void realPolicySelectorAndCaptionRenderBothPoliciesWithMatchingPlainAccessibleHelp() throws Exception {
        var harness=new JourneyRegistryTest().new NativeUi();harness.root=root;
        try(var editor=harness.new Editor(JourneyRegistryTest.fixture(JourneyDocument.DocumentKind.PROJECT,false,false))) {
            harness.edt(()->{
                JComboBox<RequestSettings.RequestPolicy> policy=harness.member(editor.ui,"requestPolicy");
                JTextArea explanation=harness.member(editor.ui,"requestPolicyHelp");
                withHostDefaults(()->{
                    for(var selected:RequestSettings.RequestPolicy.values()) {
                        policy.setSelectedItem(selected);
                        var caption=(JLabel)policy.getClientProperty("rowLabel");
                        assertEquals(policy.getToolTipText(),caption.getToolTipText());assertTrue(policy.getToolTipText().contains("<b>"));
                        assertEquals(explanation.getText(),policy.getAccessibleContext().getAccessibleDescription());
                        assertEquals(explanation.getText(),caption.getAccessibleContext().getAccessibleDescription());
                        render(policy);render(caption);
                    }
                });
            });
        }
    }

    @Test void httpAllowedOriginsAndItsCaptionUseTheSameSafeRenderer() throws Exception {
        SwingUtilities.invokeAndWait(()->withHostDefaults(()->{
            var panel=new HttpAuthenticationPanel(()->{});
            var origins=java.util.Arrays.stream(panel.getComponents())
                .filter(JLabel.class::isInstance).map(JLabel.class::cast)
                .filter(label->"Allowed origins".equals(label.getText())).findFirst().orElseThrow();
            var field=(JComponent)origins.getLabelFor();
            assertEquals(field.getToolTipText(),origins.getToolTipText());
            assertTrue(field.getAccessibleContext().getAccessibleDescription().contains("Credentials are sent only to these addresses."));
            render(field);render(origins);
        }));
    }

    private static JToolTip render(JComponent owner) {
        var tip=owner.createToolTip();tip.setTipText(owner.getToolTipText());
        assertEquals(Boolean.FALSE,tip.getClientProperty("html.disable"));assertInstanceOf(View.class,tip.getClientProperty(BasicHTML.propertyKey));
        var size=tip.getPreferredSize();assertTrue(size.width>100&&size.width<700);assertTrue(size.height>30);
        tip.setSize(size);var image=new BufferedImage(size.width,size.height,BufferedImage.TYPE_INT_ARGB);
        var graphics=image.createGraphics();try{tip.paint(graphics);}finally{graphics.dispose();}
        return tip;
    }
    private static void withHostDefaults(Runnable work) {
        Object previous=UIManager.get("ToolTipUI");
        try{UIManager.put("ToolTipUI",HtmlDisabledToolTipUI.class.getName());work.run();}
        finally{UIManager.put("ToolTipUI",previous);}
    }
}

package bpsh.burp.ui;

import bpsh.journey.JourneyDraft;
import java.util.List;
import javax.swing.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OptionalCaptureUiTest {
    @Test void theLastCaptureCanBeRemovedAndAddedAgainWithoutInventingAnOutput() throws Exception {
        SwingUtilities.invokeAndWait(()->{
            var panel=new CredentialsPanel();panel.setInputs(List.of(new JourneyDraft.CredentialInput("","json_path","","","","","","","","disabled","")));
            var removed=new java.util.concurrent.atomic.AtomicInteger();panel.setChangeListener(removed::incrementAndGet);
            var remove=find(panel,"Remove token");assertNotNull(remove);assertTrue(remove.isEnabled());remove.doClick(0);
            assertTrue(panel.snapshot().isEmpty());assertEquals(1,removed.get());
            var add=find(panel,"Add token or cookie");assertNotNull(add);add.doClick(0);
            assertEquals(1,panel.snapshot().size());assertEquals(2,removed.get());assertEquals("",panel.snapshot().getFirst().origin());
        });
    }
    @Test void missingCaptureShowsActionableInlineGuidanceInTheEmptyState() throws Exception {
        SwingUtilities.invokeAndWait(()->{
            var panel=new CredentialsPanel();panel.setInputs(List.of());String guidance="Add a token or cookie capture for this form journey.";
            panel.showInvalid("extraction.tokens:",guidance,false);assertTrue(visibleError(panel,guidance));
            find(panel,"Add token or cookie").doClick(0);assertFalse(visibleError(panel,guidance));
        });
    }
    private static boolean visibleError(java.awt.Container root,String guidance) {
        for(var child:root.getComponents()) {
            if(child instanceof JTextArea text && text.isVisible() && guidance.equals(text.getText()))return true;
            if(child instanceof java.awt.Container container && visibleError(container,guidance))return true;
        }return false;
    }
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary;
    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(booleans={false,true})
    void transportOnlyJourneysCanRemoveCaptureSaveTestAndCopyARequestReference(boolean certificate) throws Exception {
        var h=new JourneyRegistryTest().new NativeUi();h.root=temporary;
        var root=(com.fasterxml.jackson.databind.node.ObjectNode)JourneyRegistryTest.JSON.readTree(JourneyRegistryTest.fixture(bpsh.journey.persistence.JourneyDocument.DocumentKind.PROJECT,false,false));
        root.put("schemaVersion",2);var definition=(com.fasterxml.jackson.databind.node.ObjectNode)root.at("/journeys/0");
        definition.putArray("steps");((com.fasterxml.jackson.databind.node.ObjectNode)definition.get("browser")).put("formAuthentication",false);
        if(certificate)definition.putObject("mtls").put("modulePath",temporary.resolve("fixture-pkcs11.dll").toString()).put("certificateSha256","12".repeat(32)).putArray("origins");
        else definition.putObject("httpAuthentication").put("protocol","BASIC").put("username","user-a").put("domain","").put("workstation","").putArray("origins").add("https://login.example");
        try(var editor=h.new Editor(root.toString())) {
            var entry=editor.registry.snapshot().resolve("employee");var key=entry.identity().key();
            h.edt(()->h.call(editor.ui,"open",new Class<?>[]{bpsh.journey.JourneyKey.class},key));
            h.await(()->{try{return !(boolean)h.member(editor.ui,"editorLoading");}catch(Exception error){return false;}});
            h.edt(()->{CredentialsPanel panel=h.member(editor.ui,"credentials");find(panel,"Remove token").doClick(0);h.call(editor.ui,"save",new Class<?>[]{boolean.class},false);});
            h.await(()->{try{return editor.saved();}catch(Exception error){return false;}});
            var saved=editor.registry.snapshot().entries().get(key).definition();assertNull(saved.draft());assertNull(saved.extraction());
            var dialogs=new java.util.concurrent.CopyOnWriteArrayList<String>();var copied=new java.util.concurrent.CopyOnWriteArrayList<String>();
            h.edt(()->{
                JourneyDialogs port=new JourneyDialogs(){
                    public java.nio.file.Path file(java.awt.Component parent,boolean save){throw new AssertionError();}
                    public boolean confirm(java.awt.Component parent,Object content,String title){throw new AssertionError();}
                    public void inform(java.awt.Component parent,String text){dialogs.add(text);}
                    public void copyText(String text){copied.add(text);}
                };
                var field=UiController.class.getDeclaredField("dialogs");field.setAccessible(true);field.set(editor.ui,port);
                ((JButton)h.member(editor.ui,"copyReferenceButton")).doClick(0);
            });
            assertEquals(List.of("BPSP-HTTP-AUTHENT: <@employee/>"),copied);
            var allocation=new bpsh.authentication.http.HttpMessageBody.Allocator(1024);
            var factory=new bpsh.authentication.http.HttpTransportFactory(){
                public bpsh.authentication.http.HttpMessageBody.Allocator bodies(){return allocation;}public void close(){}
                public java.util.concurrent.CompletableFuture<bpsh.authentication.http.HttpAuthenticationService> open(ScopeSpec spec,bpsh.journey.SecretStore.Values values,long deadline){
                    return java.util.concurrent.CompletableFuture.completedFuture(new bpsh.authentication.http.HttpAuthenticationService(){
                        public boolean isOpen(){return true;}public void close(){}
                        public Delivery admit(long end){return bpsh.support.IntegrationFixtures.httpDelivery(request->{
                            try(var body=allocation.builder(0)){return java.util.concurrent.CompletableFuture.completedFuture(new Response(200,List.of(),body.finish(),
                                new bpsh.authentication.http.HttpAuthenticationEvidence(certificate?null:bpsh.journey.HttpAuthentication.Protocol.BASIC,
                                    certificate?bpsh.authentication.http.HttpAuthenticationEvidence.Status.UNCONFIRMED:bpsh.authentication.http.HttpAuthenticationEvidence.Status.ACCEPTED)));}
                        });}
                    });
                }
            };
            try(var manager=new bpsh.authentication.http.HttpIdentityManager(editor.registry,editor.secrets,factory)){
                h.edt(()->{editor.ui.httpIdentities(manager);((JButton)h.member(editor.ui,"testButton")).doClick(0);});
                h.await(()->!dialogs.isEmpty());assertTrue(dialogs.getFirst().contains(certificate?"client-certificate":"HTTP authentication"),dialogs.toString());
                assertTrue(dialogs.getFirst().contains("No application cookie or token"),dialogs.toString());
                assertTrue(editor.clock.workers.isEmpty());assertNull(editor.coordinator.peek(editor.registry.snapshot().entries().get(key).identity()));
            }
        }
    }
    private static JButton find(java.awt.Container root,String label) {
        for(var child:root.getComponents()) {
            if(child instanceof JButton button && label.equals(button.getAccessibleContext().getAccessibleName()))return button;
            if(child instanceof java.awt.Container container) {var found=find(container,label);if(found!=null)return found;}
        }return null;
    }
}

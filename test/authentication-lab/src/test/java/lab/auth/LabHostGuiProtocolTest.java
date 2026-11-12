package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class LabHostGuiProtocolTest {
    @TempDir Path directory;
    private LabHostGuiProtocol.Session session() throws Exception {
        return new LabHostGuiProtocol.Session(UUID.randomUUID(),"linux",UUID.randomUUID(),"a".repeat(64),"b".repeat(64),directory.toRealPath());
    }
    private LabHostGuiProtocol.Command command() {
        var args=new JsonObject();args.addProperty("nonce","h0123456789abcdef");
        return new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.SEND_REPEATER,2000,args);
    }
    @Test void nativeUnchangedAnnotationRequiresSyntheticNonceAndOnlyKnownAssertionCodes() throws Exception {
        var session=session();var args=new JsonObject();args.addProperty("alias","host_failure_a");args.addProperty("code","ORDINARY_UNCHANGED");
        var missing=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.ASSERT_UI,2000,args);
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,missing),session));
        args.addProperty("nonce","h0123456789abcdef");var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.ASSERT_UI,2000,args);
        assertEquals("ORDINARY_UNCHANGED",LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,command),session).arguments().get("code").getAsString());
        args.addProperty("code","PRIVATE_SENTINEL");var unknown=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.ASSERT_UI,2000,args);
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,unknown),session));
    }
    @Test void commandIdentityFieldsTypesAndNonceAreClosed() throws Exception {
        var session=session();var command=command();var encoded=LabHostGuiProtocol.encode(session,command);
        assertEquals(command.operationId(),LabHostGuiProtocol.command(encoded,session).operationId());
        encoded.addProperty("password","SECRET_SENTINEL");assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(encoded,session));
        encoded.remove("password");encoded.addProperty("runNonce",UUID.randomUUID().toString());
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(encoded,session));
        var bad=LabHostGuiProtocol.encode(session,command);bad.getAsJsonObject("arguments").addProperty("nonce","arbitrary-private-data");
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(bad,session));
    }
    @Test void claimedSendIsAmbiguousUntilReceiptAndNeverBecomesNewAgain() throws Exception {
        var session=session();var command=command();
        var claim=LabHostGuiProtocol.claim(session,command,1,1000);assertEquals(LabHostGuiProtocol.ClaimState.NEW,claim.state());
        assertEquals(LabHostGuiProtocol.ClaimState.AMBIGUOUS,LabHostGuiProtocol.claim(session,command,1,3000).state());
        Files.createDirectories(claim.receipt().getParent());
        LabJson.writeNew(claim.receipt(),LabHostGuiProtocol.receipt(session,command,1000,1500,"PASS","SEND_COMPLETED",new JsonObject()));
        assertEquals(LabHostGuiProtocol.ClaimState.COMPLETED,LabHostGuiProtocol.claim(session,command,1,3000).state());
        var changed=new LabHostGuiProtocol.Command(2,command.operationId(),command.operation(),4000,command.arguments());
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.claim(session,changed,2,3000));
    }
    @Test void expiredOrOutOfOrderCommandsNeverAcquireAClaim() throws Exception {
        var session=session();var command=command();
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.claim(session,command,2,1000));
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.claim(session,command,1,2000));
        try(var files=Files.list(directory.resolve("gui/claims"))){assertEquals(0,files.count());}
    }
    @Test void requestFilesCannotEscapeTheOwnedDirectory() throws Exception {
        var session=session();var args=new JsonObject();args.addProperty("path","../secret");args.addProperty("nonce","h0123456789abcdef");
        var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.SET_REPEATER_REQUEST,2000,args);
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.command(LabHostGuiProtocol.encode(session,command),session));
    }
    @Test void diagnosticGraceAcceptsFailurePublicationButNeverALatePass() throws Exception {
        var session=session();var command=command();
        var failed=LabHostGuiProtocol.receipt(session,command,1000,2500,"FAIL","GUI_DEADLINE",new JsonObject());
        assertEquals("FAIL",LabHostGuiProtocol.validateReceipt(failed,session,command).get("outcome").getAsString());
        var late=LabHostGuiProtocol.receipt(session,command,1000,2500,"PASS","COMPLETED",new JsonObject());
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateReceipt(late,session,command));
    }
    @Test void loginReceiptAllowsOnlyFixedResultAndProtocolMetadata() throws Exception {
        var session=session();var args=new JsonObject();args.addProperty("alias","host_basic_a");
        var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.TEST_LOGIN,2000,args);
        var observed=new JsonObject();observed.addProperty("loginResult","HTTP_AUTHENTICATED");observed.addProperty("httpProtocol","BASIC");
        var receipt=LabHostGuiProtocol.receipt(session,command,1000,1500,"PASS","COMPLETED",observed);
        assertNotNull(LabHostGuiProtocol.validateReceipt(receipt,session,command));
        receipt.getAsJsonObject("observed").addProperty("password","PRIVATE_SENTINEL");
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateReceipt(receipt,session,command));
        receipt.getAsJsonObject("observed").remove("password");receipt.getAsJsonObject("observed").addProperty("httpProtocol","PRIVATE_SENTINEL");
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateReceipt(receipt,session,command));
    }
    @Test void retainedProofHashesPrivateInputsAndNeverPublishesTheirPathsOrContents() throws Exception {
        var session=session();Files.writeString(directory.resolve("PRIVATE_SENTINEL.txt"),"PRIVATE_SECRET_VALUE");
        var args=new JsonObject();args.addProperty("path","PRIVATE_SENTINEL.txt");args.addProperty("nonce","h0123456789abcdef");
        var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.SET_REPEATER_REQUEST,2000,args);
        var value=LabHostGuiProtocol.retainedReceipt(LabHostGuiProtocol.receipt(session,command,1000,1500,"PASS","COMPLETED",new JsonObject()),session,command);
        assertEquals(LabJson.sha256(directory.resolve("PRIVATE_SENTINEL.txt")),value.getAsJsonObject("intent").get("inputSha256").getAsString());
        assertFalse(value.toString().contains("PRIVATE_"));assertFalse(value.getAsJsonObject("intent").has("path"));
        assertNotNull(LabHostGuiProtocol.validateRetainedReceipt(value,session));
        value.getAsJsonObject("intent").addProperty("path","PRIVATE_SENTINEL.txt");
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateRetainedReceipt(value,session));
    }
    @Test void retainedProofRejectsLatePassForeignIdentityAndArbitrarySecretReferences() throws Exception {
        var session=session();var args=new JsonObject();args.addProperty("alias","host_a");args.addProperty("secret","FORM_A");
        var command=new LabHostGuiProtocol.Command(1,UUID.randomUUID(),LabHostGuiProtocol.Operation.ENTER_SECRET,2000,args);
        var value=LabHostGuiProtocol.retainedReceipt(LabHostGuiProtocol.receipt(session,command,1000,1500,"PASS","COMPLETED",new JsonObject()),session,command);
        assertEquals("FORM_A",value.getAsJsonObject("intent").get("secretRef").getAsString());assertFalse(value.getAsJsonObject("intent").has("secret"));
        var late=value.deepCopy();late.addProperty("deadlineEpochMs",1499);
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateRetainedReceipt(late,session));
        var foreign=value.deepCopy();foreign.addProperty("runNonce",UUID.randomUUID().toString());
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateRetainedReceipt(foreign,session));
        value.getAsJsonObject("intent").addProperty("secretRef","PRIVATE_SENTINEL");
        assertThrows(IllegalArgumentException.class,()->LabHostGuiProtocol.validateRetainedReceipt(value,session));
    }
}

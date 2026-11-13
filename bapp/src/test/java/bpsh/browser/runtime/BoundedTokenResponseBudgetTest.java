package bpsh.browser.runtime;

import bpsh.authentication.AuthenticationFailure;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BoundedTokenResponseBudgetTest {
    private final BoundedTokenResponses.Capture capture=new BoundedTokenResponses.Capture(){
        public boolean matches(String url){return true;}public boolean complete(){return false;}
        public void declaredLength(String length){}public void response(String url,byte[] body,boolean success){}
        public void failure(AuthenticationFailure failure){}
    };
    @Test void newCandidatesAreAdmittedBehindUnfinishedResponsesWithoutExceedingTheSharedByteBudget() throws Exception {
        var budget=new BoundedTokenResponses.ResponseCollection<String>(capture);
        var first=new BoundedTokenResponses.ObservedBody("first",200);budget.start("first",first);budget.append("first",first,new byte[1<<20]);
        for(int i=0;i<3;i++){var body=new BoundedTokenResponses.ObservedBody("asset",200);budget.start("asset"+i,body);budget.append("asset"+i,body,new byte[1<<20]);}
        var token=new BoundedTokenResponses.ObservedBody("token",200);budget.start("token",token);budget.append("token",token,new byte[]{1,2,3});
        assertSame(token,budget.get("token"));assertNull(budget.get("first"));assertTrue(budget.retained<=4*(1<<20));
        int before=budget.retained;budget.append("first",first,new byte[]{4});assertEquals(before,budget.retained);
        budget.retire("token",token);int after=budget.retained;budget.retire("token",token);assertEquals(after,budget.retained);budget.clear();assertEquals(0,budget.retained);
    }
    @Test void metadataIsBoundedAndReentrantPrefixAssemblyKeepsOrderAndThePerResponseLimit() throws Exception {
        var budget=new BoundedTokenResponses.ResponseCollection<Integer>(capture);
        for(int i=0;i<1000;i++)budget.start(i,new BoundedTokenResponses.ObservedBody("asset",200));
        assertTrue(budget.streams.size()<=128);var body=budget.get(999);
        budget.append(999,body,new byte[]{3,4});budget.prepend(999,body,new byte[]{1,2});
        assertArrayEquals(new byte[]{1,2,3,4},body.bytes.toByteArray());assertEquals(4,budget.retained);
        assertThrows(AuthenticationFailure.class,()->budget.append(999,body,new byte[1<<20]));assertEquals(4,budget.retained);
    }
    @Test void completedResponseReplacementCountsWholeBodyOnceAndCannotReviveAnEvictedRecord() throws Exception {
        var budget=new BoundedTokenResponses.ResponseCollection<String>(capture);
        var body=new BoundedTokenResponses.ObservedBody("token",200);budget.start("token",body);
        budget.append("token",body,new byte[]{1,2});budget.replace("token",body,new byte[]{1,2,3,4});
        assertEquals(4,budget.retained);assertArrayEquals(new byte[]{1,2,3,4},body.bytes.toByteArray());
        assertThrows(AuthenticationFailure.class,()->budget.replace("token",body,new byte[(1<<20)+1]));
        assertEquals(4,budget.retained);budget.retire("token",body);
        budget.replace("token",body,new byte[]{9});assertEquals(0,budget.retained);assertNull(budget.get("token"));
    }
    @Test void completedTextIsLimitedByUtf8BytesAndBinaryByDecodedBytes() throws Exception {
        var text=new com.google.gson.JsonObject();text.addProperty("body","\u00e9".repeat(1<<19));
        assertEquals(1<<20,BoundedTokenResponses.decodeFinished(text).length);
        text.addProperty("body","\u00e9".repeat((1<<19)+1));
        assertThrows(AuthenticationFailure.class,()->BoundedTokenResponses.decodeFinished(text));
        text.addProperty("body","\ud800");
        assertThrows(AuthenticationFailure.class,()->BoundedTokenResponses.decodeFinished(text));
        var binary=new com.google.gson.JsonObject();binary.addProperty("base64Encoded",true);
        binary.addProperty("body",java.util.Base64.getEncoder().encodeToString(new byte[1<<20]));
        assertEquals(1<<20,BoundedTokenResponses.decodeFinished(binary).length);
        binary.addProperty("body",java.util.Base64.getEncoder().encodeToString(new byte[(1<<20)+3]));
        assertThrows(AuthenticationFailure.class,()->BoundedTokenResponses.decodeFinished(binary));
    }
}

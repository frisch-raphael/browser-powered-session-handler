package bpsh.burp.http;

import bpsh.authentication.http.HttpAuthenticationService;
import bpsh.authentication.http.HttpAuthenticationEvidence;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HttpAuthenticationResponseTest {
    @Test void rejectedForbiddenAndServerErrorsKeepHeadersDuplicateCookiesAndBinaryBody() {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.fidelity.errors");
        var statuses=new java.util.ArrayList<Integer>();var cookies=new java.util.ArrayList<Long>();var bodies=new java.util.ArrayList<Integer>();
        for(int status : List.of(401,403,500)) {
            var response = response(status);
            byte[] wire = wire("GET",response);
            String text = new String(wire,StandardCharsets.ISO_8859_1);
            assertTrue(text.startsWith("HTTP/1.1 " + status + " "));
            assertTrue(text.contains("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n"));
            assertTrue(text.contains("Content-Length: 3\r\n"));
            assertArrayEquals(new byte[]{0,(byte)255,1},java.util.Arrays.copyOfRange(wire,wire.length-3,wire.length));
            statuses.add(Integer.parseInt(text.split(" ")[1]));cookies.add(text.lines().filter(l->l.startsWith("Set-Cookie:")).count());bodies.add(wire.length-text.indexOf("\r\n\r\n")-4);proof.put("statuses",statuses);proof.put("cookieCounts",cookies);proof.put("bodyBytes",bodies);
        }
        proof.write();
    }
    @Test void headAnd304RetainRepresentationLengthWithoutAnEntityAnd204OmitsFraming() {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.fidelity.no-entity");
        var bytes=new java.util.ArrayList<Integer>();var lengths=new java.util.ArrayList<Boolean>();
        for(var test : List.of(new String[]{"HEAD","200"},new String[]{"GET","304"},new String[]{"GET","204"})) {
            String wire = new String(wire(test[0],response(Integer.parseInt(test[1]))),StandardCharsets.ISO_8859_1);
            assertTrue(wire.endsWith("\r\n\r\n"));
            assertEquals(!test[1].equals("204"),wire.contains("Content-Length: 123\r\n"));
            bytes.add(wire.length()-wire.indexOf("\r\n\r\n")-4);lengths.add(wire.contains("Content-Length: 123\r\n"));proof.put("entityBytes",bytes);proof.put("lengths",lengths);
        }
        proof.write();
    }
    private static byte[] wire(String method,HttpAuthenticationService.Response response) {
        var allocator=new bpsh.authentication.http.HttpMessageBody.Allocator(32L*1024*1024);
        try(response;var owned=HttpAuthenticationResponse.wire(allocator,method,response)) {return owned.borrowed().clone();}
        catch(java.io.IOException failure) {throw new AssertionError(failure);}
    }
    private static HttpAuthenticationService.Response response(int status) {
        return new HttpAuthenticationService.Response(status,List.of(
                new HttpAuthenticationService.Header("Set-Cookie","a=1"),new HttpAuthenticationService.Header("Set-Cookie","b=2"),
                new HttpAuthenticationService.Header("Content-Length","123")),bpsh.support.IntegrationFixtures.httpBody(new byte[]{0,(byte)255,1}),
                new HttpAuthenticationEvidence(null,HttpAuthenticationEvidence.Status.UNCONFIRMED));
    }
}

package bpsh.transport.httpauth;

import bpsh.journey.HttpAuthentication;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NtlmMessagesTest {
    @Test void malformedChallengeProducesSafeProgressWithoutLoggingTheChallengeOrPassword() throws Exception {
        var events=new java.util.ArrayList<bpsh.authentication.http.HttpAuthenticationProgress.Stage>();
        var scheme=new NtlmAuthScheme(settings(HttpAuthentication.Protocol.NTLM_V2),()->"private-password".toCharArray(),()->"user",
                (context,stage)->events.add(stage));
        var context=org.apache.hc.client5.http.protocol.HttpClientContext.create();
        var challenge=new org.apache.hc.client5.http.auth.AuthChallenge(org.apache.hc.client5.http.auth.ChallengeType.TARGET,"NTLM","private-invalid-challenge",java.util.List.of());
        var error=assertThrows(org.apache.hc.client5.http.auth.MalformedChallengeException.class,()->scheme.processChallenge(challenge,context));
        assertEquals(java.util.List.of(bpsh.authentication.http.HttpAuthenticationProgress.Stage.INVALID_CHALLENGE),events);
        assertFalse(error.getMessage().contains("private-invalid-challenge"));assertFalse(error.getMessage().contains("private-password"));
    }
    private static HttpAuthentication settings(HttpAuthentication.Protocol protocol) {
        return new HttpAuthentication(protocol,"User","Domain","",Set.of(URI.create("http://server")));
    }
    private static byte[] challenge(int flags) {
        var buffer=ByteBuffer.allocate(56).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(new byte[]{'N','T','L','M','S','S','P',0}).putInt(2);
        buffer.position(20);buffer.putInt(flags).put(HexFormat.of().parseHex("0123456789abcdef"));
        return buffer.array();
    }
    @Test void strictV1MatchesTheIndependentPublishedNtResponseVector() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.protocol.v1-vector");
        var protocol=HttpAuthentication.Protocol.NTLM_V1;
        byte[] response=NtlmMessages.authenticate(settings(protocol),"Password".toCharArray(),NtlmMessages.negotiate(protocol),challenge(0x201),"server",null);
        var fields=ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN);
        int size=Short.toUnsignedInt(fields.getShort(20)),offset=fields.getInt(24);
        assertEquals("67c43011f30298a2ad35ece64f16331c44bdbed927841f94",HexFormat.of().formatHex(Arrays.copyOfRange(response,offset,offset+size)));
        int lmSize=Short.toUnsignedInt(fields.getShort(12)),lmOffset=fields.getInt(16);
        assertArrayEquals(Arrays.copyOfRange(response,offset,offset+size),Arrays.copyOfRange(response,lmOffset,lmOffset+lmSize));
            proof.put("ntBytes",size);proof.put("lmBytes",lmSize);proof.put("sameProof",Arrays.equals(Arrays.copyOfRange(response,offset,offset+size),Arrays.copyOfRange(response,lmOffset,lmOffset+lmSize)));
        proof.write();
    }
    @Test void bothVariantsOfferAlwaysSignAndRejectMessageProtectionFlags() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.protocol.protection-flags");
        int variants=0,rejections=0;
        for(var protocol:new HttpAuthentication.Protocol[]{HttpAuthentication.Protocol.NTLM_V1,HttpAuthentication.Protocol.NTLM_V2}) {
            byte[] negotiate=NtlmMessages.negotiate(protocol);
            assertNotEquals(0,ByteBuffer.wrap(negotiate).order(ByteOrder.LITTLE_ENDIAN).getInt(12)&0x8000);variants++;
            for(int unsupported:new int[]{0x10,0x20,0x40,0x80,0x00400000,0x40000000}) {
                assertThrows(java.io.IOException.class,()->NtlmMessages.authenticate(settings(protocol),"Password".toCharArray(),negotiate,challenge(0x201|unsupported),"server",null));rejections++;}
            proof.put("variants",variants);proof.put("rejections",rejections);
        }
        proof.write();
    }
    @Test void strictV1RejectsNtlm2SessionAndV2RequiresTargetInformation() throws Exception {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.protocol.variant-requirements");
        var v1=assertThrows(java.io.IOException.class,()->NtlmMessages.authenticate(settings(HttpAuthentication.Protocol.NTLM_V1),"Password".toCharArray(),
                NtlmMessages.negotiate(HttpAuthentication.Protocol.NTLM_V1),challenge(0x00080201),"server",null));
        var v2=assertThrows(java.io.IOException.class,()->NtlmMessages.authenticate(settings(HttpAuthentication.Protocol.NTLM_V2),"Password".toCharArray(),
                NtlmMessages.negotiate(HttpAuthentication.Protocol.NTLM_V2),challenge(0x00080201),"server",null));
            proof.put("v1RejectedEss",v1!=null);proof.put("v2RequiresInfo",v2!=null);
        proof.write();
    }
    @Test void malformedOffsetsLengthsAndTargetInformationFailBeforeLibraryParsing() {
        var proof=new bpsh.support.HttpBoundaryCapture("HTTP.auth.protocol.malformed");
        var invalid=new java.util.ArrayList<byte[]>();invalid.add(new byte[31]);invalid.add(new byte[NtlmMessages.MAX_CHALLENGE+1]);
        byte[] signature=challenge(0x201);signature[0]='X';invalid.add(signature);
        byte[] type=challenge(0x201);ByteBuffer.wrap(type).order(ByteOrder.LITTLE_ENDIAN).putInt(8,3);invalid.add(type);
        for(int offset:new int[]{-1,1,65536}) {
            byte[] malformed=challenge(0x201);ByteBuffer.wrap(malformed).order(ByteOrder.LITTLE_ENDIAN)
                    .putShort(12,(short)4).putShort(14,(short)4).putInt(16,offset);invalid.add(malformed);
        }
        byte[] shortAllocation=challenge(0x201);ByteBuffer.wrap(shortAllocation).order(ByteOrder.LITTLE_ENDIAN)
                .putShort(12,(short)4).putShort(14,(short)2).putInt(16,48);invalid.add(shortAllocation);
        for(byte[] av:new byte[][]{
                {6,0,4,0,0,0,0,0,6,0,4,0,0,0,0,0,0,0,0,0}, // duplicate flags
                {7,0,4,0,0,0,0,0,0,0,0,0}, // timestamp must be eight bytes
                {1,0,1,0,65,0,0,0,0}, // odd UTF-16 length
                {0,0,0,0,1}, // bytes after terminator
                {6,0,4,0,0,0}, // truncated value
                {6,0,4,0,0,0,0,0} // missing terminator
        }) {
            byte[] value=Arrays.copyOf(challenge(0x00880201),56+av.length);
            ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).putShort(40,(short)av.length).putShort(42,(short)av.length).putInt(44,56);
            System.arraycopy(av,0,value,56,av.length);invalid.add(value);
        }
        int rejected=0;for(byte[] value:invalid) {assertThrows(java.io.IOException.class,()->NtlmMessages.validateChallenge(value));rejected++;}proof.put("rejected",rejected);
        proof.write();
    }
}

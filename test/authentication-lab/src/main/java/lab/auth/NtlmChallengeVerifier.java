package lab.auth;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Independent server verifier: wire structures and standard crypto, no production or jcifs code. */
final class NtlmChallengeVerifier {
    private static final byte[] SIGNATURE = {'N','T','L','M','S','S','P',0};
    private final boolean v2;
    private final byte[] nonce = new byte[8];
    private final byte[] timestamp = le(new byte[8]).putLong((System.currentTimeMillis() + 11644473600000L) * 10000L).array();
    private final byte[] binding;
    private byte[] negotiate, challenge;

    NtlmChallengeVerifier(boolean v2, byte[] binding) { this.v2 = v2; this.binding = binding; new SecureRandom().nextBytes(nonce); }

    byte[] challenge(byte[] type1) throws IOException {
        if (type(type1) != 1 || type1.length < 32) throw new IOException("Expected negotiate message.");
        negotiate = type1.clone();
        int flags = 0x02000201 | (v2 ? 0x00880000 : 0);
        byte[] target = "LAB".getBytes(StandardCharsets.UTF_16LE);
        ByteBuffer av = le(new byte[16]); av.putShort((short)7).putShort((short)8).put(timestamp).putInt(0);
        ByteBuffer message = le(new byte[56 + target.length + (v2 ? av.capacity() : 0)]);
        message.put(SIGNATURE).putInt(2);
        message.putShort((short)target.length).putShort((short)target.length).putInt(56);
        message.putInt(flags).put(nonce).putLong(0);
        message.putShort((short)(v2 ? av.capacity() : 0)).putShort((short)(v2 ? av.capacity() : 0)).putInt(56 + target.length);
        message.put(new byte[]{10,0,0,0,0,0,0,15}).put(target);
        if (v2) message.put(av.array());
        challenge = message.array(); return challenge.clone();
    }

    String verify(byte[] type3, Map<String,String> users) throws Exception {
        if (type(type3) != 3 || challenge == null || type3.length < 64) return null;
        String user = new String(field(type3, 36), StandardCharsets.UTF_16LE);
        String domain = new String(field(type3, 28), StandardCharsets.UTF_16LE);
        String password = users.get(user);
        if (password == null || !domain.equals("LAB")) return null;
        byte[] hash = MessageDigest.getInstance("MD4", new BouncyCastleProvider()).digest(password.getBytes(StandardCharsets.UTF_16LE));
        byte[] response = field(type3,20);
        int flags = le(type3).getInt(60);
        if (!v2) {
            if ((flags & 0x80000) != 0 || response.length != 24) return null;
            byte[] padded = Arrays.copyOf(hash, 21), expected = new byte[24];
            for (int i=0;i<3;i++) {
                byte[] key = desKey(Arrays.copyOfRange(padded, i*7, i*7+7));
                Cipher des = Cipher.getInstance("DES/ECB/NoPadding"); des.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"DES"));
                System.arraycopy(des.doFinal(nonce),0,expected,i*8,8);
            }
            return MessageDigest.isEqual(expected,response) ? user : null;
        }
        if ((flags & 0x80000) == 0 || response.length < 48 || type3.length < 88) return null;
        byte[] blob = Arrays.copyOfRange(response,16,response.length);
        if (le(blob).getInt(0) != 0x101 || !Arrays.equals(timestamp,Arrays.copyOfRange(blob,8,16))) return null;
        Map<Integer,byte[]> av = av(blob,28);
        if (av.get(6) == null || (le(av.get(6)).getInt() & 2) == 0) return null;
        if (binding != null && !MessageDigest.isEqual(binding,av.getOrDefault(10,new byte[0]))) throw new IOException("Destination TLS channel binding did not match.");
        if (!"HTTP/127.0.0.1".equals(new String(av.getOrDefault(9,new byte[0]),StandardCharsets.UTF_16LE))) return null;
        byte[] key = hmac(hash, (user.toUpperCase(Locale.ROOT)+domain).getBytes(StandardCharsets.UTF_16LE));
        byte[] proof = hmac(key, nonce, blob);
        if (!MessageDigest.isEqual(proof, Arrays.copyOf(response,16))) return null;
        byte[] session = hmac(key,proof);
        byte[] zeroMic = type3.clone(); Arrays.fill(zeroMic,72,88,(byte)0);
        if (!MessageDigest.isEqual(Arrays.copyOfRange(type3,72,88),hmac(session,negotiate,challenge,zeroMic))) return null;
        return user;
    }

    static int type(byte[] message) throws IOException {
        if (message.length < 12 || message.length > 65536 || !Arrays.equals(SIGNATURE,Arrays.copyOf(message,8))) throw new IOException("Invalid NTLM message.");
        return le(message).getInt(8);
    }
    private static byte[] field(byte[] message,int at) throws IOException {
        ByteBuffer b=le(message); int size=Short.toUnsignedInt(b.getShort(at)); long offset=Integer.toUnsignedLong(b.getInt(at+4));
        if (offset+size>message.length) throw new IOException("Invalid NTLM field.");
        return Arrays.copyOfRange(message,(int)offset,(int)offset+size);
    }
    private static Map<Integer,byte[]> av(byte[] data,int start) throws IOException {
        var result=new HashMap<Integer,byte[]>(); ByteBuffer b=le(data); b.position(start);
        while(b.remaining()>=4) {
            int id=Short.toUnsignedInt(b.getShort()), length=Short.toUnsignedInt(b.getShort());
            if(id==0 && length==0) return result;
            if(length>b.remaining() || result.containsKey(id)) throw new IOException("Invalid AV pair.");
            byte[] value=new byte[length];b.get(value);result.put(id,value);
        }
        throw new IOException("Missing AV terminator.");
    }
    private static byte[] desKey(byte[] key) {
        byte[] out=new byte[8]; long bits=0;for(byte value:key)bits=(bits<<8)|(value&255L);
        for(int i=0;i<8;i++)out[i]=(byte)(((bits>>>(49-i*7))&127)<<1);
        return out;
    }
    private static byte[] hmac(byte[] key,byte[]... values) throws Exception {
        Mac mac=Mac.getInstance("HmacMD5");mac.init(new SecretKeySpec(key,"HmacMD5"));for(byte[] value:values)mac.update(value);return mac.doFinal();
    }
    private static ByteBuffer le(byte[] value) { return ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN); }
}

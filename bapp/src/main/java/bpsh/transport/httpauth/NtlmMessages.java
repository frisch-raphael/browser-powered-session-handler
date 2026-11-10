package bpsh.transport.httpauth;

import bpsh.journey.HttpAuthentication;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.NtlmUtil;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import static jcifs.ntlmssp.NtlmFlags.*;

/** Isolates jcifs message primitives from HTTP, TLS providers and application configuration. */
final class NtlmMessages {
    private static final int DATAGRAM_FLAG = 0x00000040;
    static final int MAX_CHALLENGE = 64 * 1024;
    private static final byte[] SIGNATURE = {'N','T','L','M','S','S','P',0};
    private static final SecureRandom RANDOM = new SecureRandom();

    private NtlmMessages() { }

    static byte[] negotiate(HttpAuthentication.Protocol protocol) throws IOException {
        var configuration = new Properties();
        configuration.setProperty("jcifs.smb.client.useUnicode", "true");
        BaseContext context = new BaseContext(new PropertyConfiguration(configuration));
        try {
            Type1Message message = new Type1Message(context, flags(protocol), "", "");
            message.setFlags(flags(protocol));
            return message.toByteArray();
        } finally { context.close(); }
    }

    private static int flags(HttpAuthentication.Protocol protocol) {
        int flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_REQUEST_TARGET |
                NTLMSSP_NEGOTIATE_VERSION | NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
        if (protocol == HttpAuthentication.Protocol.NTLM_V2)
            flags |= NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_TARGET_INFO |
                    NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56;
        return flags;
    }

    /** Bounded validation precedes the library parser, including all server-controlled offsets. */
    static void validateChallenge(byte[] raw) throws IOException {
        if (raw.length < 32 || raw.length > MAX_CHALLENGE ||
                !Arrays.equals(SIGNATURE, Arrays.copyOf(raw, 8)) || little(raw).getInt(8) != 2)
            throw new IOException("Invalid NTLM challenge.");
        securityBuffer(raw, 12);
        int flags = little(raw).getInt(20);
        if ((flags & NTLMSSP_NEGOTIATE_UNICODE) == 0 || (flags & NTLMSSP_NEGOTIATE_NTLM) == 0)
            throw new IOException("The server does not support Unicode NTLM authentication.");
        if ((flags & NTLMSSP_NEGOTIATE_VERSION) != 0 && raw.length < 56)
            throw new IOException("Truncated NTLM challenge version.");
        if ((flags & NTLMSSP_NEGOTIATE_TARGET_INFO) != 0) {
            if (raw.length < 48) throw new IOException("Truncated NTLM target information.");
            parseAv(securityBuffer(raw, 40));
        }
    }

    static byte[] authenticate(HttpAuthentication settings, char[] password, byte[] negotiate,
                               byte[] challenge, String hostname, byte[] channelBinding)
            throws IOException, GeneralSecurityException {
        validateChallenge(challenge);
        Type2Message type2 = new Type2Message(challenge);
        int offered = type2.getFlags();
        int unsupported = DATAGRAM_FLAG | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL |
                NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_LM_KEY | NTLMSSP_REQUEST_NON_NT_SESSION_KEY;
        if((offered & unsupported) != 0) throw new IOException("The server requires unsupported NTLM message protection.");
        if(settings.protocol() == HttpAuthentication.Protocol.NTLM_V1) {
            if((offered & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) != 0)
                throw new IOException("The server selected extended session security for strict NTLMv1.");
            Map<Integer,byte[]> requirements = parseAv(type2.getTargetInformation());
            if(requirements.containsKey(10) || requirements.containsKey(6) && (little(requirements.get(6)).getInt() & 2) != 0)
                throw new IOException("The server requires MIC or channel binding unsupported by strict NTLMv1.");
        } else if((offered & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) == 0 ||
                (offered & NTLMSSP_NEGOTIATE_TARGET_INFO) == 0 || type2.getTargetInformation() == null || type2.getTargetInformation().length < 4) {
            throw new IOException("Strict NTLMv2 requires extended session security and target information.");
        }
        int selected = flags(settings.protocol()) & type2.getFlags();
        // No signing/sealing or key exchange was offered: HTTP supplies its own message transport.
        selected &= ~(NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL);
        byte[] hash = NtlmUtil.getNTHash(new String(password));
        byte[] responseKey = null, sessionKey = null;
        try {
            if (settings.protocol() == HttpAuthentication.Protocol.NTLM_V1) {
                byte[] response = NtlmUtil.getNTLMResponse(hash, type2.getChallenge());
                // LM compatibility level 2: send the NT response in both fields, never an LM hash.
                return new Type3Message(selected, response, response, settings.domain(), settings.username(), settings.workstation()).toByteArray();
            }
            Map<Integer, byte[]> av = parseAv(type2.getTargetInformation());
            byte[] serverTimestamp = av.get(7);
            long timestamp = serverTimestamp == null ? (System.currentTimeMillis() + 11644473600000L) * 10000L : little(serverTimestamp).getLong();
            String spn = "HTTP/" + hostname.toLowerCase(Locale.ROOT);
            byte[] offeredSpn = av.get(9);
            if (offeredSpn != null && !new String(offeredSpn, StandardCharsets.UTF_16LE).equalsIgnoreCase(spn))
                throw new IOException("The NTLM challenge names a different destination.");
            av.put(9, spn.getBytes(StandardCharsets.UTF_16LE));
            if (channelBinding != null) {
                if (channelBinding.length != 16) throw new IOException("Invalid NTLM channel binding.");
                av.put(10, channelBinding.clone());
            } else if (av.containsKey(10) && !Arrays.equals(av.get(10), new byte[16])) {
                throw new IOException("NTLM channel binding requires destination TLS.");
            }
            int avFlags = av.containsKey(6) ? little(av.get(6)).getInt() : 0;
            av.put(6, little(new byte[4]).putInt(avFlags | 2).array());
            byte[] nonce = new byte[8]; RANDOM.nextBytes(nonce);
            // jcifs uppercases with the default locale; supply the already invariant-uppercase name.
            responseKey = NtlmUtil.nTOWFv2(settings.domain(), settings.username().toUpperCase(Locale.ROOT), hash);
            byte[] nt = NtlmUtil.getNTLMv2Response(responseKey, type2.getChallenge(), nonce, timestamp, encodeAv(av));
            byte[] lm = serverTimestamp == null ? NtlmUtil.getLMv2Response(responseKey, type2.getChallenge(), nonce) : new byte[24];
            sessionKey = hmac(responseKey, Arrays.copyOf(nt, 16));
            Type3Message message = new Type3Message(selected, lm, nt, settings.domain(), settings.username(), settings.workstation());
            message.setMic(new byte[16]);
            message.setMic(hmac(sessionKey, negotiate, challenge, message.toByteArray()));
            return message.toByteArray();
        } finally {
            Arrays.fill(hash, (byte) 0);
            if (responseKey != null) Arrays.fill(responseKey, (byte) 0);
            if (sessionKey != null) Arrays.fill(sessionKey, (byte) 0);
        }
    }

    private static byte[] securityBuffer(byte[] raw, int offset) throws IOException {
        if (offset + 8 > raw.length) throw new IOException("Truncated NTLM security buffer.");
        ByteBuffer b = little(raw);
        int size = Short.toUnsignedInt(b.getShort(offset));
        long start = Integer.toUnsignedLong(b.getInt(offset + 4));
        if (Short.toUnsignedInt(b.getShort(offset + 2)) < size || start + size > raw.length || (size > 0 && start < 32))
            throw new IOException("Invalid NTLM security buffer.");
        return Arrays.copyOfRange(raw, (int) start, (int) start + size);
    }

    private static Map<Integer, byte[]> parseAv(byte[] raw) throws IOException {
        Map<Integer, byte[]> result = new LinkedHashMap<>();
        if (raw == null || raw.length == 0) return result;
        ByteBuffer b = little(raw);
        while (b.remaining() >= 4) {
            int id = Short.toUnsignedInt(b.getShort()), length = Short.toUnsignedInt(b.getShort());
            if (id == 0) {
                if (length != 0 || b.hasRemaining()) throw new IOException("Invalid NTLM target terminator.");
                return result;
            }
            if (length > b.remaining() || result.containsKey(id) ||
                    (id == 6 && length != 4) || (id == 7 && length != 8) || (id == 10 && length != 16) ||
                    ((id <= 5 || id == 9) && length % 2 != 0)) throw new IOException("Invalid NTLM target information.");
            byte[] value = new byte[length]; b.get(value); result.put(id, value);
        }
        throw new IOException("Missing NTLM target terminator.");
    }

    private static byte[] encodeAv(Map<Integer, byte[]> pairs) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (var entry : pairs.entrySet()) {
            out.write(little(new byte[4]).putShort((short) (int) entry.getKey()).putShort((short) entry.getValue().length).array());
            out.write(entry.getValue());
        }
        out.write(new byte[4]);
        return out.toByteArray();
    }

    private static ByteBuffer little(byte[] value) { return ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN); }
    private static byte[] hmac(byte[] key, byte[]... messages) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacMD5"); mac.init(new SecretKeySpec(key, "HmacMD5"));
        for (byte[] message : messages) mac.update(message);
        return mac.doFinal();
    }
}

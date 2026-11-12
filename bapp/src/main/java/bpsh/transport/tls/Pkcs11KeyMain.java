package bpsh.transport.tls;

import bpsh.authentication.AuthenticationFailure;
import bpsh.journey.JourneyDefinition;
import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PSSParameterSpec;
import java.util.*;

/** Isolated native key owner. Its authenticated parent is its sole caller; EOF ends the process. */
public final class Pkcs11KeyMain {
    static final int MAX_FIELD = 1 << 20;
    private Pkcs11KeyMain() {}
    /** Reads bootstrap authentication from stdin, then accepts bounded device and signature commands. */
    public static void main(String[] arguments) throws Exception {
        byte[] token = System.in.readNBytes(32); if (token.length != 32) return;
        try (var socket = new Socket(InetAddress.getLoopbackAddress(), Integer.parseInt(arguments[0]));
             var input = new DataInputStream(socket.getInputStream()); var output = new DataOutputStream(socket.getOutputStream())) {
            output.write(token); output.flush(); Arrays.fill(token, (byte) 0);
            var device = new Pkcs11IdentityManager.Device(Path.of(input.readUTF()),
                    new JourneyDefinition.Slot(JourneyDefinition.SlotKind.valueOf(input.readUTF()), input.readLong()));
            int length = input.readInt(); if (length < 0 || length > 4096) return;
            char[] pin = new char[length]; for (int i = 0; i < length; i++) pin[i] = input.readChar();
            Provider provider; KeyStore keys;
            var operation = Pkcs11Failures.Operation.INITIALIZE;
            try {
                var access = new Pkcs11IdentityManager.SunAccess(); provider = access.configure(device);
                operation = Pkcs11Failures.Operation.LOGIN; keys = access.load(provider, pin); Arrays.fill(pin, '\0');
                operation = Pkcs11Failures.Operation.CERTIFICATES;
                var aliases = Collections.list(keys.aliases()).stream().filter(alias -> {
                    try { return keys.isKeyEntry(alias); } catch (KeyStoreException error) { return false; }
                }).toList();
                if (aliases.size() > 256) throw new KeyStoreException("Too many keys.");
                output.writeBoolean(true); output.writeInt(aliases.size());
                for (var alias : aliases) {
                    var chain = keys.getCertificateChain(alias); if (chain == null || chain.length < 1 || chain.length > 16) throw new KeyStoreException("Invalid chain.");
                    output.writeUTF(alias); output.writeInt(chain.length); for (var certificate : chain) writeField(output, certificate.getEncoded());
                }
                output.flush();
            } catch (Exception | LinkageError error) { writeFailure(output, Pkcs11Failures.from(operation, error)); return; }
            finally { Arrays.fill(pin, '\0'); }
            while (true) {
                String alias; try { alias = input.readUTF(); } catch (EOFException closed) { return; }
                String algorithm = input.readUTF(); byte[] parameters = readField(input), message = readField(input);
                try {
                    if (!Set.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "RSASSA-PSS", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "Ed25519", "Ed448").contains(algorithm)) throw new NoSuchAlgorithmException();
                    var signature = Signature.getInstance(algorithm, provider);
                    if (parameters.length != 0) { var p = AlgorithmParameters.getInstance("RSASSA-PSS"); p.init(parameters); signature.setParameter(p.getParameterSpec(PSSParameterSpec.class)); }
                    signature.initSign((PrivateKey) keys.getKey(alias, null)); signature.update(message);
                    output.writeBoolean(true); writeField(output, signature.sign()); output.flush();
                } catch (Exception | LinkageError error) { writeFailure(output, Pkcs11Failures.from(Pkcs11Failures.Operation.CERTIFICATES, error)); return; }
            }
        } finally { Arrays.fill(token, (byte) 0); }
    }
    /** Reads an exact bounded binary field without Java object deserialization. */
    static byte[] readField(DataInputStream input) throws IOException {
        int size = input.readInt(); if (size < 0 || size > MAX_FIELD) throw new IOException("Field exceeds limit.");
        byte[] value = input.readNBytes(size); if (value.length != size) throw new EOFException(); return value;
    }
    /** Writes a bounded binary field. */
    static void writeField(DataOutputStream output, byte[] value) throws IOException {
        if (value.length > MAX_FIELD) throw new IOException("Field exceeds limit."); output.writeInt(value.length); output.write(value);
    }
    /** Serializes only the existing safe native-failure classifier's output. */
    private static void writeFailure(DataOutputStream output, AuthenticationFailure failure) throws IOException {
        output.writeBoolean(false); output.writeUTF(failure.phase().name()); output.writeUTF(failure.reason().name()); output.writeUTF(failure.problem()); output.writeUTF(failure.recovery());
        output.writeUTF(failure.input() == null ? "" : failure.input().input().name()); output.flush();
    }
}

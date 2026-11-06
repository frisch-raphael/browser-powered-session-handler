import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;

/** Owned PIN-free helper entry point; native vendor output is never used as a UI protocol. */
public final class Pkcs11DiscoveryMain {
    /** No instances. */
    private Pkcs11DiscoveryMain() {}

    /** @param args Canonical middleware path and an owned result-file path; neither contains a PIN. @throws Exception If the owned result cannot be written. */
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("Expected middleware and result file.");
        var mapper = new ObjectMapper(); var result = mapper.createObjectNode();
        try { result.set("tokens", mapper.valueToTree(new Pkcs11Discovery().tokens(Path.of(args[0])))); }
        catch (Exception | LinkageError error) {
            var safe = error instanceof AuthenticationFailure known ? known : Pkcs11Failures.from(Pkcs11Failures.Operation.DISCOVERY, error);
            result.put("problem", safe.problem()).put("recovery", safe.recovery());
        }
        mapper.writeValue(Path.of(args[1]).toFile(), result);
    }
}

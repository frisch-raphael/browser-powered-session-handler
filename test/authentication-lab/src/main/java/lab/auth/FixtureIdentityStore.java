package lab.auth;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Private credential registry. Authentication never trusts client-supplied identity labels. */
public final class FixtureIdentityStore {
    public enum Role { B, C1, C2 }
    public static final class Secret {
        private final String value;
        private Secret(String value) { this.value = value; }
        public String reveal() { return value; }
        @Override public String toString() { return "[redacted]"; }
    }
    public static final class Issuance {
        private final String id, account;
        private final EnumMap<Role, Secret> values = new EnumMap<>(Role.class);
        private final long expiry;
        private boolean revoked;
        private Issuance(String id, String account, long expiry) { this.id = id; this.account = account; this.expiry = expiry; }
        public String id() { return id; }
        public String account() { return account; }
        public Secret credential(Role role) { return values.get(role); }
        @Override public String toString() { return "Issuance[" + id + "," + account + "]"; }
    }
    public record Accepted(String accountId, List<String> issuanceIds, List<Role> roles) {}
    private record Registered(Issuance issuance, Role role) {}
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, String> ACCOUNTS = Map.of("user", "pass", "user2", "pass2", "admin", "adminpass");
    private final Map<String, Issuance> issuances = new LinkedHashMap<>();
    private final Map<String, Registered> registry = new HashMap<>();
    private final byte[] signingKey = new byte[32];
    private final long epoch = System.currentTimeMillis();
    private final long epochNanos = System.nanoTime();
    private long offset;

    public FixtureIdentityStore() {
        RANDOM.nextBytes(signingKey);
        for (String account : List.of("user", "user2", "admin")) { issue(account, false); issue(account, false); }
    }
    public static Secret randomSecret() { byte[] bytes = new byte[32]; RANDOM.nextBytes(bytes); return new Secret(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)); }
    static Secret secretFromPrivateMaterial(String value) { if (!value.matches("[A-Za-z0-9_-]{43}")) throw new IllegalArgumentException("Invalid private material."); return new Secret(value); }
    public synchronized long timeMillis() { return Math.addExact(Math.addExact(epoch, offset), elapsedMillis()); }
    private long elapsedMillis() { return (System.nanoTime() - epochNanos) / 1_000_000; }
    public synchronized void advance(Duration delta) {
        if (delta.isNegative()) throw new IllegalArgumentException("Clock cannot go backward.");
        long next = Math.addExact(offset, delta.toMillis());
        Math.addExact(Math.addExact(Math.addExact(epoch, next), elapsedMillis()), 60_000);
        offset = next;
    }
    public synchronized Issuance login(String account, String password, boolean signed) {
        if (account == null || !ACCOUNTS.containsKey(account) || !Objects.equals(ACCOUNTS.get(account), password)) return null;
        return issue(account, signed);
    }
    static boolean valid(String account, String password) { return account != null && ACCOUNTS.containsKey(account) && Objects.equals(ACCOUNTS.get(account), password); }
    synchronized Issuance issueVerified(String account) { if (!ACCOUNTS.containsKey(account)) throw new IllegalArgumentException("Unknown account."); return issue(account, false); }
    public synchronized Issuance seeded(String id) {
        var value = issuances.get(id);
        if (value == null) throw new IllegalArgumentException("Unknown issuance label.");
        return value;
    }
    private Issuance issue(String account, boolean signed) {
        long expiry = signed ? Math.multiplyExact(Math.addExact(timeMillis() / 1000, 60), 1000) : Math.addExact(timeMillis(), 60_000);
        var result = new Issuance("s" + issuances.size(), account, expiry);
        for (Role role : Role.values()) {
            var secret = signed && role == Role.B ? new Secret(jwt(result)) : randomSecret();
            result.values.put(role, secret); registry.put(secret.reveal(), new Registered(result, role));
        }
        issuances.put(result.id, result); return result;
    }
    private String jwt(Issuance issuance) {
        try {
            var encoder = Base64.getUrlEncoder().withoutPadding();
            String header = encoder.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String body = encoder.encodeToString(("{\"sub\":\"" + issuance.account + "\",\"jti\":\"" + randomSecret().reveal() + "\",\"exp\":" + issuance.expiry / 1000 + "}").getBytes(StandardCharsets.UTF_8));
            var mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            return header + "." + body + "." + encoder.encodeToString(mac.doFinal((header + "." + body).getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.GeneralSecurityException ex) { throw new IllegalStateException("JWT fixture signing unavailable."); }
    }
    public synchronized void revoke(String id) { seeded(id).revoked = true; }
    synchronized void clear() { registry.clear(); issuances.clear(); Arrays.fill(signingKey, (byte) 0); }
    public synchronized Secret rotate(String id, Role role) {
        var issuance = seeded(id); registry.remove(issuance.credential(role).reveal());
        var replacement = randomSecret(); issuance.values.put(role, replacement); registry.put(replacement.reveal(), new Registered(issuance, role));
        return replacement;
    }
    public synchronized Accepted accept(Map<Role, String> supplied, boolean independentCookies) {
        String account = null, commonId = null;
        var ids = new ArrayList<String>(); var roles = new ArrayList<Role>();
        for (var entry : supplied.entrySet()) {
            var registered = registry.get(entry.getValue());
            if (registered == null || registered.role != entry.getKey()) return null;
            var issuance = registered.issuance;
            if (issuance.revoked || timeMillis() >= issuance.expiry) return null;
            if (account != null && (!account.equals(issuance.account) || (!independentCookies && !commonId.equals(issuance.id)))) return null;
            account = issuance.account; commonId = issuance.id; ids.add(issuance.id); roles.add(entry.getKey());
        }
        return account == null ? null : new Accepted(account, List.copyOf(ids), List.copyOf(roles));
    }
}

package bpsh.burp.ui;

import bpsh.browser.mtls.Pkcs11IdentityManager;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import javax.naming.ldap.LdapName;

/** Human-readable public identity labels; exact certificate selection remains fingerprint-based. */
final class CertificatePresentation {
    static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("dd MMM uuuu").withZone(ZoneId.systemDefault());
    private CertificatePresentation() {}
    /** @param subject X.500 distinguished name. @param attribute Requested public name component. @return Readable component when present. */
    static String attribute(String subject, String attribute) {
        try {
            for (var rdn : new LdapName(subject).getRdns()) {
                var value = rdn.toAttributes().get(attribute);
                if (value != null && value.get() instanceof String text && !text.isBlank()) return text;
            }
        } catch (javax.naming.NamingException ignored) { /* Malformed or encoded attributes retain the full identity as fallback. */ }
        return "";
    }
    /** @param subject Full identity. @return Common name, or the original identity when no common name exists. */
    static String name(String subject) { String common = attribute(subject, "CN"); return common.isBlank() ? subject : common; }
    /** @param certificate Selected public identity. @return Readable owner, issuer and validity, without technical identifiers. */
    static String summary(Pkcs11IdentityManager.CertificateInfo certificate) {
        var text = new StringBuilder(name(certificate.subject()));
        String organization = attribute(certificate.subject(), "O"), email = attribute(certificate.subject(), "EMAILADDRESS");
        if (!organization.isBlank()) text.append("\nOrganization: ").append(organization);
        if (!email.isBlank()) text.append("\nEmail: ").append(email);
        return text.append("\nIssued by: ").append(name(certificate.issuer()))
                .append("\nValid: ").append(DATE.format(certificate.notBefore())).append(" – ").append(DATE.format(certificate.notAfter())).toString();
    }
    /** @param certificate Public identity. @return Explicitly requested technical details. */
    static String technical(Pkcs11IdentityManager.CertificateInfo certificate) {
        return "Subject: " + certificate.subject() + "\nIssuer: " + certificate.issuer() + "\nSerial: " + certificate.serial() + "\nSHA-256: " + certificate.sha256();
    }
}

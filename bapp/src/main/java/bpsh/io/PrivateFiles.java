package bpsh.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.*;
import java.util.EnumSet;
import java.util.List;

/** Shared local ownership checks; independent of browser installation and library storage. */
public final class PrivateFiles {
    private PrivateFiles() {}
    /**
     * Resolves the actual Windows account instead of the host's mutable user.name system property.
     * @param path Existing ACL-capable filesystem path.
     * @return Qualified operating-system principal used for private file creation.
     * @throws IOException If native account lookup is unavailable; never grants a broader fallback ACL.
     */
    public static java.nio.file.attribute.UserPrincipal windowsFilePrincipal(Path path) throws IOException {
        try {
            var account = new com.sun.security.auth.module.NTSystem(); String name = account.getName(), domain = account.getDomain();
            if (name == null || name.isBlank()) throw new IOException("Windows account lookup returned no user.");
            String qualified = domain == null || domain.isBlank() ? name : domain + "\\" + name;
            return path.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(qualified);
        } catch (LinkageError | SecurityException error) { throw new IOException("Windows account lookup is unavailable."); }
    }
    /**
     * Supplies creation-time user-only permissions before extracted data receives its final POSIX mode.
     * @param parent Existing owned parent determining supported attribute views.
     * @param directory Whether private directory permissions are required.
     * @return Initial POSIX mode or current-user ACL.
     * @throws IOException If restricted creation is unavailable.
     */
    public static FileAttribute<?>[] creationAttributes(Path parent, boolean directory) throws IOException {
        if (Files.getFileAttributeView(parent, PosixFileAttributeView.class) != null)
            return new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"))};
        if (Files.getFileAttributeView(parent, AclFileAttributeView.class) != null) {
            var user = windowsFilePrincipal(parent);
            var entry = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(user).setPermissions(EnumSet.allOf(AclEntryPermission.class));
            if (directory) entry.setFlags(AclEntryFlag.DIRECTORY_INHERIT, AclEntryFlag.FILE_INHERIT);
            var acl = List.of(entry.build());
            return new FileAttribute<?>[]{new FileAttribute<List<AclEntry>>() {
                /**
                 * Identifies the ACL attribute applied atomically when an owned path is created.
                 *
                 * @return ACL creation attribute name.
                 */
                public String name() { return "acl:acl"; }
                /**
                 * Returns current-user-only allow entries.
                 *
                 * @return Current-user-only allow entries.
                 */
                public List<AclEntry> value() { return acl; }
            }};
        }
        throw new IOException("Private cache permissions unsupported.");
    }
}

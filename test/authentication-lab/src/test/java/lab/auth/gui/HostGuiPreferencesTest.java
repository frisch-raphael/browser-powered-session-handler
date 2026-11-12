package lab.auth.gui;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import lab.auth.LabJson;
import static org.junit.jupiter.api.Assertions.*;

class HostGuiPreferencesTest {
    @TempDir Path directory;
    @Test void preferencesPersistOnlyWithinTheirOwnedStoreIncludingEmptyValuesAndChildren() throws Exception {
        var first=new HostGuiPreferences(directory);var node=first.userRoot().node("burp/child");node.put("empty","");node.put("key","value");node.flush();
        var second=new HostGuiPreferences(directory);assertEquals("value",second.userRoot().node("burp/child").get("key",null));
        assertEquals("",second.userRoot().node("burp/child").get("empty",null));assertArrayEquals(new String[]{"child"},second.userRoot().node("burp").childrenNames());
        assertNull(second.systemRoot().node("burp/child").get("key",null));
        var isolated=new HostGuiPreferences(Files.createDirectory(directory.resolve("other")));assertNull(isolated.userRoot().node("burp/child").get("key",null));
        second.userRoot().node("burp/child").removeNode();second.userRoot().flush();
        assertFalse(new HostGuiPreferences(directory).userRoot().nodeExists("burp/child"));
    }
    @Test void approvedSubsetIsClosedAndNeverImportsUnrelatedPreferences() throws Exception {
        LabJson.writeNew(directory.resolve("approved-preferences.json"),Map.of("version",1,"burp",Map.of("burp.eula","approved-fixture","use_community_edition","true")));
        var factory=new HostGuiPreferences(directory);assertEquals("approved-fixture",factory.userRoot().node("burp").get("burp.eula",null));
        assertNull(factory.userRoot().node("burp").get("license",null));
        Files.writeString(directory.resolve("approved-preferences.json"),"{\"version\":1,\"burp\":{\"license\":\"SECRET_SENTINEL\"}}");
        var failure=assertThrows(IllegalStateException.class,()->new HostGuiPreferences(directory));
        assertEquals("GUI_PREFERENCES_UNAVAILABLE",failure.getMessage());assertNull(failure.getCause());
    }
}

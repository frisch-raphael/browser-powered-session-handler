package lab.auth;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ProfileSelectionTest {
    private JsonObject plan(List<String> profiles, String task) {
        var rows = LabProductionEvidence.profileRows(profiles);
        var result = new JsonObject();
        result.add("selectedProfiles", LabRun.JSON.toJsonTree(profiles));
        result.add("selectedRequirementIds", LabRun.JSON.toJsonTree(rows.stream().map(ScenarioCatalog.Requirement::id).toList()));
        result.add("selectedMethods", LabRun.JSON.toJsonTree(LabProductionEvidence.profileMethods(rows, task)));
        return result;
    }
    @Test void baselineNeedsBothActualLayersAndNoProviderOrNativeMiddlewareOwner() throws Exception {
        var profiles = List.of("baseline");
        var component = LabProductionEvidence.scopedProfileRows(plan(profiles, ":authLabComponentTest"), ":authLabComponentTest");
        var browser = LabProductionEvidence.scopedProfileRows(plan(profiles, ":authLabBrowserTest"), ":authLabBrowserTest");
        assertEquals(8, component.size()); assertEquals(4, browser.size());
        assertTrue(component.stream().allMatch(r -> r.layer() == ScenarioCatalog.Layer.COMPONENT));
        assertTrue(browser.stream().allMatch(r -> r.layer() == ScenarioCatalog.Layer.RUNNER));
        assertTrue(LabProductionEvidence.profileRows(profiles).stream().noneMatch(r -> r.capabilities().stream().anyMatch(Set.of("KEYCLOAK", "PKCS11", "SOFTHSM")::contains)));
    }
    @Test void overlappingProfilesShareTheirExistingOwnersAndKeepExclusionsSeparate() throws Exception {
        var profiles = List.of("baseline", "recovery", "revised", "baseline");
        var rows = LabProductionEvidence.profileRows(profiles);
        assertEquals(rows.size(), rows.stream().map(ScenarioCatalog.Requirement::id).distinct().count());
        var methods = LabProductionEvidence.profileMethods(rows, ":authLabComponentTest");
        assertEquals(methods.size(), new HashSet<>(methods).size());
        assertTrue(methods.size() < rows.stream().filter(r -> r.binding() != null && r.binding().taskPath().equals(":authLabComponentTest")).count());
        var scoped = LabProductionEvidence.scopedProfileRows(plan(profiles, ":authLabComponentTest"), ":authLabComponentTest");
        assertTrue(scoped.stream().noneMatch(r -> r.disposition() == ScenarioCatalog.Disposition.EXCLUDED));
        assertEquals(3, rows.stream().filter(r -> r.disposition() == ScenarioCatalog.Disposition.EXCLUDED).count());
    }
    @Test void diagnosticsCannotSilentlyDropARequirementOrAddAnUnreviewedOwner() throws Exception {
        var selected = plan(List.of("diagnostics"), ":authLabComponentTest");
        assertEquals(18, LabProductionEvidence.scopedProfileRows(selected, ":authLabComponentTest").size());
        var missing = selected.deepCopy(); missing.getAsJsonArray("selectedRequirementIds").remove(0);
        assertThrows(IOException.class, () -> LabProductionEvidence.scopedProfileRows(missing, ":authLabComponentTest"));
        var foreign = selected.deepCopy(); foreign.getAsJsonArray("selectedMethods").add("UnknownTest.hiddenProviderLogin");
        assertThrows(IOException.class, () -> LabProductionEvidence.scopedProfileRows(foreign, ":authLabComponentTest"));
        assertThrows(IOException.class, () -> LabProductionEvidence.scopedProfileRows(selected, ":authLabBrowserTest"));
        assertThrows(IllegalArgumentException.class, () -> LabProductionEvidence.profileRows(List.of("all")));
        assertThrows(IllegalArgumentException.class, () -> LabProductionEvidence.profileRows(List.of("burp")));
    }
}

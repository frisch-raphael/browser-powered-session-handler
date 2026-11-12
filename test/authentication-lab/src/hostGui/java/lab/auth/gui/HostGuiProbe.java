package lab.auth.gui;

import com.google.gson.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import javax.swing.*;
import javax.swing.text.JTextComponent;
import lab.auth.*;
import static lab.auth.gui.HostGuiSelectors.*;

/** Configures and exports the passive probe through its visible controls only. */
final class HostGuiProbe {
    private final HostGuiDriver ui;
    HostGuiProbe(HostGuiDriver ui){this.ui=ui;}
    record Setup(String origins,String label) {}
    static Setup setup(JsonObject value) {
        LabJson.object(value,"version","origins","case");LabJson.require(LabJson.positive(value.get("version"))==1,"GUI_PROBE_VERSION");
        LabJson.require(value.get("origins").isJsonArray(),"GUI_PROBE_ORIGINS");var origins=new LinkedHashSet<String>();
        for(var item:value.getAsJsonArray("origins")) {
            String text=LabJson.string(item);URI uri=URI.create(text);
            LabJson.require(Set.of("http","https").contains(uri.getScheme())&&uri.getHost()!=null&&uri.getRawUserInfo()==null
                    &&uri.getRawQuery()==null&&uri.getRawFragment()==null&&(uri.getRawPath().isEmpty()||uri.getRawPath().equals("/"))
                    &&Set.of("127.0.0.1","localhost","[::1]","::1").contains(uri.getHost())&&uri.getPort()>0&&uri.getPort()<=65535
                    &&origins.add(text),"GUI_PROBE_ORIGIN");
        }
        LabJson.require(!origins.isEmpty()&&origins.size()<=4,"GUI_PROBE_ORIGINS");
        String label=LabJson.text(value,"case");LabJson.require(label.matches("[A-Za-z0-9._-]{1,80}"),"GUI_PROBE_CASE");
        return new Setup(String.join(",",origins),label);
    }
    void capture(String phase,Path path) throws IOException {
        ui.probeTab();Window frame=ui.surface();
        var enabled=edt(()->(JCheckBox)field(frame,"authlab.observation.enabled"));
        if(edt(enabled::isSelected))ui.click(enabled);
        ui.until(()->edt(()->!enabled.isSelected()));
        if(phase.equals("RESET")) {
            var setup=setup(LabJson.read(path,4096));
            ui.replace(edt(()->(JTextComponent)field(frame,"authlab.observation.origins")),setup.origins());
            ui.replace(edt(()->(JTextComponent)field(frame,"authlab.observation.case")),setup.label());
            ui.click(edt(()->button(frame,"Clear capture")));status("Capture cleared.");
            ui.click(enabled);ui.until(()->edt(enabled::isSelected));status("Observing selected fixture traffic. Maximum 1,000 events.");
        }else {
            if(Files.exists(path)||!Files.isDirectory(path.getParent()))throw new Failure("GUI_PROBE_OUTPUT");
            ui.click(edt(()->button(frame,"Export capture...")));ui.chooseFile(path);
            ui.until(()->Files.isRegularFile(path));
            var value=LabJson.read(path,1_048_576);
            if(!value.has("complete")||!value.get("complete").getAsBoolean())throw new Failure("GUI_PROBE_INCOMPLETE");
            status("Callback capture exported.");
        }
    }
    private void status(String expected){ui.until(()->edt(()->field(ui.surface(),"authlab.observation.status") instanceof JLabel label&&expected.equals(label.getText())));}
}

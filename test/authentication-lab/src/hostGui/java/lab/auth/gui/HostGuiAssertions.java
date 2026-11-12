package lab.auth.gui;

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.text.JTextComponent;
import static lab.auth.gui.HostGuiSelectors.*;

/** Reads visible feedback without copying arbitrary product messages into evidence. */
final class HostGuiAssertions {
    private final HostGuiDriver ui;
    HostGuiAssertions(HostGuiDriver ui){this.ui=ui;}
    static boolean message(String code,String text) {
        return switch(code) {
            case "URL_REGEX_INVALID" -> text.matches("Rule [0-9]+: Use supported RE2 syntax for the URL expression(?: at position [0-9]+)?\\.")
                    ||text.toLowerCase(Locale.ROOT).contains("invalid url regex");
            case "RECOVERY_PAUSED" -> text.contains("Automatic recovery is paused after")&&text.contains("Test login");
            case "LOGIN_FAILED" -> text.contains("Login failed")||text.contains("HTTP 503");
            default -> throw new Failure("GUI_ASSERTION_UNSUPPORTED");
        };
    }
    static boolean unchangedMessage(String alias,String text){return text.contains("BPSH left the request unchanged.")&&text.contains("Journey "+alias+":");}
    void verify(String alias,String code,String nonce) {
        if(code.equals("ORDINARY_UNCHANGED")){ui.unchangedRequest(nonce,alias);return;}
        if(code.equals("URL_REGEX_INVALID")) {
            ui.productTab("Session handling");
            ui.until(()->edt(()->all(ui.surface()).stream().anyMatch(c->c instanceof JTextComponent t&&c.isShowing()
                    &&named(c,"Input error")&&message(code,t.getText()))));
            return;
        }
        if(!Set.of("RECOVERY_PAUSED","LOGIN_FAILED").contains(code))throw new Failure("GUI_ASSERTION_UNSUPPORTED");
        ui.journey(alias);
        var toggle=edt(()->(JToggleButton)find(ui.surface(),c->c instanceof JToggleButton&&label(c).matches("Event log(?: \\([0-9]+\\))?"),true));
        if(!edt(toggle::isSelected))ui.click(toggle);
        ui.until(()->edt(()->{
            var tables=all(ui.surface()).stream().filter(c->c instanceof JTable t&&t.isShowing()&&column(t,"Time")>=0&&column(t,"Type")>=0&&column(t,"Message")>=0).map(c->(JTable)c).toList();
            if(tables.isEmpty())return false;JTable table=unique(tables);
            for(int row=0;row<table.getRowCount();row++)if(message(code,Objects.toString(table.getValueAt(row,column(table,"Message")),"")))return true;
            return false;
        }));
    }
}

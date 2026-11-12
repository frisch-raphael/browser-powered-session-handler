package lab.auth.gui;

import com.google.gson.*;
import java.nio.file.Path;
import java.util.*;
import javax.swing.*;
import javax.swing.text.JTextComponent;
import lab.auth.LabJson;
import static lab.auth.gui.HostGuiSelectors.*;

/** Typed fixture intent applied through the same visible controls a user edits. */
final class HostGuiRules {
    record Rule(String alias,boolean enabled,String mode,String url,boolean regex,Integer port,
                boolean detect,String detection,Integer status,String pattern) { }
    record Spec(String mode,String policy,boolean enabled,List<String> tools,List<Rule> rules,int row) { }
    private final HostGuiDriver driver;
    HostGuiRules(HostGuiDriver driver){this.driver=driver;}

    static Spec parse(JsonObject value) {
        String mode=LabJson.member(value.get("mode"),"REPLACE","INVALID_REGEX");
        if(mode.equals("INVALID_REGEX")) {
            LabJson.object(value,"mode","rule");Integer rule=number(value.get("rule"),1,8);
            LabJson.require(rule!=null,"GUI_RULE_INDEX");
            return new Spec(mode,null,true,List.of(),List.of(),rule-1);
        }
        LabJson.object(value,"mode","policy","enabled","tools","rules");
        String policy=LabJson.member(value.get("policy"),"WAIT_FOR_LOGIN","DO_NOT_WAIT");
        List<String> tools=LabJson.strings(value.get("tools"));
        LabJson.require(new HashSet<>(tools).size()==tools.size()&&Set.of("PROXY","REPEATER","EXTENSIONS","SCANNER","INTRUDER").containsAll(tools),"GUI_RULE_TOOLS");
        LabJson.require(value.get("rules").isJsonArray()&&value.getAsJsonArray("rules").size()<=8,"GUI_RULE_COUNT");
        var rules=new ArrayList<Rule>();var aliases=new HashSet<String>();
        for(var item:value.getAsJsonArray("rules")) {
            var row=LabJson.object(item,"alias","enabled","urlMode","url","regex","proxyPort","detect","detectBy","failureStatus","responsePattern");
            String alias=LabJson.text(row,"alias");LabJson.require(alias.matches("[a-z][a-z0-9_]{0,63}")&&aliases.add(alias),"GUI_RULE_ALIAS");
            String urlMode=LabJson.member(row.get("urlMode"),"ALL_REQUESTS","SINGLE_URL","BURP_SCOPE"),url=LabJson.string(row.get("url"));
            boolean regex=bool(row,"regex");LabJson.require(url.length()<=4096&&(urlMode.equals("SINGLE_URL")?!url.isBlank():url.isEmpty()&&!regex),"GUI_RULE_URL");
            Integer port=number(row.get("proxyPort"),1,65535);
            String detection=LabJson.member(row.get("detectBy"),"STATUS_CODE","REGEX","BOTH"),pattern=LabJson.string(row.get("responsePattern"));
            Integer status=number(row.get("failureStatus"),100,599);LabJson.require(pattern.length()<=4096,"GUI_RULE_PATTERN");
            boolean detect=bool(row,"detect");
            LabJson.require(detection.equals("REGEX")?status==null:status!=null,"GUI_RULE_STATUS");
            LabJson.require(detection.equals("STATUS_CODE")?pattern.isEmpty():!pattern.isBlank(),"GUI_RULE_PATTERN");
            LabJson.require(detect||detection.equals("STATUS_CODE")&&Integer.valueOf(401).equals(status)&&pattern.isEmpty(),"GUI_RULE_UNUSED_DETECTION");
            rules.add(new Rule(alias,bool(row,"enabled"),urlMode,url,regex,port,detect,detection,status,pattern));
        }
        return new Spec(mode,policy,bool(value,"enabled"),List.copyOf(tools),List.copyOf(rules),-1);
    }
    private static boolean bool(JsonObject value,String key) {
        var field=value.get(key);LabJson.require(field.isJsonPrimitive()&&field.getAsJsonPrimitive().isBoolean(),"GUI_RULE_BOOLEAN");return field.getAsBoolean();
    }
    private static Integer number(JsonElement value,int min,int max) {
        if(value.isJsonNull())return null;
        long number=LabJson.positive(value);LabJson.require(number>=min&&number<=max,"GUI_RULE_NUMBER");return (int)number;
    }
    boolean apply(Path file) throws java.io.IOException {
        Spec spec=parse(LabJson.read(file,65536));
        if(spec.mode().equals("INVALID_REGEX")) {
            driver.productTab("Session handling");var table=table();
            if(spec.row()>=edt(table::getRowCount))throw new Failure("GUI_RULE_INDEX");
            driver.clickCell(table,spec.row(),edt(()->column(table,"Journey")));
            var regex=checkBox("Use regex");if(!edt(regex::isSelected))throw new Failure("GUI_RULE_TEST_SETUP");
            driver.replace(text("URL"),"[");driver.until(this::hasError);return true;
        }
        driver.productTab("Settings");
        driver.combo(edt(()->(JComboBox<?>)field(driver.surface(),"Automatic handling policy")),spec.policy());
        stable(()->edt(()->comboKey(((JComboBox<?>)field(driver.surface(),"Automatic handling policy")).getSelectedItem()).equals(spec.policy())));
        driver.productTab("Session handling");set(checkBox("Automatically authenticate matching requests"),true);
        var table=table();
        while(edt(table::getRowCount)>0) {
            int before=edt(table::getRowCount);driver.clickCell(table,0,edt(()->column(table,"Journey")));
            driver.click(edt(()->find(driver.surface(),c->c instanceof AbstractButton&&named(c,"Remove automatic rule"),true)));
            driver.until(()->edt(()->table.getRowCount()==before-1));
        }
        for(var rule:spec.rules()) {
            String name=driver.displayName(rule.alias());
            var available=edt(()->(JComboBox<?>)find(driver.surface(),c->c instanceof JComboBox<?> box&&
                    java.util.stream.IntStream.range(0,box.getItemCount()).anyMatch(i->name.equals(comboKey(box.getItemAt(i)))),true));
            driver.combo(available,name);int before=edt(table::getRowCount);
            driver.click(edt(()->find(driver.surface(),c->c instanceof AbstractButton&&named(c,"Add automatic journey"),true)));
            driver.until(()->edt(()->table.getRowCount()==before+1));driver.clickCell(table,before,edt(()->column(table,"Journey")));
            driver.combo(combo("URL handling"),rule.mode());
            if(rule.mode().equals("SINGLE_URL")){set(checkBox("Use regex"),rule.regex());driver.replace(text("URL"),rule.url());}
            driver.combo(combo("Proxy port"),rule.port()==null?"Any listener":rule.port().toString());
            set(checkBox("Detect expired sessions"),rule.detect());
            if(rule.detect()) {
                driver.combo(combo("Detect by"),rule.detection());
                if(!rule.detection().equals("REGEX")) {
                    if(rule.status()==null)throw new Failure("GUI_RULE_STATUS");driver.replace(text("Failure status"),rule.status().toString());
                }
                if(!rule.detection().equals("STATUS_CODE"))driver.replace(text("RE2 expression"),rule.pattern());
            }
            boolean on=edt(()->Boolean.TRUE.equals(table.getValueAt(before,column(table,"On"))));
            if(on!=rule.enabled())driver.clickCell(table,before,edt(()->column(table,"On")));
        }
        for(String tool:List.of("PROXY","REPEATER","EXTENSIONS","SCANNER","INTRUDER"))set(checkBox(tool),spec.tools().contains(tool));
        stable(()->rowsMatch(table,spec)&&!hasError());
        set(checkBox("Automatically authenticate matching requests"),spec.enabled());
        stable(()->rowsMatch(table,spec)&&edt(()->checkBox("Automatically authenticate matching requests").isSelected()==spec.enabled())&&!hasError());
        return false;
    }
    static String comboKey(Object value){return value instanceof Enum<?> kind?kind.name():Objects.toString(value,"");}
    private JTable table(){return edt(()->(JTable)find(driver.surface(),c->c instanceof JTable t&&column(t,"Journey")>=0&&column(t,"URL scope")>=0,true));}
    private JCheckBox checkBox(String title){return edt(()->(JCheckBox)button(driver.surface(),title));}
    private JTextComponent text(String title){return edt(()->(JTextComponent)field(driver.surface(),title));}
    private JComboBox<?> combo(String title){return edt(()->(JComboBox<?>)field(driver.surface(),title));}
    private void set(JCheckBox box,boolean desired){if(edt(box::isSelected)!=desired)driver.click(box);driver.until(()->edt(()->box.isSelected()==desired));}
    private boolean hasError(){return edt(()->all(driver.surface()).stream().anyMatch(c->c instanceof JTextComponent t&&c.isShowing()&&named(c,"Input error")&&!t.getText().isBlank()));}
    private boolean rowsMatch(JTable table,Spec spec) {
        return edt(()->{
            if(table.getRowCount()!=spec.rules().size())return false;
            for(int i=0;i<spec.rules().size();i++) {
                var rule=spec.rules().get(i);String scope=rule.mode().equals("ALL_REQUESTS")?"All requests":rule.mode().equals("BURP_SCOPE")?"Burp target scope":(rule.regex()?"Regex: ":"Prefix: ")+rule.url();
                if(!driver.displayName(rule.alias()).equals(table.getValueAt(i,column(table,"Journey")))
                        ||!scope.equals(table.getValueAt(i,column(table,"URL scope")))
                        ||!Objects.equals(rule.port()==null?"Any listener":rule.port().toString(),table.getValueAt(i,column(table,"Proxy port")))
                        ||Boolean.TRUE.equals(table.getValueAt(i,column(table,"On")))!=rule.enabled())return false;
            }
            return true;
        });
    }
    /** Let visible controls settle across the normal autosave debounce, then prove application behavior independently. */
    private void stable(java.util.function.BooleanSupplier state) {
        long[] since={0};driver.until(()->{if(!state.getAsBoolean()){since[0]=0;return false;}long now=System.nanoTime();
            if(since[0]==0)since[0]=now;return now-since[0]>=java.util.concurrent.TimeUnit.SECONDS.toNanos(1);});
    }
}

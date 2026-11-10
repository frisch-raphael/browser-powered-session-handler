package bpsh.burp.ui;

import javax.swing.JTabbedPane;
import java.awt.Component;
import java.util.LinkedHashMap;
import java.util.Map;

/** Stable page identities keep navigation correct when optional pages are absent. */
final class JourneyWizardPages<P> {
    private record Page(String title,Component component) { }
    private final JTabbedPane tabs;
    private final Map<P,Page> pages=new LinkedHashMap<>();
    JourneyWizardPages(JTabbedPane tabs) {this.tabs=tabs;}
    void add(P id,String title,Component component) {pages.put(id,new Page(title,component));tabs.addTab(title,component);}
    P current(P fallback) {return pages.entrySet().stream().filter(entry->entry.getValue().component()==tabs.getSelectedComponent()).map(Map.Entry::getKey).findFirst().orElse(fallback);}
    void select(P id) {Page page=pages.get(id);int index=page==null?-1:tabs.indexOfComponent(page.component());tabs.setSelectedIndex(index<0?0:index);}
    void visible(P id,boolean visible) {
        Page page=pages.get(id);if(page==null)return;
        int current=tabs.indexOfComponent(page.component());
        if(!visible && current>=0) {if(tabs.getSelectedIndex()==current)tabs.setSelectedIndex(0);tabs.removeTabAt(current);}
        else if(visible && current<0) {
            Component selected=tabs.getSelectedComponent();int index=0;
            for(var entry:pages.entrySet()) {if(entry.getKey().equals(id))break;if(tabs.indexOfComponent(entry.getValue().component())>=0)index++;}
            tabs.insertTab(page.title(),null,page.component(),null,index);if(selected!=null)tabs.setSelectedComponent(selected);
        }
    }
}

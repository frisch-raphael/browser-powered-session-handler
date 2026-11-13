package lab.auth.gui;

import java.awt.*;
import java.nio.file.Path;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.function.Predicate;
import javax.swing.*;

/** Public Swing/accessible state only; every ambiguous match fails before input. */
public final class HostGuiSelectors {
    private HostGuiSelectors() {}
    public static final class Failure extends RuntimeException {
        public Failure(String code) { super(code!=null&&code.matches("[A-Z][A-Z0-9_]{0,79}")?code:"GUI_ACTION_FAILED"); }
    }
    public static <T> T edt(Callable<T> query) {
        return edt(query,5000);
    }
    static <T> T edt(Callable<T> query,long timeoutMs) {
        var task=new FutureTask<>(query);
        if(SwingUtilities.isEventDispatchThread())task.run();else SwingUtilities.invokeLater(task);
        try{return task.get(timeoutMs,TimeUnit.MILLISECONDS);}
        catch(InterruptedException stopped){Thread.currentThread().interrupt();throw new Failure("GUI_CANCELLED");}
        catch(ExecutionException failed){if(failed.getCause() instanceof Failure fixed)throw new Failure(fixed.getMessage());throw new Failure("GUI_EDT_QUERY_FAILED");}
        catch(TimeoutException failed){task.cancel(false);throw new Failure("GUI_EDT_QUERY_FAILED");}
    }
    public static List<Component> all(Container root) {
        var result=new ArrayList<Component>();var queue=new ArrayDeque<Component>();queue.add(root);
        var seen=Collections.newSetFromMap(new IdentityHashMap<Component,Boolean>());
        while(!queue.isEmpty()) {
            Component component=queue.removeFirst();if(!seen.add(component))continue;
            if(seen.size()>10_000)throw new Failure("GUI_TREE_LIMIT");
            result.add(component);if(component instanceof Container container)queue.addAll(Arrays.asList(container.getComponents()));
        }
        return List.copyOf(result);
    }
    public static <T> T unique(List<T> matches) {
        if(matches.size()!=1)throw new Failure(matches.isEmpty()?"GUI_CONTROL_MISSING":"GUI_CONTROL_AMBIGUOUS");
        return matches.getFirst();
    }
    public static Component find(Container root,Predicate<Component> predicate,boolean showing) {
        return unique(all(root).stream().filter(c->(!showing||c.isShowing())&&predicate.test(c)).toList());
    }
    public static String label(Component component) {
        if(component instanceof AbstractButton button)return Objects.toString(button.getText(),"");
        if(component instanceof JLabel label)return Objects.toString(label.getText(),"");
        return "";
    }
    public static boolean named(Component component,String name) {
        if(name.equals(component.getName()))return true;
        var context=component.getAccessibleContext();return context!=null&&name.equals(context.getAccessibleName());
    }
    public static JTabbedPane tabs(Container root,String... required) {
        return (JTabbedPane)find(root,c->c instanceof JTabbedPane p&&Arrays.stream(required).allMatch(title->p.indexOfTab(title)>=0),true);
    }
    public static Component button(Container root,String title) {
        return find(root,c->c instanceof AbstractButton&&title.equals(label(c)),true);
    }
    public static String comboKey(Object value) {return value instanceof Enum<?> kind?kind.name():Objects.toString(value,"");}
    record ComboChoice(JList<?> list,int row) {}
    /** Reads the visible list owned by this exact combo, including nonfocusable combos. */
    static ComboChoice comboChoice(JPopupMenu popup,JComboBox<?> invoker,String value) {
        if(popup.getInvoker()!=invoker||!popup.isShowing())throw new Failure("GUI_POPUP_CONTEXT");
        var list=(JList<?>)find(popup,c->c instanceof JList<?>,true);
        var rows=new ArrayList<Integer>();for(int i=0;i<list.getModel().getSize();i++)
            if(value.equals(comboKey(list.getModel().getElementAt(i))))rows.add(i);
        return new ComboChoice(list,unique(rows));
    }
    /** Custom toolbar controls can expose their caption as a label on a mouse-handling container. */
    public static Component actionControl(Container root,String title) {
        var candidates=new ArrayList<Component>();var seen=Collections.newSetFromMap(new IdentityHashMap<Component,Boolean>());
        for(Component component:all(root))if(component.isShowing()&&title.equals(label(component))) {
            Component target=null;
            if(component instanceof AbstractButton)target=component;
            else if(component instanceof JLabel) {
                boolean mouseHandler=false;
                for(Component owner=component;owner!=null&&owner!=root&&!(owner instanceof JTabbedPane)&&!(owner instanceof Window);owner=owner.getParent()) {
                    if(owner instanceof AbstractButton){target=owner;break;}
                    mouseHandler|=owner.getMouseListeners().length>0;
                }
                if(target==null&&mouseHandler)target=component;
            }
            if(target!=null&&seen.add(target))candidates.add(target);
        }
        return unique(candidates);
    }
    public static boolean actionEnabled(Component component) {
        for(Component owner=component;owner!=null;owner=owner.getParent())if(!owner.isEnabled())return false;
        return true;
    }
    /** A heavyweight popup may have its own window; its exact invoker establishes the context. */
    public static JPopupMenu popupMenu(Component invoker) {
        return popupMenu(invoker,Arrays.asList(Window.getWindows()));
    }
    static JPopupMenu popupMenu(Component invoker,Collection<? extends Container> windows) {
        var matches=new ArrayList<JPopupMenu>();
        var seen=Collections.newSetFromMap(new IdentityHashMap<JPopupMenu,Boolean>());
        if(invoker!=null)for(Container window:windows)if(window.isShowing())for(Component component:all(window))
            if(component instanceof JPopupMenu menu&&menu.isShowing()&&menu.getInvoker()==invoker&&seen.add(menu))matches.add(menu);
        return unique(matches);
    }
    static JPopupMenu popupAncestor(Component target) {
        return target instanceof JPopupMenu menu?menu:(JPopupMenu)SwingUtilities.getAncestorOfClass(JPopupMenu.class,target);
    }
    /** Focus belongs to a nonfocusable popup's public owner, while clicks retain popup geometry. */
    public static Window focusWindow(Component target) {
        Window window=SwingUtilities.getWindowAncestor(target);var popup=popupAncestor(target);Window invokerWindow=null;
        if(popup!=null) {
            Component invoker=popup.getInvoker();invokerWindow=invoker==null?null:SwingUtilities.getWindowAncestor(invoker);
            if(invokerWindow==null)throw new Failure("GUI_FOCUS_FAILED");
        }
        return focusWindow(window,invokerWindow,Window::getOwner,Window::isFocusableWindow);
    }
    static <T> T focusWindow(T window,T popupInvokerWindow,Function<T,T> owner,Predicate<T> focusable) {
        if(window==null)throw new Failure("GUI_WINDOW_MISSING");
        if(popupInvokerWindow==null) {
            if(!focusable.test(window))throw new Failure("GUI_FOCUS_FAILED");return window;
        }
        T nearest=null;boolean owned=false;var seen=Collections.newSetFromMap(new IdentityHashMap<T,Boolean>());
        for(T current=window;current!=null&&seen.add(current);current=owner.apply(current)) {
            if(nearest==null&&focusable.test(current))nearest=current;
            owned|=current==popupInvokerWindow;
            if(owned&&nearest!=null)return nearest;
        }
        throw new Failure("GUI_FOCUS_FAILED");
    }
    public static int column(JTable table,String title) {
        for(int i=0;i<table.getColumnCount();i++)if(title.equals(table.getColumnName(i)))return i;return -1;
    }
    /** Selects a history row through its neutral public Method cell, never a row-action/menu column. */
    static int historySelectionColumn(JTable table,int row) {
        if(row<0||row>=table.getRowCount())throw new Failure("GUI_HISTORY_ROW_MISSING");
        var matches=new ArrayList<Integer>();
        for(int column=0;column<table.getColumnCount();column++)if("Method".equals(table.getColumnName(column)))matches.add(column);
        if(matches.size()!=1)throw new Failure(matches.isEmpty()?"GUI_HISTORY_METHOD_MISSING":"GUI_HISTORY_METHOD_AMBIGUOUS");
        int column=matches.getFirst();
        if(table.isCellEditable(row,column))throw new Failure("GUI_HISTORY_METHOD_EDITABLE");
        return column;
    }
    /** Reads the underlying public model, whose full filename is not its truncated renderer text. */
    public static String extensionFilename(Container root) {
        var table=(JTable)find(root,c->c instanceof JTable t&&column(t,"Item")>=0&&column(t,"Detail")>=0,true);
        var rows=new ArrayList<Integer>();
        for(int row=0;row<table.getRowCount();row++)if("Filename".equals(Objects.toString(table.getValueAt(row,column(table,"Item")),"")))rows.add(row);
        return Objects.toString(table.getValueAt(unique(rows),column(table,"Detail")),"");
    }
    /** Native Path equality preserves each platform's case and separator semantics without filesystem I/O. */
    public static boolean filePathMatches(String shown,Path expected) {
        if(shown==null)return false;
        try {var path=Path.of(shown);return path.isAbsolute()&&path.normalize().equals(expected.toAbsolutePath().normalize());}
        catch(java.nio.file.InvalidPathException invalid){return false;}
    }
    /** Matches the exact native unload question; a generic Yes button is insufficient. */
    public static boolean unloadConfirmation(Container root,String extension) {
        var texts=new ArrayList<String>();
        for(Component component:all(root))if(component.isShowing()) {
            String text=component instanceof JLabel label?label.getText():component instanceof javax.swing.text.JTextComponent input
                    &&!(input instanceof JPasswordField)&&!input.isEditable()?input.getText():null;
            if(text!=null)texts.add(text.replaceAll("<[^>]*>"," ").replace("&quot;","\"").replace("&#34;","\"")
                    .replace("&nbsp;"," ").replace('\u00a0',' ').replaceAll("\\s+"," ").trim());
        }
        return texts.contains("Unload extension")&&texts.stream().anyMatch(text->text.contains("Are you sure you want to unload \""+extension+"\"?"));
    }
    public static void requireAvailable(Component component) {
        if(!component.isShowing()||!component.isEnabled()||component.getWidth()<=0||component.getHeight()<=0)
            throw new Failure("GUI_CONTROL_UNAVAILABLE");
        if(component instanceof JComponent swing&&swing.getVisibleRect().isEmpty())throw new Failure("GUI_CONTROL_CLIPPED");
    }
    public static Component field(Container root,String name) {
        var direct=fieldTargets(root,all(root).stream().filter(c->c.isShowing()&&named(c,name)));
        if(!direct.isEmpty())return unique(direct);
        return unique(fieldTargets(root,all(root).stream().filter(c->c instanceof JLabel label&&c.isShowing()
                &&name.equals(label.getText())&&label.getLabelFor()!=null)));
    }
    /** A caption and its labelled control identify one input, never two action targets. */
    private static List<Component> fieldTargets(Container root,java.util.stream.Stream<Component> matches) {
        var seen=Collections.newSetFromMap(new IdentityHashMap<Component,Boolean>());
        return matches.map(c->c instanceof JLabel label&&label.getLabelFor()!=null?label.getLabelFor():c)
                .filter(c->c.isShowing()&&(c==root||SwingUtilities.isDescendingFrom(c,root)))
                .filter(seen::add).toList();
    }
    public static javax.swing.text.JTextComponent requestEditor(Container root) {
        var editor=(javax.swing.text.JTextComponent)find(root,c->c instanceof javax.swing.text.JTextComponent text&&!(c instanceof JPasswordField)
                &&c.isShowing()&&HostGuiMessages.request(text.getText()),true);
        if(!editor.isEditable())throw new Failure("GUI_REQUEST_EDITOR_READ_ONLY");return editor;
    }
    static String extensionFailure(String title,List<String> texts) {
        if(!"Error loading extension".equals(title))return null;
        return texts.stream().anyMatch(text->text.contains("java.lang.OutOfMemoryError: Java heap space"))
                ?"GUI_EXTENSION_HEAP_EXHAUSTED":"GUI_EXTENSION_LOAD_FAILED";
    }
}

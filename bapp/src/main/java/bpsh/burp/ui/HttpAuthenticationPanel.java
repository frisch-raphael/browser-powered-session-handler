package bpsh.burp.ui;

import bpsh.journey.HttpAuthentication;
import bpsh.journey.JourneyDefinition;
import bpsh.journey.SecretStore;
import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** Saved destination identity editor. Password snapshots are independent and never enter raw text maps. */
final class HttpAuthenticationPanel extends JPanel {
    private final JComboBox<HttpAuthentication.Protocol> protocol=new JComboBox<>(HttpAuthentication.Protocol.values());
    private final Map<String,JTextField> fields=new LinkedHashMap<>();
    private final JPasswordField password=new JPasswordField(30);
    private final JTextArea help=new JTextArea();
    private boolean loading, supplied;
    HttpAuthenticationPanel(Runnable changed) {
        super(new GridBagLayout());setBorder(BorderFactory.createEmptyBorder(12,12,12,12));
        protocol.setSelectedItem(HttpAuthentication.Protocol.NTLM_V2);
        protocol.setRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> list,Object value,int index,boolean selected,boolean focused) {
                String name=value==HttpAuthentication.Protocol.NTLM_V1?"NTLMv1":value==HttpAuthentication.Protocol.NTLM_V2?"NTLMv2":"Basic";
                return super.getListCellRendererComponent(list,name,index,selected,focused);
            }
        });
        protocol.setName("httpProtocol");addRow("Authentication type",protocol);
        for(String key:java.util.List.of("httpUsername","httpDomain","httpWorkstation","httpOrigins")) {
            JTextField field=UiTooltips.textField(36);field.setName(key);fields.put(key,field);
            String label=switch(key) {case "httpUsername"->"Username";case "httpDomain"->"NTLM domain (optional)";case "httpWorkstation"->"Workstation (optional)";default->"Allowed origins";};
            if(key.equals("httpOrigins")) {
                String guidance="Exact server addresses, separated by commas, for example https://app.example, https://login.example:8443. No paths. Filled from the Login URL when enabled; review before saving. Credentials are sent only to these addresses.";
                UiTooltips.set(field,guidance,340);
            }
            addRow(label,field);field.getDocument().addDocumentListener(new DocumentChangeListener(()->{if(!loading) {clearValidation();changed.run();}}));
        }
        password.setName("httpPassword");addRow("Password",password);
        password.getDocument().addDocumentListener(new DocumentChangeListener(()->{if(!loading) {supplied=true;clearValidation();changed.run();}}));
        setJourneyAlias("");
        help.setEditable(false);help.setOpaque(false);help.setLineWrap(true);help.setWrapStyleWord(true);help.setColumns(52);addRow("",help);
        protocol.addActionListener(event->{modes();if(!loading) {clearValidation();changed.run();}});modes();
    }
    private void addRow(String label,JComponent input) {
        int row=getComponentCount()/2;GridBagConstraints c=new GridBagConstraints();c.gridy=row;c.anchor=GridBagConstraints.NORTHWEST;c.insets=new Insets(4,0,8,12);
        JLabel title=UiTooltips.label(label);title.setLabelFor(input);UiTooltips.copy(input,title);add(title,c);c.gridx=1;c.weightx=1;c.fill=GridBagConstraints.HORIZONTAL;add(input==help?input:InlineValidation.wrap(input),c);
    }
    /** Updates the literal header example without touching edited credentials or interpreting the name as HTML. */
    void setJourneyAlias(String alias) {
        String example=alias==null||alias.isBlank()?"Name this journey to see its custom header.":AuthenticationTagMenu.httpHeader(alias);
        String text="These credentials can authenticate the browser login. To authenticate an individual Burp request, add this custom header:\n\n"+example
                +"\n\nThe extension uses this journey's HTTP authentication for that request and removes the custom header before sending it to the server."
                +"\n\nTo use only HTTP authentication, turn off form-based authentication and leave Capture credentials empty.";
        if(!text.equals(help.getText()))help.setText(text);
    }
    private void modes() {boolean ntlm=protocol.getSelectedItem()!=HttpAuthentication.Protocol.BASIC;fields.get("httpDomain").setEnabled(ntlm);fields.get("httpWorkstation").setEnabled(ntlm);}
    void showInvalid(String path,String guidance,boolean focus) {
        String field=path.split(":",2)[0];
        JComponent target=field.endsWith("password")||field.endsWith("httpPassword")?password:field.endsWith("username")?fields.get("httpUsername"):
                field.endsWith("domain")?fields.get("httpDomain"):field.endsWith("workstation")?fields.get("httpWorkstation"):
                field.endsWith("origins")?fields.get("httpOrigins"):protocol;
        InlineValidation.show(target,guidance);if(focus)InlineValidation.focus(target);
    }
    private void clearValidation() {
        InlineValidation.clear(protocol);InlineValidation.clear(password);fields.values().forEach(InlineValidation::clear);
    }
    void initializeOrigin(String loginUrl) {
        if(!fields.get("httpOrigins").getText().isBlank())return;
        try { fields.get("httpOrigins").setText(bpsh.journey.JourneyOrigins.authenticationOrigin(java.net.URI.create(loginUrl.trim())).toString()); }
        catch(IllegalArgumentException invalid) { /* The user must enter an explicit origin after fixing the URL. */ }
    }
    Map<String,String> text() {var result=new LinkedHashMap<String,String>();fields.forEach((key,input)->result.put(key,input.getText()));result.put("httpProtocol",((HttpAuthentication.Protocol)protocol.getSelectedItem()).name());return result;}
    char[] password() {return supplied?password.getPassword():null;}
    void populate(JourneyDefinition definition,SecretStore.Values values) {
        loading=true;
        try {
            clearValidation();
            var settings=definition.httpAuthentication();
            protocol.setSelectedItem(settings==null?HttpAuthentication.Protocol.NTLM_V2:settings.protocol());
            fields.get("httpUsername").setText(settings==null?"":settings.username());fields.get("httpDomain").setText(settings==null?"":settings.domain());
            fields.get("httpWorkstation").setText(settings==null?"":settings.workstation());
            fields.get("httpOrigins").setText(settings==null?"":settings.origins().stream().map(Object::toString).sorted().collect(java.util.stream.Collectors.joining(", ")));
            if(definition.draft()!=null) {
                fields.forEach((key,input)->input.setText(definition.draft().text().get(key)));
                try {protocol.setSelectedItem(HttpAuthentication.Protocol.valueOf(definition.draft().text().get("httpProtocol")));}catch(IllegalArgumentException ignored) {protocol.setSelectedItem(HttpAuthentication.Protocol.NTLM_V2);}
            }
            char[] secret=values.httpPassword();try {supplied=secret!=null;password.setText(secret==null?"":new String(secret));}finally {if(secret!=null)Arrays.fill(secret,'\0');}
            modes();
        } finally {loading=false;}
    }
    void clearSecret() {loading=true;try {password.setText("");supplied=false;}finally {loading=false;}}
}

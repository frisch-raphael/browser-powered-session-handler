package lab.auth;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.*;

/** One manual Montoya dispatch for H01's EXTENSIONS origin; contains no authentication or replay engine. */
public final class HostProbeExtension implements BurpExtension {
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean busy = new AtomicBoolean();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
        var thread = new Thread(task, "authentication-lab-host-probe"); thread.setDaemon(true); return thread;
    });
    private final JTextField origin = new JTextField();
    private final JTextField expectedAccount = new JTextField("user2");
    private final JComboBox<String> expectedProtocol = new JComboBox<>(new String[]{"Captured credentials", "BASIC", "NTLM_V1", "NTLM_V2"});
    private final JTextField expectedRoles = new JTextField("B,C1");
    private final JTextField selectedFile = new JTextField();
    private final JButton choose = new JButton("Load prepared request...");
    private final JButton send = new JButton("Send once from Extensions");
    private final JTextArea result = new JTextArea(16, 76);
    private final JLabel status = new JLabel("Choose the local lab origin and a prepared HTTP request file.");
    private MontoyaApi api;
    private Path requestFile;

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Authentication lab host probe");
        api.extension().registerUnloadingHandler(() -> { closed.set(true); worker.shutdownNow(); });
        SwingUtilities.invokeLater(() -> {
            if (closed.get()) return;
            var panel = new JPanel(new BorderLayout(8, 8));
            panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
            var fields = new JPanel(new GridLayout(0, 2, 8, 8));
            fields.add(new JLabel("Local lab origin")); fields.add(origin);
            fields.add(new JLabel("Expected account")); fields.add(expectedAccount);
            fields.add(new JLabel("Proof type")); fields.add(expectedProtocol);
            expectedProtocol.addActionListener(event -> expectedRoles.setEnabled(expectedProtocol.getSelectedIndex() == 0));
            fields.add(new JLabel("Expected roles (comma separated)")); fields.add(expectedRoles);
            fields.add(new JLabel("Prepared HTTP request")); fields.add(selectedFile);
            selectedFile.setEditable(false);
            origin.setToolTipText("For example, http://127.0.0.1:41234. Use the current prepared lab origin.");
            var actions = new JPanel(); actions.add(choose); actions.add(send); send.setEnabled(false);
            var top = new JPanel(new BorderLayout(8, 8)); top.add(fields); top.add(actions, BorderLayout.SOUTH);
            result.setEditable(false); result.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            result.setLineWrap(true); result.setWrapStyleWord(true);
            panel.add(top, BorderLayout.NORTH); panel.add(new JScrollPane(result)); panel.add(status, BorderLayout.SOUTH);
            choose.addActionListener(event -> chooseRequest(panel));
            send.addActionListener(event -> sendOnce());
            api.userInterface().registerSuiteTab("Auth lab probe", panel);
        });
    }

    private void chooseRequest(JPanel parent) {
        var chooser = new JFileChooser(); chooser.setDialogTitle("Select a prepared local lab HTTP request");
        if (chooser.showOpenDialog(parent) == JFileChooser.APPROVE_OPTION) {
            requestFile = chooser.getSelectedFile().toPath(); selectedFile.setText(requestFile.toAbsolutePath().toString());
            send.setEnabled(!busy.get()); status.setText("Ready. Each click makes one Montoya sendRequest call.");
        }
    }

    private void sendOnce() {
        if (closed.get() || !busy.compareAndSet(false, true)) return;
        Path file = requestFile; String target = origin.getText().trim();
        String account = expectedAccount.getText().trim(), roles = expectedRoles.getText().trim();
        String protocol = expectedProtocol.getSelectedIndex() == 0 ? null : (String) expectedProtocol.getSelectedItem();
        choose.setEnabled(false); send.setEnabled(false); status.setText("Sending one prepared request...");
        worker.execute(() -> {
            String summary;
            try { summary = dispatch(file, target, account, roles, protocol); }
            catch (PreparationException error) { summary = error.getMessage(); }
            catch (Exception error) { summary = "No usable response was obtained. Inspect Burp and the lab feedback. No request or credential values were recorded."; }
            String safe = summary;
            busy.set(false);
            SwingUtilities.invokeLater(() -> {
                if (closed.get()) return;
                result.setText(safe); result.setCaretPosition(0); choose.setEnabled(true); send.setEnabled(requestFile != null);
                status.setText("Finished. This result is a manual host checkpoint, not full profile acceptance.");
            });
        });
    }

    private String dispatch(Path file, String target, String account, String roles, String protocol) throws Exception {
        if (file == null || !Files.isRegularFile(file)) throw new PreparationException("Choose a readable prepared HTTP request file.");
        if (Files.size(file) == 0 || Files.size(file) > 4L * 1024 * 1024) throw new PreparationException("The prepared request must contain between 1 byte and 4 MiB.");
        if (!account.matches("[A-Za-z0-9._@-]{1,128}")) throw new PreparationException("Enter the expected public fixture account identifier.");
        var required = new TreeSet<String>();
        for (String value : protocol == null ? roles.split(",", -1) : new String[0]) {
            String role = value.trim();
            if (!Set.of("B", "C1", "C2").contains(role) || !required.add(role))
                throw new PreparationException("Choose each expected fixture role once: B, C1 or C2.");
        }
        URI uri;
        try { uri = URI.create(target); }
        catch (IllegalArgumentException error) { throw new PreparationException("Enter the current local lab HTTP(S) origin."); }
        if (!Set.of("http", "https").contains(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/")))
            throw new PreparationException("Enter an HTTP(S) origin; the request file supplies its path.");
        for (var address : InetAddress.getAllByName(uri.getHost())) if (!address.isLoopbackAddress())
            throw new PreparationException("The host probe sends only to local lab origins.");
        int port = uri.getPort() == -1 ? uri.getScheme().equals("https") ? 443 : 80 : uri.getPort();
        if (port < 1 || port > 65535) throw new PreparationException("Enter the current lab origin's listening port.");
        byte[] input = Files.readAllBytes(file);
        var service = HttpService.httpService(uri.getHost(), port, uri.getScheme().equals("https"));
        var request = HttpRequest.httpRequest(service, ByteArray.byteArray(input));
        var record = JsonObjectNode.jsonObjectNode();
        record.putString("probeId", UUID.randomUUID().toString()); record.putString("startedAt", Instant.now().toString());
        record.putString("expectedToolOrigin", "EXTENSIONS"); record.putString("dispatchApi", "Montoya.http.sendRequest");
        record.putString("inputRequestSha256", sha(input));
        record.putString("expectedAccount", account); record.putString("expectedRoles", String.join(",", required));
        if (protocol != null) record.putString("expectedProtocol", protocol);
        shape(record, "parsedInput", request);
        // This is the only dispatch. The loaded product owns acquisition, injection, pause and any authorized replay.
        var exchange = api.http().sendRequest(request, RequestOptions.requestOptions().withResponseTimeout(20_000));
        shape(record, "returnedRequest", exchange.request());
        var response = exchange.response();
        if (response == null) { record.putString("proof", "no-response"); return retain(file, record); }
        record.putNumber("httpStatus", response.statusCode()); record.putNumber("responseBytes", response.body().length());
        record.putString("proof", "not-established");
        if (response.body().length() <= 65_536) {
            try {
                var body = JsonNode.jsonNode(response.bodyToString()).asObject();
                if (protocol != null) {
                    String actualAccount = publicId(body.getString("user"));
                    String actualProtocol = body.getString("protocol");
                    if (!Set.of("BASIC", "NTLM_V1", "NTLM_V2").contains(actualProtocol)) throw new IllegalArgumentException();
                    record.putString("accountId", actualAccount);record.putString("observedProtocol", actualProtocol);
                    record.putBoolean("accountMatches", account.equals(actualAccount));record.putBoolean("protocolMatches", protocol.equals(actualProtocol));
                    if (response.statusCode() == 200 && account.equals(actualAccount) && protocol.equals(actualProtocol))
                        record.putString("proof", "accepted-expected-account-and-http-authentication-type");
                    return retain(file, record);
                }
                String actualAccount = publicId(body.getString("accountId"));
                String issuance = body.hasString("issuanceId") ? publicId(body.getString("issuanceId")) : null;
                var actualRoles = new TreeSet<String>();
                for (var node : body.get("acceptedRoles").asArray().asList()) {
                    String role = node.asString(); if (!Set.of("B", "C1", "C2").contains(role)) throw new IllegalArgumentException();
                    actualRoles.add(role);
                }
                record.putString("accountId", actualAccount); if (issuance != null) record.putString("issuanceId", issuance);
                record.putString("acceptedRoles", String.join(",", actualRoles));
                record.putBoolean("accountMatches", account.equals(actualAccount)); record.putBoolean("rolesMatch", required.equals(actualRoles));
                if (response.statusCode() == 200 && account.equals(actualAccount) && required.equals(actualRoles) && issuance != null)
                    record.putString("proof", "accepted-expected-account-and-roles");
            } catch (RuntimeException ignored) { /* An unknown response cannot qualify a protected-use proof. Never print its body. */ }
        }
        return retain(file, record);
    }

    /** Records only counts, fixed fixture-role labels, tag presence and a digest; never header values. */
    private static void shape(JsonObjectNode record, String prefix, HttpRequest request) throws Exception {
        byte[] bytes = request.toByteArray().getBytes();
        record.putString(prefix + "Sha256", sha(bytes));
        record.putBoolean(prefix + "HasNativeTags", new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1).contains("<@"));
        var roles = new TreeSet<String>(); int authorization = 0, cookies = 0, directives = 0;
        for (var header : request.headers()) {
            if (header.name().equalsIgnoreCase("BPSP-HTTP-AUTHENT")) directives++;
            if (header.name().equalsIgnoreCase("Authorization")) { authorization++; roles.add("B"); }
            if (header.name().equalsIgnoreCase("Cookie")) {
                cookies++;
                for (String pair : header.value().split(";")) {
                    String name = pair.split("=", 2)[0].trim();
                    if (name.equals("LAB_C1")) roles.add("C1");
                    if (name.equals("LAB_C2")) roles.add("C2");
                }
            }
        }
        record.putNumber(prefix + "HttpAuthenticationDirectives", directives);
        record.putNumber(prefix + "AuthorizationHeaders", authorization);
        record.putNumber(prefix + "CookieHeaders", cookies);
        record.putString(prefix + "Roles", String.join(",", roles));
    }

    /** Retains the same credential-free metadata shown in the UI, beside the explicitly selected input. */
    private static String retain(Path input, JsonObjectNode record) {
        Path evidence = input.resolveSibling(input.getFileName() + "." + record.getString("probeId") + ".probe.json");
        try {
            java.nio.file.Files.writeString(evidence, record.toJsonString(), java.nio.charset.StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE_NEW);
        } catch (java.io.IOException error) { record.putString("evidenceWrite", "failed; result remains visible"); }
        return record.toJsonString();
    }

    private static String publicId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._@-]{1,128}")) throw new IllegalArgumentException();
        return value;
    }
    private static String sha(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static final class PreparationException extends Exception {
        PreparationException(String safe) { super(safe); }
    }
}

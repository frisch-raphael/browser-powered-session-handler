import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;

import burp.api.montoya.persistence.PersistedObject;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.locks.ReentrantLock;

public class Extension implements BurpExtension
{
    private static final String EXT_NAME = "Browser powered JWT fetcher";
    private static final String DEFAULT_TOKEN_URL = "http://127.0.0.1:7575/token?refresh_frequency=120";
    private static final String STORAGE_KEY = "token_url";
    private static final String API_SUBSTRING = "sopht";
    private static final Integer JWT_TTL_SECONDS = 2800;
    private volatile boolean enabled = true;

    private MontoyaApi api;
    private PersistedObject storage;

    private final TokenCache tokenCache = new TokenCache();

    @Override
    public void initialize(MontoyaApi montoyaApi)
    {
        this.api = montoyaApi;
        this.storage = api.persistence().extensionData();

        api.extension().setName(EXT_NAME);

        api.userInterface().registerSuiteTab("OIDC Token", buildUi());

        api.http().registerHttpHandler(new JwtHandler());

        api.logging().logToOutput(EXT_NAME + " loaded");
    }

    // ================= UI =================

    private Component buildUi()
    {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextField urlField = new JTextField(getTokenUrl(), 50);
        JButton save = new JButton("Save URL");
        JButton test = new JButton("Test");
        JLabel status = new JLabel("Ready");
        JToggleButton enableToggle = new JToggleButton("Enabled", enabled);

        save.addActionListener(e -> {
            setTokenUrl(urlField.getText().trim());
            tokenCache.invalidate();
            status.setText("Saved, cache cleared");
        });

        test.addActionListener(e -> {
            try {
                String t = tokenCache.get(true);
                status.setText("OK (len=" + t.length() + ")");
            } catch (Exception ex) {
                status.setText("Failed: " + ex.getMessage());
            }
        });

        enableToggle.addActionListener(e -> {
            enabled = enableToggle.isSelected();
            enableToggle.setText(enabled ? "Enabled" : "Disabled");
            status.setText(enabled ? "Enabled" : "Disabled");
        });

        JPanel top = new JPanel(new BorderLayout(6, 6));
        top.add(new JLabel("Token service URL:"), BorderLayout.WEST);
        top.add(urlField, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(save);
        buttons.add(test);
        buttons.add(enableToggle);

        panel.add(top, BorderLayout.NORTH);
        panel.add(buttons, BorderLayout.CENTER);
        panel.add(status, BorderLayout.SOUTH);

        return panel;
    }

    private String getTokenUrl()
    {
        String v = storage.getString(STORAGE_KEY);
        return (v == null || v.isBlank()) ? DEFAULT_TOKEN_URL : v;
    }

    private void setTokenUrl(String url)
    {
        storage.setString(STORAGE_KEY, url.isBlank() ? DEFAULT_TOKEN_URL : url);
    }

    // ================= HTTP HANDLER =================

    private final class JwtHandler implements HttpHandler
    {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request)
        {
            if (!enabled) {
                return RequestToBeSentAction.continueWith(request);
            }
            // test request goes to API
            if (!request.url().toLowerCase().contains(API_SUBSTRING.toLowerCase())) {
                return RequestToBeSentAction.continueWith(request);
            }
            try {
                if (!api.scope().isInScope(request.url())) {
                    return RequestToBeSentAction.continueWith(request);
                }

                String jwt = tokenCache.get(false);

                HttpHeader authHeader = HttpHeader.httpHeader("Authorization", "Bearer " + jwt);

                // Idempotent: remove any existing Authorization header, then add ours.
                HttpRequest updated = request
                        .withHeader(authHeader)
                        .withHeader("test", "test");


                return RequestToBeSentAction.continueWith(updated);

            } catch (Exception e) {
                api.logging().logToError("JWT injection failed: " + e.getMessage());
                return RequestToBeSentAction.continueWith(request);
            }
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response)
        {
            if (!enabled) {
                return ResponseReceivedAction.continueWith(response);
            }
            int sc = response.statusCode();
            if (sc == 401) {
                tokenCache.invalidate();
            }
            return ResponseReceivedAction.continueWith(response);
        }
    }

    // ================= TOKEN CACHE =================

    private final class TokenCache
    {
        private static final long TTL_SECONDS = 2800;

        private final ReentrantLock lock = new ReentrantLock();
        private String token;
        private long validUntil;

        private final HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();

        void invalidate()
        {
            lock.lock();
            try {
                token = null;
                validUntil = 0;
            } finally {
                lock.unlock();
            }
        }

        String get(boolean force) throws Exception
        {
            long now = System.currentTimeMillis() / 1000;

            if (!force && token != null && now < validUntil) {
                return token;
            }

            lock.lock();
            try {
                now = System.currentTimeMillis() / 1000;
                if (!force && token != null && now < validUntil) {
                    return token;
                }

                token = fetch();
                validUntil = now + JWT_TTL_SECONDS;
                return token;

            } finally {
                lock.unlock();
            }
        }

        private String fetch() throws Exception
        {
            URI uri = URI.create(getTokenUrl());

            var req = java.net.http.HttpRequest.newBuilder(uri)
                    .GET()
                    .timeout(Duration.ofSeconds(15))
                    .build();

            HttpResponse<String> resp =
                    client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                throw new RuntimeException("Token HTTP " + resp.statusCode());
            }

            String body = resp.body().trim();

            if (body.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
                body = body.substring(7).trim();
            }

            if (!body.contains(".")) {
                api.logging().logToError("Warning: token does not look like a JWT");
            }

            return body;
        }
    }
}

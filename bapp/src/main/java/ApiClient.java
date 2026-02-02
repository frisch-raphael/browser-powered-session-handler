import burp.api.montoya.logging.Logging;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

public final class ApiClient {
    private final HttpClient client;
    private final ObjectMapper mapper;
    private final Logging logging;
    private final AtomicReference<Config> configRef;

    public ApiClient(Logging logging, AtomicReference<Config> configRef) {
        this.logging = logging;
        this.configRef = configRef;
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        this.mapper = new ObjectMapper();
    }

    public void testHealth() throws IOException, InterruptedException {
        Config cfg = configRef.get();
        URI uri = URI.create(cfg.apiBaseUrl + "/health");

        var req = java.net.http.HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> resp;
        try {
            resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException | InterruptedException ex) {
            logging.logToError("Token service unreachable (" + errorMessage(ex) + ")");
            throw ex;
        }

        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            logging.logToError("Health check failed: HTTP " + resp.statusCode() + " " + resp.body());
            throw new RuntimeException("Config HTTP " + resp.statusCode() + ": " + resp.body());
        }
        logging.logToOutput("Health OK");
    }

    public void sendConfig(Config cfg) throws IOException, InterruptedException {
        Map<String, Object> payload = new LinkedHashMap<>();

        Map<String, Object> parsing = new LinkedHashMap<>();
        parsing.put("mode", cfg.tokenParsingMode);
        parsing.put("path", cfg.tokenJsonPath);
        parsing.put("cookie_name", cfg.tokenCookieName);

        payload.put("token_url_substring", cfg.authenticationServerUrlSubstring);
        payload.put("refresh_frequency_seconds", cfg.refreshFrequencySeconds);
        payload.put("refresh_skew_seconds", cfg.refreshSkewSeconds);
        payload.put("nav_timeout_ms", cfg.navTimeoutMs);
        payload.put("wait_token_timeout_ms", cfg.waitTokenTimeoutMs);
        payload.put("parsing", parsing);

        String body = mapper.writeValueAsString(payload);
        URI uri = URI.create(cfg.apiBaseUrl + "/config");

        var req = java.net.http.HttpRequest.newBuilder(uri)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> resp;
        try {
            resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException | InterruptedException ex) {
            logging.logToError("Config update failed: token service unreachable (" + errorMessage(ex) + ")");
            throw ex;
        }

        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            logging.logToError("Config update failed: HTTP " + resp.statusCode() + " " + resp.body());
            throw new RuntimeException("Config HTTP " + resp.statusCode() + ": " + resp.body());
        }
        logging.logToOutput("Config updated successfully");
    }

    public String fetchToken(boolean force) throws IOException, InterruptedException {
        Config cfg = configRef.get();
        URI uri = URI.create(cfg.apiBaseUrl + "/token");
        long timeoutMs = Math.max(5000L, (long) cfg.navTimeoutMs + (long) cfg.waitTokenTimeoutMs + 5000L);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("authentication_url", cfg.authenticationUrl);
        payload.put("headless", cfg.headless);
        payload.put("proxy", cfg.browserProxy);
        payload.put("steps", cfg.steps);
        payload.put("mtls_enabled", cfg.mtlsEnabled);
        payload.put("mtls_hostname", cfg.mtlsHostname);
        payload.put("mtls_pin", cfg.mtlsPin);
        payload.put("mtls_cert_cn", cfg.mtlsCertCn);
        payload.put("force", force);
        String body = mapper.writeValueAsString(payload);

        var req = java.net.http.HttpRequest.newBuilder(uri)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofMillis(timeoutMs))
                .build();

        HttpResponse<String> resp;
        try {
            resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException | InterruptedException ex) {
            logging.logToError("Token fetch failed: token service unreachable (" + errorMessage(ex) + ")");
            throw ex;
        }

        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            logging.logToError("Token fetch failed: HTTP " + resp.statusCode() + " " + resp.body());
            throw new RuntimeException("Token HTTP " + resp.statusCode() + ": " + resp.body());
        }

        String tokenBody = resp.body().trim();
        if (tokenBody.toLowerCase().startsWith("bearer ")) {
            tokenBody = tokenBody.substring(7).trim();
        }
        logging.logToOutput("Token fetched successfully");
        return tokenBody;
    }

    public void invalidateCache() throws IOException, InterruptedException {
        Config cfg = configRef.get();
        URI uri = URI.create(cfg.apiBaseUrl + "/invalidate");

        var req = java.net.http.HttpRequest.newBuilder(uri)
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build();

        HttpResponse<String> resp;
        try {
            resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException | InterruptedException ex) {
            logging.logToError("Invalidate failed: token service unreachable (" + errorMessage(ex) + ")");
            throw ex;
        }

        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            logging.logToError("Invalidate failed: HTTP " + resp.statusCode() + " " + resp.body());
            throw new RuntimeException("Invalidate HTTP " + resp.statusCode() + ": " + resp.body());
        }
        logging.logToOutput("Token cache invalidated");
    }

    private String errorMessage(Exception ex) {
        String msg = ex.getMessage();
        if (msg == null || msg.isBlank()) {
            return ex.getClass().getSimpleName();
        }
        return msg;
    }
}

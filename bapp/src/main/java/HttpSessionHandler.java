import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.time.ZonedDateTime;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class HttpSessionHandler implements HttpHandler {
    private final MontoyaApi api;
    private final AtomicReference<Config> configRef;
    private final ApiClient apiClient;
    private final LocalTokenCache localTokenCache;
    private final AtomicBoolean enabled;

    public HttpSessionHandler(
            MontoyaApi api,
            AtomicReference<Config> configRef,
            ApiClient apiClient,
            LocalTokenCache localTokenCache,
            AtomicBoolean enabled) {
        this.api = api;
        this.configRef = configRef;
        this.apiClient = apiClient;
        this.localTokenCache = localTokenCache;
        this.enabled = enabled;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!enabled.get()) {
            return RequestToBeSentAction.continueWith(request);
        }

        Config cfg = configRef.get();
        if (!shouldHandleTool(cfg, request.toolSource().toolType())) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (!shouldHandleUrl(cfg, request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }

        if (localTokenCache.isRefreshing()) {
            return RequestToBeSentAction.continueWith(request);
        }

        try {
            String token = localTokenCache.get(false);
            HttpRequest updated;
            if ("cookie".equals(cfg.tokenParsingMode)) {
                String cookieName = cfg.tokenCookieName == null ? "" : cfg.tokenCookieName.trim();
                if (cookieName.isEmpty()) {
                    throw new IllegalArgumentException("Cookie name is required for cookie mode");
                }
                URI uri = URI.create(request.url());
                String host = uri.getHost();
                if (host != null && !host.isBlank()) {
                    api.http().cookieJar().setCookie(
                            cookieName,
                            token,
                            "/",
                            host,
                            ZonedDateTime.now().plusYears(1));
                }
                String existing = request.headerValue("Cookie");
                String cookieValue = cookieName + "=" + token;
                String merged = (existing == null || existing.isBlank())
                        ? cookieValue
                        : existing + "; " + cookieValue;
                updated = request
                        .withRemovedHeader("Cookie")
                        .withAddedHeader("Cookie", merged);
            } else {
                updated = request
                        .withRemovedHeader("Authorization")
                        .withAddedHeader("Authorization", "Bearer " + token);
            }
            return RequestToBeSentAction.continueWith(updated);
        } catch (Exception e) {
            api.logging().logToError("Token injection failed: " + e.getMessage());
            return RequestToBeSentAction.continueWith(request);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!enabled.get()) {
            return ResponseReceivedAction.continueWith(response);
        }

        Config cfg = configRef.get();
        if (!shouldHandleTool(cfg, response.toolSource().toolType())) {
            return ResponseReceivedAction.continueWith(response);
        }
        if (!shouldHandleUrl(cfg, response.initiatingRequest().url())) {
            return ResponseReceivedAction.continueWith(response);
        }

        if (cfg.autoSessionRecovery == null || cfg.autoSessionRecovery) {
            if ("status_code".equals(cfg.sessionLostMode)) {
                if (response.statusCode() == cfg.sessionLostStatusCode) {
                    tryInvalidate();
                    api.logging().logToOutput("Session lost: status code " + cfg.sessionLostStatusCode);
                }
            } else if (cfg.sessionLostRegexPattern != null) {
                if (cfg.sessionLostRegexPattern.matcher(response.bodyToString()).find()) {
                    tryInvalidate();
                    api.logging().logToOutput("Session lost: regex matched");
                }
            }
        }

        return ResponseReceivedAction.continueWith(response);
    }

    private boolean shouldHandleTool(Config cfg, ToolType toolType) {
        if (cfg.scopeToolSet == null || cfg.scopeToolSet.isEmpty()) {
            return false;
        }
        return cfg.scopeToolSet.contains(toolType);
    }

    private boolean shouldHandleUrl(Config cfg, String url) {
        String mode = cfg.requestHandlingMode == null ? "burp_scope" : cfg.requestHandlingMode;
        if ("all_requests".equals(mode)) {
            return true;
        }
        if ("single_url".equals(mode)) {
            String prefix = cfg.singleUrlPrefix == null ? "" : cfg.singleUrlPrefix.trim();
            if (prefix.isEmpty()) {
                return false;
            }
            return url != null && url.startsWith(prefix);
        }
        return api.scope().isInScope(url);
    }

    private void tryInvalidate() {
        try {
            apiClient.invalidateCache();
            localTokenCache.invalidate();
        } catch (Exception ex) {
            api.logging().logToError("Failed to invalidate token cache: " + ex.getMessage());
        }
    }
}

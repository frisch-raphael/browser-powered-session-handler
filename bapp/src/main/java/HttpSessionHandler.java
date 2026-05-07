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
import java.util.Locale;
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
        if (isApiServiceUrl(cfg, request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (!shouldHandleTool(cfg, request.toolSource().toolType())) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (!shouldHandleUrl(cfg, request.url())) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (containsHackvertorTag(request)) {
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
        if (isApiServiceUrl(cfg, response.initiatingRequest().url())) {
            return ResponseReceivedAction.continueWith(response);
        }
        if (!shouldHandleTool(cfg, response.toolSource().toolType())) {
            return ResponseReceivedAction.continueWith(response);
        }
        if (!shouldHandleUrl(cfg, response.initiatingRequest().url())) {
            return ResponseReceivedAction.continueWith(response);
        }
        if (containsHackvertorTag(response.initiatingRequest())) {
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

    private boolean isApiServiceUrl(Config cfg, String url) {
        if (cfg.apiBaseUrl == null || cfg.apiBaseUrl.isBlank() || url == null || url.isBlank()) {
            return false;
        }
        try {
            URI apiUri = URI.create(cfg.apiBaseUrl.trim());
            URI requestUri = URI.create(url.trim());
            if (!sameIgnoreCase(apiUri.getScheme(), requestUri.getScheme())) {
                return false;
            }
            if (!sameIgnoreCase(apiUri.getHost(), requestUri.getHost())) {
                return false;
            }
            if (effectivePort(apiUri) != effectivePort(requestUri)) {
                return false;
            }

            String apiPath = normalizedPath(apiUri.getPath());
            String requestPath = normalizedPath(requestUri.getPath());
            return "/".equals(apiPath)
                    || requestPath.equals(apiPath)
                    || requestPath.startsWith(apiPath + "/");
        } catch (IllegalArgumentException ex) {
            String apiBaseUrl = cfg.apiBaseUrl.trim();
            return !apiBaseUrl.isEmpty() && url.startsWith(apiBaseUrl);
        }
    }

    private boolean sameIgnoreCase(String left, String right) {
        if (left == null || right == null) {
            return left == right;
        }
        return left.equalsIgnoreCase(right);
    }

    private int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        String scheme = uri.getScheme();
        if ("http".equalsIgnoreCase(scheme)) {
            return 80;
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return 443;
        }
        return -1;
    }

    private String normalizedPath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        if (path.length() > 1 && path.endsWith("/")) {
            return path.substring(0, path.length() - 1);
        }
        return path;
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

    private boolean containsHackvertorTag(HttpRequest request) {
        String message = request.toString();
        return message != null && message.contains("<@_") && message.contains("</@_");
    }


    private boolean containsCookie(String cookieHeader, String cookieName) {
        String normalizedHeader = cookieHeader.toLowerCase(Locale.ROOT);
        String normalizedName = cookieName.toLowerCase(Locale.ROOT) + "=";
        return normalizedHeader.startsWith(normalizedName)
                || normalizedHeader.contains("; " + normalizedName)
                || normalizedHeader.contains(";" + normalizedName);
    }
}

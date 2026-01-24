import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.core.ToolType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class ConfigManager {
    private static final String STORAGE_KEY = "bpsh_config";

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final PersistedObject storage;
    private final Logging logging;

    public ConfigManager(PersistedObject storage, Logging logging) {
        this.storage = storage;
        this.logging = logging;
    }

    public Config loadFromStorage() {
        String json = storage.getString(STORAGE_KEY);
        if (json == null || json.isBlank()) {
            return Config.defaults();
        }
        try {
            Config cfg = parseJson(json);
            return normalize(cfg);
        } catch (Exception ex) {
            logging.logToError("Failed to load config, using defaults: " + ex.getMessage());
            return Config.defaults();
        }
    }

    public void saveToStorage(Config cfg) {
        try {
            storage.setString(STORAGE_KEY, toJson(cfg));
        } catch (JsonProcessingException ex) {
            logging.logToError("Failed to persist config: " + ex.getMessage());
        }
    }

    public Config parseJson(String json) throws JsonProcessingException {
        return MAPPER.readValue(json, Config.class);
    }

    public String toJson(Config cfg) throws JsonProcessingException {
        return MAPPER.writeValueAsString(cfg);
    }

    public Config normalize(Config cfg) {
        if (cfg == null) {
            cfg = Config.defaults();
        }
        if ("raw".equals(cfg.tokenParsingMode)) {
            cfg.tokenParsingMode = "cookie";
        } else if (!"json_path".equals(cfg.tokenParsingMode) && !"cookie".equals(cfg.tokenParsingMode)) {
            cfg.tokenParsingMode = "json_path";
        }
        if (cfg.tokenCookieName == null) {
            cfg.tokenCookieName = "";
        }
        if (cfg.steps == null) {
            cfg.steps = new ArrayList<>();
        }
        if (cfg.scopeTools == null) {
            cfg.scopeTools = new ArrayList<>();
        }
        if (cfg.pythonExecutable == null) {
            cfg.pythonExecutable = "";
        }

        Set<ToolType> allowed = new LinkedHashSet<>();
        allowed.add(ToolType.SCANNER);
        allowed.add(ToolType.PROXY);
        allowed.add(ToolType.REPEATER);
        allowed.add(ToolType.EXTENSIONS);
        allowed.add(ToolType.INTRUDER);

        Set<ToolType> toolSet = new LinkedHashSet<>();
        for (String name : cfg.scopeTools) {
            try {
                ToolType type = ToolType.valueOf(name);
                if (allowed.contains(type)) {
                    toolSet.add(type);
                }
            } catch (IllegalArgumentException ignored) {
            }
        }
        cfg.scopeToolSet = toolSet;

        if ("regex".equals(cfg.sessionLostMode)
                && cfg.sessionLostRegex != null
                && !cfg.sessionLostRegex.isBlank()) {
            cfg.sessionLostRegexPattern = Pattern.compile(cfg.sessionLostRegex, Pattern.DOTALL);
        } else {
            cfg.sessionLostRegexPattern = null;
        }
        return cfg;
    }

    public void validate(Config cfg) {
        if (cfg.authenticationUrl == null || cfg.authenticationUrl.isBlank()) {
            throw new IllegalArgumentException("Authentication URL is required");
        }
        if (cfg.steps == null || cfg.steps.isEmpty()) {
            throw new IllegalArgumentException("At least one authentication step is required");
        }
        for (int i = 0; i < cfg.steps.size(); i++) {
            AuthStep step = cfg.steps.get(i);
            if (!"click".equals(step.type)
                    && !"input".equals(step.type)
                    && !"wait_load_state".equals(step.type)) {
                throw new IllegalArgumentException("Invalid step type at index " + i);
            }
            if (("click".equals(step.type) || "input".equals(step.type))
                    && (step.selector == null || step.selector.isBlank())) {
                throw new IllegalArgumentException("Missing selector at index " + i);
            }
            if ("input".equals(step.type) && (step.value == null || step.value.isBlank())) {
                throw new IllegalArgumentException("Missing input value at index " + i);
            }
            if ("wait_load_state".equals(step.type)
                    && step.value != null
                    && !step.value.isBlank()) {
                String state = step.value.trim().toLowerCase(Locale.ROOT);
                if (!state.equals("load")
                        && !state.equals("domcontentloaded")
                        && !state.equals("networkidle")) {
                    throw new IllegalArgumentException(
                            "Invalid load state at index " + i + " (load, domcontentloaded, networkidle)");
                }
            }
        }
        if (cfg.authenticationServerUrlSubstring == null || cfg.authenticationServerUrlSubstring.isBlank()) {
            throw new IllegalArgumentException("Authentication server substring is required");
        }
        if (!"json_path".equals(cfg.tokenParsingMode) && !"cookie".equals(cfg.tokenParsingMode)) {
            throw new IllegalArgumentException("Token parsing mode must be cookie or json_path");
        }
        if ("json_path".equals(cfg.tokenParsingMode)
                && (cfg.tokenJsonPath == null || cfg.tokenJsonPath.isBlank())) {
            throw new IllegalArgumentException("JSON path is required for JSON parsing");
        }
        if ("cookie".equals(cfg.tokenParsingMode)
                && (cfg.tokenCookieName == null || cfg.tokenCookieName.isBlank())) {
            throw new IllegalArgumentException("Cookie name is required for cookie parsing");
        }
        if ("regex".equals(cfg.sessionLostMode)
                && (cfg.sessionLostRegex == null || cfg.sessionLostRegex.isBlank())) {
            throw new IllegalArgumentException("Regex is required for regex session detection");
        }
    }
}

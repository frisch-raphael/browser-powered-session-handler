import burp.api.montoya.core.ToolType;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public final class Config {
    public String apiBaseUrl;
    public String authenticationUrl;
    public boolean headless;
    public List<AuthStep> steps;
    public boolean mtlsEnabled;
    public String mtlsHostname;
    public String mtlsPin;
    @JsonProperty("mtls_cert_cn")
    public String mtlsCertCn;
    public String pythonExecutable;

    public String authenticationServerUrlSubstring;
    public String tokenParsingMode;
    public String tokenJsonPath;
    public String tokenCookieName;
    public int refreshFrequencySeconds;
    public int refreshSkewSeconds;
    public int navTimeoutMs;
    public int waitTokenTimeoutMs;

    public String sessionLostMode;
    public int sessionLostStatusCode;
    public String sessionLostRegex;

    public List<String> scopeTools;

    @JsonIgnore
    public Set<ToolType> scopeToolSet = new LinkedHashSet<>();

    @JsonIgnore
    public Pattern sessionLostRegexPattern;

    static Config defaults() {
        Config cfg = new Config();
        cfg.apiBaseUrl = "http://127.0.0.1:7575";
        cfg.authenticationUrl = "";
        cfg.headless = true;
        cfg.steps = new ArrayList<>();
        cfg.steps.add(new AuthStep("click", "", ""));
        cfg.mtlsEnabled = false;
        cfg.mtlsHostname = "";
        cfg.mtlsPin = "";
        cfg.mtlsCertCn = "";
        cfg.pythonExecutable = "";

        cfg.authenticationServerUrlSubstring = "/protocol/openid-connect/token";
        cfg.tokenParsingMode = "json_path";
        cfg.tokenJsonPath = "access_token";
        cfg.tokenCookieName = "";
        cfg.refreshFrequencySeconds = 120;
        cfg.refreshSkewSeconds = 10;
        cfg.navTimeoutMs = 30000;
        cfg.waitTokenTimeoutMs = 3000;

        cfg.sessionLostMode = "status_code";
        cfg.sessionLostStatusCode = 401;
        cfg.sessionLostRegex = "";

        cfg.scopeTools = new ArrayList<>();
        cfg.scopeTools.add(ToolType.SCANNER.name());
        cfg.scopeTools.add(ToolType.PROXY.name());
        cfg.scopeTools.add(ToolType.REPEATER.name());
        cfg.scopeTools.add(ToolType.EXTENSIONS.name());
        cfg.scopeTools.add(ToolType.INTRUDER.name());
        cfg.scopeToolSet.add(ToolType.SCANNER);
        cfg.scopeToolSet.add(ToolType.PROXY);
        cfg.scopeToolSet.add(ToolType.REPEATER);
        cfg.scopeToolSet.add(ToolType.EXTENSIONS);
        cfg.scopeToolSet.add(ToolType.INTRUDER);
        return cfg;
    }
}

final class AuthStep {
    public String type;
    public String selector;
    public String value;
    public String pin;
    @JsonProperty("cert_cn")
    public String certCn;

    AuthStep() {
    }

    AuthStep(String type, String selector, String value) {
        this.type = type;
        this.selector = selector;
        this.value = value;
        this.pin = "";
        this.certCn = "";
    }

    AuthStep(String type, String selector, String value, String pin, String certCn) {
        this.type = type;
        this.selector = selector;
        this.value = value;
        this.pin = pin;
        this.certCn = certCn;
    }
}

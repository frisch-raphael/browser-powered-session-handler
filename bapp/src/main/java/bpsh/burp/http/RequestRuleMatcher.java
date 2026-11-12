package bpsh.burp.http;

import bpsh.browser.AuthTrafficGuard;
import bpsh.journey.ConfigurationException;
import bpsh.journey.JourneyDefinition;
import bpsh.pattern.BoundedRegex;
import bpsh.request.RequestSettings;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.re2j.Pattern;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Immutable matching plan for one validated controls publication. */
public final class RequestRuleMatcher {
    /** @param exchange Callback-family identity. @param tool Supported tool, or null. @param incomingPort Actual listener port, or null. */
    public record Context(RequestExchange exchange, RequestSettings.Tool tool, Integer incomingPort) {
        /** Keeps missing metadata distinct from an inferred browser assignment. */
        public Context { Objects.requireNonNull(exchange); }
    }
    /** One compiled rule; nonregex modes do not own a pattern. */
    private record Compiled(RequestSettings.AutomaticRule rule, Pattern pattern) {}
    private final RequestSettings.Controls controls;
    private final List<Compiled> rules;

    /** @param controls Validated source. @param rules Immutable compiled rules. */
    private RequestRuleMatcher(RequestSettings.Controls controls, List<Compiled> rules) {
        this.controls = controls; this.rules = List.copyOf(rules);
    }

    /**
     * Validates and compiles every rule, including disabled rows, before publication.
     * @param controls Source snapshot.
     * @return Immutable matching plan.
     * @throws ConfigurationException For duplicate journeys, excess rules or invalid regex syntax/bounds.
     */
    public static RequestRuleMatcher compile(RequestSettings.Controls controls) {
        Objects.requireNonNull(controls);
        if (controls.rules().size() > 64) throw new ConfigurationException("Session handling supports at most 64 rules.");
        var identities = new java.util.HashSet<RequestSettings.JourneySelection>();
        var compiled = new ArrayList<Compiled>();
        for (var rule : controls.rules()) {
            if (!identities.add(rule.journey())) throw new ConfigurationException("A journey may appear only once in Session handling.");
            Pattern pattern = null;
            if (rule.url() instanceof RequestSettings.Regex regex) {
                try { pattern = BoundedRegex.compile(regex.value(), 0); }
                catch (BoundedRegex.Failure failure) {
                    String detail = switch (failure.reason()) {
                        case SOURCE -> "Enter a URL expression containing 1-4096 UTF-8 bytes.";
                        case COMPLEXITY -> "The URL expression is too complex. Simplify it.";
                        case SYNTAX -> "Use supported RE2 syntax for the URL expression"
                                + (failure.syntaxIndex() < 0 ? "." : " at position " + failure.syntaxIndex() + ".");
                    };
                    throw new ConfigurationException("Rule " + (compiled.size() + 1) + ": " + detail);
                }
            }
            compiled.add(new Compiled(rule, pattern));
        }
        return new RequestRuleMatcher(controls, compiled);
    }

    /** @return The immutable source paired with this compiled plan. */
    public RequestSettings.Controls controls() { return controls; }

    /** @param request Untagged outgoing request. @param context Actual host origin. @return Matching enabled rules in saved order. */
    public List<RequestSettings.AutomaticRule> automaticRules(HttpRequest request, Context context) {
        if (!controls.enabled() || context.tool() == null || !controls.tools().contains(context.tool())) return List.of();
        return rules.stream().filter(c -> c.rule().enabled() && portMatches(c.rule(), context) && urlMatches(c, request))
                .map(Compiled::rule).toList();
    }

    /** @param identity Committed credential identity. @param request Fully substituted request. @param context Actual origin. @return Matching recovery policy independent of tool selection. */
    public Optional<JourneyDefinition.Recovery> taggedRecovery(JourneyDefinition.Identity identity, HttpRequest request, Context context) {
        if (!controls.enabled()) return Optional.empty();
        return rules.stream().filter(c -> c.rule().enabled() && c.rule().journey().scope() == identity.scope()
                        && c.rule().journey().id().equals(identity.journeyId()) && portMatches(c.rule(), context) && urlMatches(c, request))
                .map(c -> c.rule().recovery()).findFirst();
    }

    /** @param rule Saved restriction. @param context Actual origin. @return Whether the incoming listener satisfies the restriction. */
    private static boolean portMatches(RequestSettings.AutomaticRule rule, Context context) {
        return rule.proxyPort() == null || context.exchange().family() == AuthTrafficGuard.Family.PROXY
                && context.tool() == RequestSettings.Tool.PROXY && rule.proxyPort().equals(context.incomingPort());
    }

    /** @param compiled Saved condition and optional pattern. @param request Request inspected lazily. @return Exact condition result. */
    private static boolean urlMatches(Compiled compiled, HttpRequest request) {
        return switch (compiled.rule().url()) {
            case RequestSettings.AllRequests ignored -> true;
            case RequestSettings.BurpScope ignored -> request.isInScope();
            case RequestSettings.Prefix prefix -> request.url().startsWith(prefix.value().toString());
            case RequestSettings.Regex ignored -> compiled.pattern().matcher(request.url()).find();
        };
    }
}

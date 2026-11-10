package lab.auth;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.*;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/** Metadata only: loading this catalog never loads production code or starts services. */
public final class ScenarioCatalog {
    public enum Layer { FIXTURE, COMPONENT, RUNNER, PROVIDER_CONTROL, TRANSPORT, HOST, ASSESSMENT }
    public enum Contract { LAB, BASELINE, REVISED, PROVIDER_CONTROL, ASSESSMENT }
    public enum Disposition { NEW, REUSE, EXTEND, BLOCKED, MANUAL, EXCLUDED }
    public record Axis(String name, String value) {}
    public record Assignment(String slot, String value) {}
    public record Fact(String fact, String value) {}
    public record Budget(long startup, long caseMs, long cleanup) {}
    public record Fault(String phase, int occurrence, String kind, String role, Integer status, String checkpoint) {}
    public record Witness(String requirementId, String assertionId, String sourcePath, String sourceSymbol, String inputKey) {}
    public record Binding(String executionId, String executor, String className, String methodSignature,
                          String parameterKey, List<Witness> witnesses, String sourceRevision,
                          Map<String, String> sourceHashes, String taskPath, String configurationHash, String xmlCaseName) {}
    public record Requirement(String id, String group, int revision, Contract contract, Layer layer,
                              List<Axis> axes, List<String> capabilities, List<String> roles, String recipe,
                              List<Assignment> assignments, List<Fact> expected, List<Fault> faults,
                              List<String> evidence, Budget budget, Binding binding, Disposition disposition) {
        public String readiness() {
            if(disposition==Disposition.EXCLUDED)return "EXCLUDED";
            if (layer == Layer.ASSESSMENT) return "UNASSESSED";
            if (layer == Layer.HOST) return "MANUAL";
            return binding == null ? "BLOCKED" : "BOUND_NOT_EXECUTED";
        }
        public String prerequisite() {
            if(disposition==Disposition.EXCLUDED)return "Not executed and earns no product coverage; see the recorded scope/relevance audit.";
            if (layer == Layer.HOST) return "Actual host/artifact checkpoint not performed; manual binding not established.";
            if (layer == Layer.ASSESSMENT) return "Capability has not been assessed; no support is inferred.";
            if (binding != null) return "Binding declared; current execution and evidence still required.";
            if (layer == Layer.FIXTURE) return "Callable fixture execution binding/current result required; :auth-lab:test checks the independent targets.";
            return "P2 fresh predecessor audit and callable binding required; later capabilities remain conditional.";
        }
    }
    public record Selection(List<Requirement> requirements, int uniqueBoundExecutions, int unboundRequirements) {}
    public static final class CatalogException extends IllegalArgumentException {
        CatalogException(String message) { super(message); }
    }

    private static final List<String> DATA_FILES = List.of("fixtures.json", "browser.json", "credentials.json",
            "recovery.json", "registry.json", "federation.json", "transport.json", "http-authentication.json", "burp.json", "assessments.json");
    private static final Set<String> CAPABILITIES = words("FIXTURES PRODUCTION BROWSER NATIVE_TAGS WRAPPERS LIMITS INJECTION MULTI_OUTPUT REPLAY_PAUSE PRESENTATION NATIVE_STORAGE HTTPS CROSS_SITE KEYCLOAK BROKER IDP_COOKIE_PROOF PKCS11 SOFTHSM PHYSICAL_TOKEN BURP_HOST PACKAGED_ARTIFACT");
    private static final Set<String> ROLES = words("B C1 C2 API_TOKEN CLIENT_COOKIE IDP_COOKIE");
    private static final Set<String> FACTS = words("outcome httpStatus account issuance role publication ingressBytes actions attempts replays state stage cause requiredMessageFact forbiddenMessageClaim currentRevision resources redaction capability");
    private static final Set<String> EVIDENCE;
    private static final Set<String> SLOTS = words("account issuance required B C1 C2 method body return selector location mode references tool urlMode enabled tagged trigger requestMode outputs originals dimension point");
    private static final Set<String> REQUIREMENT_FIELDS = words("id group revision contract layer axes capabilities roles recipe assignments expected faults evidence budgetMs binding disposition");
    private static boolean reviewedExclusion(String id,String group,Map<String,String> facts) {
        if(group.equals("FED.saml")||group.equals("FED.negative")&&!id.equals("FED.negative.code-expired"))
            return "outside-extension-scope-provider-validation".equals(facts.get("outcome"));
        return group.equals("BROW.cookie-rules")
                ||Set.of("RUN.recovery.network-three-fail","RUN.recovery.replacement-rejected","RUN.recovery.cancel-cleanup","TLS.trust.unlisted-proxy-key").contains(id);
    }
    private static final List<String> BASELINE = List.of("BROW.basic.json", "BROW.basic.cookie-one", "BROW.basic.two-page",
            "BROW.redirect.cookie-each-hop", "CORE.tag-selection.repeat-one-output", "CORE.injection.bearer", "CORE.injection.cookie",
            "CORE.lifetime.fresh", "CORE.lifetime.exact-expiry", "CORE.registry.missing-secret",
            "CORE.diagnostics.missing-cookie", "CORE.diagnostics.connection-refused");
    private record Spec(String file, Layer layer, List<String> names, LinkedHashMap<String, List<String>> axes) {}
    private static final Map<String, Spec> SPECS = new LinkedHashMap<>();
    static {
        var evidence = new HashSet<>(FACTS);
        evidence.addAll(words("browserLaunch contextClose processOwnership hostCheckpoint completion"));
        EVIDENCE = Set.copyOf(evidence);
        named("FIX.matrix", "fixtures.json", Layer.FIXTURE, "matrix");
        named("FIX.extra", "fixtures.json", Layer.FIXTURE, "unknown expired revoked wrong-kind duplicated-role-value duplicate-authorization duplicate-cookie extra-unrequired empty-value same-account-other-login other-account-complete-set generator-witness");
        named("BROW.basic", "browser.json", Layer.RUNNER, "json cookie-one cookie-two two-page csrf-cookie javascript interstitial invalid-credentials");
        named("BROW.redirect", "browser.json", Layer.RUNNER, "zero one multi cross-origin cookie-each-hop deep-link post-303 post-307");
        named("BROW.redirect-failure", "browser.json", Layer.RUNNER, "missing-callback wrong-return missing-state loop unreachable-hop cancel-before-callback");
        named("BROW.cookie-selection", "browser.json", Layer.RUNNER, "idp-client-decoy early-cookie-rotated same-name-paths same-name-domains deleted-mid-flow ambiguous");
        named("BROW.cookie-rules", "browser.json", Layer.RUNNER, "host-only domain path secure-https secure-http-negative httponly lax-top-navigation strict-cross-site-negative none-secure-cross-site-post none-insecure-negative");
        named("BROW.surfaces", "browser.json", Layer.RUNNER, "early-response late-response nested-json popup frame cors-fetch service-worker");
        named("BROW.fresh", "browser.json", Layer.RUNNER, "cookies local-storage session-storage service-worker");
        named("CORE.outputs", "credentials.json", Layer.COMPONENT, "complete-set token-before-cookie cookie-before-token missing-member one-member-expired late-retired-attempt");
        axes("CORE.tag-matrix", "credentials.json", Layer.COMPONENT, "location:header,path,query,text-body", "mode:raw,url,form,json", "references:1,2,3");
        named("CORE.tag-selection", "credentials.json", Layer.COMPONENT, "repeat-one-output two-outputs three-outputs two-identities three-identities same-account-distinct-journeys alternating-users case-only-alias");
        named("CORE.tag-failure", "credentials.json", Layer.COMPONENT, "unknown deleted ambiguous paused malformed incomplete-selector mixed-valid-invalid output-contains-tag unsupported-body invalid-header-output");
        named("CORE.encoding", "credentials.json", Layer.COMPONENT, "space reserved unicode quote newline nested-wrappers multiple-inner-references literal-prefix unrelated-bytes body-length invalid-target");
        axes("CORE.limits", "credentials.json", Layer.COMPONENT, "dimension:wrapper_depth,reference_count,tagged_request_bytes,json_response_bytes,output_bytes,regex_source_bytes", "point:below,at,above");
        named("CORE.injection", "credentials.json", Layer.COMPONENT, "bearer cookie combined replace-stale preserve-other-cookie duplicate-name tag-precedence disabled url-filter selected-journey-change");
        axes("CORE.tool-policy", "credentials.json", Layer.COMPONENT, "tool:scanner,proxy,repeater,extensions,intruder", "urlMode:burp_scope,all_requests,single_url", "enabled:true,false", "tagged:true,false");
        named("CORE.lifetime", "credentials.json", Layer.COMPONENT, "fresh exact-expiry refresh-skew opaque-age server-revoked usable-during-refresh failed-refresh-usable-old late-old-401");
        axes("CORE.recovery", "recovery.json", Layer.COMPONENT, "trigger:status-match,body-match,no-match,disabled,success,replacement-rejected,acquisition-failed,original-timeout,post-action,replay-once", "requestMode:auto,tagged", "outputs:single,combined", "originals:1,8");
        named("CORE.retry", "recovery.json", Layer.COMPONENT, "second-succeeds third-succeeds three-fail callers-share-budget cancel-backoff deadline-backoff nontransient PIN-rejected PIN-unknown subresource-error");
        named("CORE.resources", "recovery.json", Layer.COMPONENT, "slow-form held-token queue-full waiter-unlimited waiter-finite one-caller-timeout cancel-queued cancel-running unload-backoff late-publication");
        named("CORE.registry", "registry.json", Layer.COMPONENT, "alias-conflict retired-alias explicit-reassignment display-rename case-only-rename missing-secret edit-during-login delete-during-login library-change healthy-unrelated");
        named("CORE.storage", "registry.json", Layer.COMPONENT, "project-roundtrip library-roundtrip export-roundtrip unsupported-load-preserves failed-write-preserves mixed-version rollback");
        named("CORE.diagnostics", "registry.json", Layer.COMPONENT, "connection-refused tls-untrusted navigation-timeout step-target-missing login-rejected missing-cookie ambiguous-cookie missing-response-token invalid-response-format incomplete-output-set protected-use-rejected unresolved-tag unsupported-capability cancelled attempts-exhausted stale-result extraction-only-success success-after-failure");
        named("RUN.recovery", "recovery.json", Layer.RUNNER, "network-third-succeeds network-three-fail replacement-rejected cancel-cleanup");
        named("FED.flow", "federation.json", Layer.RUNNER, "browser-oidc backend-oidc saml-sp");
        named("FED.outputs", "federation.json", Layer.RUNNER, "api-token client-cookie idp-cookie client-cookie-plus-bearer");
        named("FED.negative", "federation.json", Layer.RUNNER, "code-reuse code-expired state-mismatch pkce-mismatch wrong-client wrong-callback id-token-at-api refresh-token-at-api code-at-api wrong-audience");
        named("FED.sso", "federation.json", Layer.RUNNER, "missing-cookie other-account-cookie wrong-service client-logout-idp-live fresh-production-attempt");
        named("FED.saml", "federation.json", Layer.PROVIDER_CONTROL, "relay-state invalid-signature expired replayed wrong-recipient");
        named("FED.broker", "federation.json", Layer.RUNNER, "success upstream-rejected cancelled combined-outputs");
        named("TLS.proxy", "transport.json", Layer.TRANSPORT, "direct http-proxy connect proxy-unavailable no-direct-fallback");
        named("TLS.mtls", "transport.json", Layer.TRANSPORT, "expected-fingerprint same-CN-pair missing-certificate ambiguous-certificate token-unavailable allowed-redirect disallowed-origin resource-without-mtls pool-cleanup internal-proxy-credentials");
        named("TLS.trust", "transport.json", Layer.TRANSPORT, "untrusted-origin wrong-host listed-proxy-key unlisted-proxy-key");
        axes("H01", "burp.json", Layer.HOST, "tool:scanner,proxy,repeater,extensions,intruder", "mode:automatic-combined-injection,native-tags");
        for (String protocol : List.of("basic", "ntlm-v1", "ntlm-v2")) {
            named("HTTP.auth." + protocol, "http-authentication.json", Layer.COMPONENT, "identity direct browser recording");
        }
        named("HTTP.auth.browser-authorization", "http-authentication.json", Layer.RUNNER, "fresh-basic fresh-ntlm-v1 fresh-ntlm-v2 reused-basic reused-ntlm-v1 reused-ntlm-v2");
        named("HTTP.auth.browser-trust", "http-authentication.json", Layer.RUNNER, "scoped");
        named("HTTP.auth.configuration", "http-authentication.json", Layer.COMPONENT, "schema-two secrets invalid schema-one disabled");
        named("HTTP.auth.fidelity", "http-authentication.json", Layer.COMPONENT, "errors no-entity");
        named("HTTP.auth.lifecycle", "http-authentication.json", Layer.COMPONENT, "early-epoch cancel-own retire-setup observation-remap secret-revision");
        named("HTTP.auth.protocol", "http-authentication.json", Layer.COMPONENT, "v1-vector protection-flags variant-requirements malformed no-downgrade");
        named("HTTP.auth.resources", "http-authentication.json", Layer.COMPONENT, "scopes setup-snapshot setup-shutdown admission running-ownership pin-expiry connections response-headers-basic response-headers-ntlm-v1 response-headers-ntlm-v2 body-budget");
        named("HOST.http-auth", "http-authentication.json", Layer.HOST, "basic ntlm-v1 ntlm-v2");
        named("H02", "burp.json", Layer.HOST, "tagged-stop ordinary-unchanged");
        named("H03", "burp.json", Layer.HOST, "successful-replay rejected-replacement-pauses");
        named("H04", "burp.json", Layer.HOST, "intercepted-auth-traffic mtls-through-burp");
        named("H05", "burp.json", Layer.HOST, "save test paused-test repeated-test dirty-editor late-result");
        named("H06", "burp.json", Layer.HOST, "offline-load unload-reload");
        named("CAP.assessment", "assessments.json", Layer.ASSESSMENT, "totp delayed-approval webauthn captcha basic digest kerberos ntlm device-flow client-credentials refresh-grant dpop certificate-bound-token idp-initiated-saml websocket-opening session-loss-redirect");
    }

    private final Map<String, Requirement> requirements;
    private final Map<String, List<String>> profiles;
    private ScenarioCatalog(Map<String, Requirement> requirements, Map<String, List<String>> profiles) {
        this.requirements = Collections.unmodifiableMap(new LinkedHashMap<>(requirements));
        this.profiles = Collections.unmodifiableMap(new LinkedHashMap<>(profiles));
    }
    public Collection<Requirement> requirements() { return requirements.values(); }
    public Map<String, List<String>> profiles() { return profiles; }
    public Requirement requirement(String id) {
        var result = requirements.get(id);
        require(result != null, "Unknown requirement ID.");
        return result;
    }
    public static ScenarioCatalog load() {
        return loadResources(name -> {
            var stream = ScenarioCatalog.class.getResourceAsStream("/catalog/" + name);
            if (stream == null) throw new IOException("Missing catalog resource.");
            return stream;
        });
    }
    public static ScenarioCatalog load(Path directory) {
        return loadResources(name -> Files.newInputStream(directory.resolve(name)));
    }
    @FunctionalInterface private interface Resource { InputStream open(String name) throws IOException; }
    private static ScenarioCatalog loadResources(Resource source) {
        var index = object(read(source, "catalog.json"), words("labCatalogVersion dataFiles profiles"));
        version(index);
        require(strings(index.get("dataFiles")).equals(DATA_FILES), "Catalog must index the exact declared data files in order.");
        var all = new LinkedHashMap<String, Requirement>();
        for (var name : DATA_FILES) {
            var document = object(read(source, name), words("labCatalogVersion requirements"));
            version(document);
            for (var element : array(document.get("requirements"))) {
                var requirement = parseRequirement(element);
                var spec = SPECS.get(requirement.group());
                require(spec != null && spec.file().equals(name), "Requirement group is unknown or in the wrong data file.");
                Layer owningLayer = requirement.group().startsWith("HTTP.auth.") &&
                        (requirement.id().endsWith(".browser") || requirement.id().endsWith(".recording")) ? Layer.RUNNER : spec.layer();
                require(owningLayer == requirement.layer(), "Requirement has an incorrect owning layer.");
                require(all.putIfAbsent(requirement.id(), requirement) == null, "Duplicate requirement ID.");
            }
        }
        require(all.keySet().equals(expectedIds()), "Catalog does not contain every exact declared case: missing, extra or altered ID.");
        var rawProfiles = object(index.get("profiles"), expectedProfiles(all).keySet());
        var profiles = new LinkedHashMap<String, List<String>>();
        for (var entry : expectedProfiles(all).entrySet()) {
            var ids = strings(rawProfiles.get(entry.getKey()));
            require(new HashSet<>(ids).size() == ids.size(), "Duplicate profile member.");
            require(new HashSet<>(ids).equals(entry.getValue()), "Profile membership differs from its declared scope.");
            profiles.put(entry.getKey(), List.copyOf(ids));
        }
        return new ScenarioCatalog(all, profiles);
    }
    public Selection select(Collection<String> names) {
        require(!names.isEmpty(), "Select at least one profile.");
        var selected = new TreeMap<String, Requirement>();
        for (var name : names) {
            var ids = profiles.get(name);
            require(ids != null, "Unknown profile; use the catalog's named profiles.");
            for (var id : ids) selected.put(id, requirements.get(id));
        }
        var executions = new HashSet<String>();
        int unbound = 0;
        for (var r : selected.values()) {
            if(r.disposition()==Disposition.EXCLUDED)continue;
            if (r.binding() == null) unbound++;
            else {
                var binding = r.binding();
                executions.add(binding.executionId() + "\n" + binding.taskPath() + "\n" + binding.configurationHash());
            }
        }
        return new Selection(List.copyOf(selected.values()), executions.size(), unbound);
    }

    private static Requirement parseRequirement(JsonElement element) {
        var o = object(element, REQUIREMENT_FIELDS);
        String id = string(o.get("id")), group = string(o.get("group"));
        var spec = SPECS.get(group);
        require(spec != null, "Unknown requirement group.");
        var axes = new ArrayList<Axis>();
        for (var e : array(o.get("axes"))) {
            var axis = object(e, words("name value"));
            axes.add(new Axis(string(axis.get("name")), string(axis.get("value"))));
        }
        var expectedId = group + ".";
        if (group.equals("FIX.matrix")) {
            var values = axes.stream().collect(Collectors.toMap(Axis::name, Axis::value, (a, b) -> { throw new CatalogException("Duplicate axis."); }, LinkedHashMap::new));
            require(!values.isEmpty() && values.keySet().iterator().next().equals("required"), "Fixture required axis must be first.");
            String required = values.get("required");
            require(List.of("b", "c1", "c2", "b_c1", "b_c2", "c1_c2", "b_c1_c2").contains(required), "Invalid required subset.");
            var keys = new ArrayList<>(List.of("required")); keys.addAll(List.of(required.split("_")));
            require(keys.equals(new ArrayList<>(values.keySet())), "Fixture axes do not match required roles/order.");
            for (int i = 1; i < axes.size(); i++) require(issuances().contains(axes.get(i).value()), "Invalid fixture issuance.");
            expectedId += axes.stream().map(a -> a.name() + "=" + a.value()).collect(Collectors.joining("~"));
        } else if (!spec.axes().isEmpty()) {
            require(axes.size() == spec.axes().size(), "Wrong axis count.");
            int i = 0;
            for (var entry : spec.axes().entrySet()) {
                var axis = axes.get(i++);
                require(entry.getKey().equals(axis.name()) && entry.getValue().contains(axis.value()), "Invalid axis order or value.");
            }
            expectedId += axes.stream().map(a -> a.name() + "=" + a.value()).collect(Collectors.joining("~"));
        } else {
            require(axes.isEmpty(), "Named variants cannot declare axes.");
            require(spec.names().stream().anyMatch(n -> id.equals(group + "." + n)), "Unknown named variant.");
            expectedId = id;
        }
        require(id.equals(expectedId), "ID does not agree with its ordered axes.");
        var capabilities = members(o.get("capabilities"), CAPABILITIES);
        require(!capabilities.isEmpty(), "Requirement must declare its prerequisites.");
        var roles = members(o.get("roles"), ROLES);
        var assignments = new ArrayList<Assignment>();
        var slots = new HashSet<String>();
        for (var e : array(o.get("assignments"))) {
            var a = object(e, words("slot value"));
            String slot = string(a.get("slot"));
            require(SLOTS.contains(slot) && slots.add(slot), "Unknown or duplicate assignment slot.");
            assignments.add(new Assignment(slot, string(a.get("value"))));
        }
        var assigned = assignments.stream().collect(Collectors.toMap(Assignment::slot, Assignment::value));
        for (var axis : axes) if (SLOTS.contains(axis.name()))
            require(axis.value().equals(assigned.get(axis.name())), "Declared axis assignment is missing or inconsistent.");
        for (String role : List.of("B", "C1", "C2")) if (assigned.containsKey(role))
            require(issuances().contains(assigned.get(role)), "Credential assignments must use safe issuance labels, never raw values.");
        var facts = new ArrayList<Fact>();
        var factValues = new HashMap<String, String>();
        var distinctFacts = new HashSet<Fact>();
        for (var e : array(o.get("expected"))) {
            var f = object(e, words("fact value"));
            String fact = string(f.get("fact")), value = string(f.get("value"));
            require(FACTS.contains(fact), "Unknown expected fact.");
            var parsed = new Fact(fact, value);
            require(distinctFacts.add(parsed), "Duplicate expected fact.");
            if (!words("role requiredMessageFact forbiddenMessageClaim").contains(fact))
                require(factValues.putIfAbsent(fact, value) == null, "Contradictory duplicate fact.");
            facts.add(parsed);
        }
        require(!facts.isEmpty(), "Requirement must declare its expected assertion.");
        var requiredMessages = facts.stream().filter(f -> f.fact().equals("requiredMessageFact")).map(Fact::value).collect(Collectors.toSet());
        require(facts.stream().noneMatch(f -> f.fact().equals("forbiddenMessageClaim") && requiredMessages.contains(f.value())), "Message fact is both required and forbidden.");
        var faults = new ArrayList<Fault>();
        for (var e : array(o.get("faults"))) faults.add(parseFault(e));
        var budget = object(o.get("budgetMs"), words("startup case cleanup"));
        var layer = enumeration(o.get("layer"), Layer.class);
        var disposition = enumeration(o.get("disposition"), Disposition.class);
        String recipe = nullableString(o.get("recipe"));
        if (layer != Layer.COMPONENT) require(recipe != null, "Missing flow/checkpoint recipe.");
        if (recipe != null && !spec.names().isEmpty()) require(spec.names().contains(recipe), "Unknown recipe for named variant.");
        if (recipe != null && !spec.names().isEmpty() && !group.equals("FIX.matrix"))
            require(id.equals(group + "." + recipe), "Recipe does not match this named variant.");
        var binding = o.get("binding").isJsonNull() ? null : parseBinding(o.get("binding"), id, layer);
        if(disposition==Disposition.EXCLUDED)require(binding==null&&reviewedExclusion(id,group,factValues),"Excluded scope must be explicit, unbound and covered by the recorded relevance decision.");
        if (disposition == Disposition.REUSE || disposition == Disposition.EXTEND) require(binding != null, "Reuse/extend requires a current binding.");
        if (layer == Layer.HOST || layer == Layer.ASSESSMENT) require(disposition == Disposition.MANUAL, "Host/assessment work must stay manual.");
        var evidence = members(o.get("evidence"), EVIDENCE);
        require(evidence.contains("completion") && facts.stream().allMatch(f -> evidence.contains(f.fact())), "Required assertion evidence is missing.");
        if (group.equals("FIX.matrix")) validateFixtureFacts(axes, assignments, factValues);
        return new Requirement(id, group, positiveInt(o.get("revision")), enumeration(o.get("contract"), Contract.class), layer,
                List.copyOf(axes), capabilities, roles, recipe, List.copyOf(assignments), List.copyOf(facts), List.copyOf(faults),
                evidence, new Budget(positiveLong(budget.get("startup")), positiveLong(budget.get("case")), positiveLong(budget.get("cleanup"))), binding, disposition);
    }
    private static void validateFixtureFacts(List<Axis> axes, List<Assignment> assignments, Map<String, String> expected) {
        var values = axes.subList(1, axes.size()).stream().map(Axis::value).toList();
        boolean accepted = !values.contains("none") && new HashSet<>(values).size() == 1;
        require((accepted ? "200" : "401").equals(expected.get("httpStatus")), "Fixture expectation does not match the declared independent matrix.");
        var assigned = assignments.stream().collect(Collectors.toMap(Assignment::slot, Assignment::value));
        require(axes.getFirst().value().equals(assigned.get("required")), "Missing fixture required assignment.");
        for (var axis : axes.subList(1, axes.size())) require(axis.value().equals(assigned.get(axis.name().toUpperCase(Locale.ROOT))), "Fixture assignment does not match its axis.");
        if (accepted) {
            String issuance = values.getFirst();
            String account = switch (issuance) { case "s0", "s1" -> "user"; case "s2", "s3" -> "user2"; default -> "admin"; };
            require(issuance.equals(expected.get("issuance")) && account.equals(expected.get("account")), "Wrong expected authenticated identity.");
        }
    }
    static Fault parseFault(JsonElement element) {
        var o = object(element, words("phase occurrence kind role status checkpoint"));
        String phase = member(o.get("phase"), words("LOGIN HOP EXTRACTION TOKEN_EXCHANGE PROTECTED"));
        String kind = member(o.get("kind"), words("REJECT CLOSE_BEFORE_RESPONSE HTTP_ERROR HOLD OMIT_OUTPUT ROTATE_OUTPUT OMIT_HOP_COOKIE REDIRECT_LOOP REJECT_REPLACEMENT"));
        int occurrence = positiveInt(o.get("occurrence")); require(occurrence <= 32, "Fault occurrence exceeds 32.");
        String role = nullableString(o.get("role")), checkpoint = nullableString(o.get("checkpoint"));
        if (role != null) require(ROLES.contains(role), "Unknown fault role.");
        Integer status = o.get("status").isJsonNull() ? null : positiveInt(o.get("status"));
        if (kind.equals("HTTP_ERROR")) require(status != null && Set.of(401, 403, 500, 502, 503, 504).contains(status), "Invalid HTTP fault status.");
        else require(status == null, "Status is only valid for HTTP_ERROR.");
        require(kind.equals("HOLD") ? checkpoint != null : checkpoint == null, "Checkpoint must be declared only for HOLD.");
        require(kind.startsWith("OMIT_") || kind.equals("ROTATE_OUTPUT") ? role != null : role == null, "Incompatible fault role.");
        return new Fault(phase, occurrence, kind, role, status, checkpoint);
    }
    private static Binding parseBinding(JsonElement element, String requirementId, Layer layer) {
        var o = object(element, words("executionId executor className methodSignature parameterKey witnesses sourceRevision sourceHashes taskPath configurationHash xmlCaseName"));
        String executor = member(o.get("executor"), words("JUNIT FIXTURE MANUAL"));
        String className = nullableString(o.get("className")), method = nullableString(o.get("methodSignature"));
        String task = nullableString(o.get("taskPath")), xml = nullableString(o.get("xmlCaseName"));
        if (executor.equals("JUNIT")) require(className != null && method != null && task != null && xml != null, "JUnit binding lacks actual owner/report identity.");
        else require(className == null && method == null && task == null && xml == null, "Non-JUnit binding contains JUnit identity.");
        if (executor.equals("FIXTURE")) require(layer == Layer.FIXTURE, "Fixture execution cannot prove production behavior.");
        if (executor.equals("MANUAL")) require(layer == Layer.HOST || layer == Layer.ASSESSMENT, "Manual binding has an automated layer.");
        if (layer == Layer.HOST || layer == Layer.ASSESSMENT) require(executor.equals("MANUAL"), "Host/assessment binding must retain its actual operator owner.");
        var witnesses = new ArrayList<Witness>();
        var ids = new HashSet<String>();
        for (var e : array(o.get("witnesses"))) {
            var w = object(e, words("requirementId assertionId sourcePath sourceSymbol inputKey"));
            String rid = string(w.get("requirementId")), assertion = string(w.get("assertionId")), sourcePath = relativePath(w.get("sourcePath"));
            require(rid.equals(requirementId) && ids.add(assertion), "Witness is foreign or duplicated.");
            witnesses.add(new Witness(rid, assertion, sourcePath, string(w.get("sourceSymbol")), nullableString(w.get("inputKey"))));
        }
        require(!witnesses.isEmpty(), "Binding has no assertion witnesses.");
        require(o.get("sourceHashes").isJsonObject(), "Source hashes must be an object.");
        var hashes = new LinkedHashMap<String, String>();
        for (var entry : o.getAsJsonObject("sourceHashes").entrySet()) {
            relativePath(new JsonPrimitive(entry.getKey())); hashes.put(entry.getKey(), hash(entry.getValue()));
        }
        require(witnesses.stream().allMatch(w -> hashes.containsKey(w.sourcePath())), "Witness source hash is missing.");
        return new Binding(string(o.get("executionId")), executor, className, method, nullableString(o.get("parameterKey")),
                List.copyOf(witnesses), string(o.get("sourceRevision")), Collections.unmodifiableMap(hashes), task, hash(o.get("configurationHash")), xml);
    }

    private static Set<String> expectedIds() {
        var result = new LinkedHashSet<String>();
        for (var entry : SPECS.entrySet()) {
            String group = entry.getKey(); var spec = entry.getValue();
            if (group.equals("FIX.matrix")) {
                for (String required : List.of("b", "c1", "c2", "b_c1", "b_c2", "c1_c2", "b_c1_c2")) {
                    var axes = new LinkedHashMap<String, List<String>>(); axes.put("required", List.of(required));
                    for (String role : required.split("_")) axes.put(role, issuances());
                    expand(group, new ArrayList<>(axes.entrySet()), 0, "", result);
                }
            } else if (spec.axes().isEmpty()) for (String name : spec.names()) result.add(group + "." + name);
            else expand(group, new ArrayList<>(spec.axes().entrySet()), 0, "", result);
        }
        return result;
    }
    private static void expand(String group, List<Map.Entry<String, List<String>>> axes, int position, String prefix, Set<String> into) {
        if (position == axes.size()) { into.add(group + "." + prefix); return; }
        var axis = axes.get(position);
        for (var value : axis.getValue()) expand(group, axes, position + 1, prefix + (prefix.isEmpty() ? "" : "~") + axis.getKey() + "=" + value, into);
    }
    private static Map<String, Set<String>> expectedProfiles(Map<String, Requirement> all) {
        var profiles = new LinkedHashMap<String, Set<String>>();
        profiles.put("fixtures", matching(all, r -> r.group().startsWith("FIX.")));
        profiles.put("baseline", new HashSet<>(BASELINE));
        profiles.put("revised", matching(all, r -> Set.of("CORE.outputs", "CORE.recovery", "CORE.retry", "RUN.recovery").contains(r.group()) || Set.of("CORE.injection.combined", "CORE.diagnostics.incomplete-output-set", "CORE.diagnostics.attempts-exhausted").contains(r.id())));
        profiles.put("credentials", matching(all, r -> Set.of("CORE.outputs", "CORE.tag-matrix", "CORE.tag-selection", "CORE.tag-failure", "CORE.encoding", "CORE.limits", "CORE.injection", "CORE.tool-policy", "CORE.lifetime").contains(r.group())));
        profiles.put("diagnostics", matching(all, r -> r.group().equals("CORE.diagnostics")));
        profiles.put("browser", matching(all, r -> r.group().startsWith("BROW.")));
        profiles.put("federation", matching(all, r -> r.group().startsWith("FED.")));
        profiles.put("recovery", matching(all, r -> Set.of("CORE.recovery", "CORE.retry", "CORE.resources", "RUN.recovery").contains(r.group()) || Set.of("CORE.lifetime.server-revoked", "CORE.lifetime.late-old-401").contains(r.id())));
        profiles.put("http-auth", matching(all, r -> r.group().startsWith("HTTP.auth.")));
        profiles.put("transport", matching(all, r -> r.group().startsWith("TLS.")));
        profiles.put("burp", matching(all, r -> r.layer() == Layer.HOST && !r.group().equals("H06")));
        profiles.put("deployment", matching(all, r -> r.group().equals("H06")));
        profiles.put("all", new HashSet<>(all.keySet()));
        return profiles;
    }
    private static Set<String> matching(Map<String, Requirement> all, java.util.function.Predicate<Requirement> predicate) {
        return all.values().stream().filter(predicate).map(Requirement::id).collect(Collectors.toSet());
    }
    private static void named(String group, String file, Layer layer, String variants) {
        SPECS.put(group, new Spec(file, layer, List.of(variants.split(" ")), new LinkedHashMap<>()));
    }
    private static void axes(String group, String file, Layer layer, String... definitions) {
        var values = new LinkedHashMap<String, List<String>>();
        for (var definition : definitions) { var parts = definition.split(":", 2); values.put(parts[0], List.of(parts[1].split(","))); }
        SPECS.put(group, new Spec(file, layer, List.of(), values));
    }
    private static List<String> issuances() { return List.of("s0", "s1", "s2", "s3", "s4", "s5", "none"); }
    private static Set<String> words(String text) { return Set.of(text.split(" ")); }
    private static void version(JsonObject o) { require(positiveInt(o.get("labCatalogVersion")) == 1, "Unsupported lab catalog version."); }
    private static void require(boolean value, String message) { if (!value) throw new CatalogException(message); }
    private static JsonObject object(JsonElement element, Set<String> fields) {
        require(element != null && element.isJsonObject(), "Expected a JSON object.");
        var result = element.getAsJsonObject(); require(result.keySet().equals(fields), "Unknown or missing JSON field."); return result;
    }
    private static JsonArray array(JsonElement element) { require(element != null && element.isJsonArray(), "Expected an array."); return element.getAsJsonArray(); }
    private static String string(JsonElement element) {
        require(element != null && element.isJsonPrimitive() && element.getAsJsonPrimitive().isString(), "Expected a string.");
        String result = element.getAsString(); require(!result.isBlank(), "Blank strings are not allowed."); return result;
    }
    private static String nullableString(JsonElement e) { return e.isJsonNull() ? null : string(e); }
    private static List<String> strings(JsonElement element) { var result = new ArrayList<String>(); for (var e : array(element)) result.add(string(e)); return List.copyOf(result); }
    private static String member(JsonElement e, Set<String> allowed) { String value = string(e); require(allowed.contains(value), "Unknown enum/domain value."); return value; }
    private static List<String> members(JsonElement e, Set<String> allowed) { var values = strings(e); require(new HashSet<>(values).size() == values.size() && allowed.containsAll(values), "Unknown or duplicate member."); return values; }
    private static <T extends Enum<T>> T enumeration(JsonElement e, Class<T> type) {
        try { return Enum.valueOf(type, string(e)); } catch (IllegalArgumentException ex) { throw new CatalogException("Unknown enum value."); }
    }
    private static long positiveLong(JsonElement e) {
        require(e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isNumber(), "Expected a positive integer.");
        try { long value = new BigDecimal(e.getAsString()).longValueExact(); require(value > 0, "Expected a positive integer."); return value; }
        catch (ArithmeticException | NumberFormatException ex) { throw new CatalogException("Invalid integer."); }
    }
    private static int positiveInt(JsonElement e) { long value = positiveLong(e); require(value <= Integer.MAX_VALUE, "Integer out of range."); return (int) value; }
    private static String hash(JsonElement e) { String value = string(e); require(value.matches("[0-9a-fA-F]{64}"), "Invalid SHA-256."); return value; }
    private static String relativePath(JsonElement e) {
        String path = string(e); require(!path.contains("\\") && !path.contains(":") && !path.startsWith("/") && Arrays.stream(path.split("/")).noneMatch(p -> p.equals("..") || p.isEmpty()), "Source path must be relative and normalized."); return path;
    }
    private static JsonElement read(Resource source, String name) {
        try (var stream = source.open(name)) {
            byte[] bytes = stream.readNBytes(8 * 1024 * 1024 + 1);
            require(bytes.length <= 8 * 1024 * 1024, "Catalog file exceeds 8 MiB.");
            return parseJson(bytes);
        } catch (IOException | IllegalStateException ex) { throw new CatalogException("Invalid or unavailable catalog JSON: " + name); }
    }
    static JsonElement parseJson(byte[] bytes) {
        var decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        try (var reader = new JsonReader(new StringReader(decoder.decode(ByteBuffer.wrap(bytes)).toString()))) {
            reader.setStrictness(Strictness.STRICT);
            var value = readValue(reader, 0);
            require(reader.peek() == JsonToken.END_DOCUMENT, "Trailing JSON content.");
            return value;
        } catch (IOException | IllegalStateException | NumberFormatException ex) { throw new CatalogException("Invalid JSON input."); }
    }
    private static JsonElement readValue(JsonReader reader, int depth) throws IOException {
        require(depth <= 64, "Catalog nesting exceeds 64.");
        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                var object = new JsonObject(); reader.beginObject();
                while (reader.hasNext()) { String name = reader.nextName(); require(!object.has(name), "Duplicate JSON member."); object.add(name, readValue(reader, depth + 1)); }
                reader.endObject(); yield object;
            }
            case BEGIN_ARRAY -> { var array = new JsonArray(); reader.beginArray(); while (reader.hasNext()) array.add(readValue(reader, depth + 1)); reader.endArray(); yield array; }
            case STRING -> new JsonPrimitive(reader.nextString());
            case NUMBER -> new JsonPrimitive(new BigDecimal(reader.nextString()));
            case BOOLEAN -> new JsonPrimitive(reader.nextBoolean());
            case NULL -> { reader.nextNull(); yield JsonNull.INSTANCE; }
            default -> throw new CatalogException("Unexpected JSON token.");
        };
    }
}

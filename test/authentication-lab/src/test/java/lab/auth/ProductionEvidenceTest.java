package lab.auth;

import com.google.gson.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Evidence validation only: these synthetic records claim no product authentication coverage. */
class ProductionEvidenceTest {
    @TempDir Path directory;
    final JsonObject context = JsonParser.parseString("{\"invocationId\":\"current\",\"taskPath\":\":authLabComponentTest\",\"productionRevision\":\"current-source\",\"configurationHash\":\"current-config\"}").getAsJsonObject();
    JsonObject capture(ScenarioCatalog.Requirement row) {
        var axes = new HashMap<String, String>(); row.axes().forEach(a -> axes.put(a.name(), a.value()));
        var facts = new LinkedHashMap<String, Object>();
        var diagnostic = LabProductionEvidence.diagnosticSpec(row);
        if (row.group().equals("BROW.fresh")) {
            facts.putAll(Map.of("sameDefinition", true, "firstAccount", "user2", "secondAccount", "user2", "differentIssuance", true, "differentToken", true,
                    "primeSequence", 1, "firstLoginSequence", 2, "probeSequence", 3, "secondLoginSequence", 4));
            facts.putAll(Map.of("firstContext", 2, "secondContext", 5, "firstClosedBeforeSecond", true, "closedContexts", 2, "openedBrowsers", 2, "closedBrowsers", 2,
                    "drivers", 2, "processes", 8, "alive", 0));
        } else if (row.group().equals("CORE.recovery")) {
            String trigger = axes.get("trigger"); int originals = Integer.parseInt(axes.get("originals"));
            boolean quiet = Set.of("no-match", "disabled", "success", "original-timeout").contains(trigger);
            boolean failed = trigger.equals("acquisition-failed"), rejected = Set.of("replacement-rejected", "replay-once").contains(trigger);
            facts.put("trigger", trigger); facts.put("originals", originals); facts.put("tagged", axes.get("requestMode").equals("tagged")); facts.put("combined", axes.get("outputs").equals("combined"));
            facts.put("recoveryAttempts", quiet ? 0 : failed ? 3 : 1); facts.put("replays", quiet || failed ? 0 : rejected ? 1 : originals);
            facts.put("protectedProofs", quiet || failed || rejected ? 0 : originals); facts.put("actions", trigger.equals("post-action") ? originals : 0);
            facts.put("bytesMatch", true); facts.put("waitingRequests", 0); facts.put("state", failed || rejected ? "PAUSED" : "READY");
        } else if (diagnostic != null) {
            facts.put("nativePhase", diagnostic.phase()); facts.put("nativeCause", diagnostic.nativeCause());
            for (String field : List.of("summaryMatches", "detailsMatch", "stateMatches", "currentRevision", "requiredMessageMatches", "forbiddenClaimAbsent", "redacted")) facts.put(field, true);
            if (LabProductionEvidence.diagnosticSuccess(row)) facts.put("protectedUseVerified", false);
            else { facts.put("requestFeedbackMatches", true); facts.put("noPartialPublication", true); }
            if(row.id().equals("CORE.diagnostics.step-target-missing"))for(String field:List.of("stepAttributionMatches","stepLinkCurrent","stepLinkRetired"))facts.put(field,true);
            if(row.id().equals("CORE.diagnostics.attempts-exhausted")){facts.put("attempts",3);facts.put("state","PAUSED");}
        } else if (row.group().equals("CORE.tag-matrix")) {
            int references = Integer.parseInt(axes.get("references"));
            facts.put("location", axes.get("location")); facts.put("mode", axes.get("mode")); facts.put("references", references); facts.put("plans", references == 1 ? 1 : 2);
            facts.put("bytesMatch", true); facts.put("snapshotVersionsMatch", true); facts.put("cachedBytesMatch", true); facts.put("extraAttemptsOnCacheUse", 0);
            facts.put("attempts", references == 1 ? 1 : references + 1); facts.put("usedSnapshots", references == 1 ? 1 : references + 1); facts.put("waitingRequests", 0);
        } else if (row.id().equals("CORE.encoding.literal-prefix")) {
            facts.putAll(Map.of("wrapperBytesMatch", true, "literalBytesMatch", true, "wrapperAttempts", 0, "outputAttempts", 1, "waitingRequests", 0));
        } else {
            facts.put("tool", axes.get("tool").toUpperCase(Locale.ROOT)); facts.put("urlMode", axes.get("urlMode").toUpperCase(Locale.ROOT));
            facts.put("tagged", Boolean.valueOf(axes.get("tagged"))); facts.put("enabled", Boolean.valueOf(axes.get("enabled")));
            facts.put("policyChecks", 4); facts.put("attempts", Boolean.parseBoolean(axes.get("tagged")) || Boolean.parseBoolean(axes.get("enabled")) ? 1 : 0);
            facts.put("waitingRequests", 0); facts.put("bytesMatch", true); facts.put("continued", true); facts.put("urlHelperCalls", 0);
        }
        var result = contextFor(row); result.addProperty("version", 2); result.addProperty("requirementId", row.id()); result.addProperty("cleanup", "COMPLETE");
        result.add("observed", LabRun.JSON.toJsonTree(facts)); result.add("timings", LabRun.JSON.toJsonTree(Map.of("startupMs", 1, "caseMs", 2, "cleanupMs", 1))); return result;
    }
    ScenarioCatalog.Requirement tagged() { return ScenarioCatalog.load().requirement("CORE.tool-policy.tool=proxy~urlMode=burp_scope~enabled=false~tagged=true"); }
    JsonObject contextFor(ScenarioCatalog.Requirement row) { var value = context.deepCopy(); if (row.group().equals("BROW.fresh")) value.addProperty("taskPath", ":authLabBrowserTest"); return value; }
    @Test void federationEvidenceCannotHideReusedContextsSurvivingProcessesOrExportedBackendTokens() {
        var catalog=ScenarioCatalog.load();var browser=catalog.requirement("FED.outputs.client-cookie-plus-bearer");
        var observed=new JsonObject();
        observed.addProperty("ownerMethod","realBrowserOutputsAuthenticateExpectedAccountsWithFreshIssuances");
        observed.addProperty("caseId",browser.id());observed.addProperty("caseGeneration",1);observed.addProperty("runId",UUID.randomUUID().toString());
        observed.addProperty("runtimeIdentity","a".repeat(64));observed.addProperty("childJvmsClosed",true);
        observed.addProperty("protectedProofs",3);observed.addProperty("freshInteractiveAccounts",2);observed.addProperty("repeatedAccountLogins",1);observed.addProperty("freshAfterVerifier",true);
        var attempts=new JsonArray();
        for(int i=1;i<=3;i++) {
            var attempt=new JsonObject();attempt.addProperty("journeyId",UUID.randomUUID().toString());attempt.addProperty("contextId",i);
            for(String key:List.of("contexts","closedContexts","browsers","closedBrowsers","drivers"))attempt.addProperty(key,1);
            for(String key:List.of("contextIdentityObserved","contextClosed","browserClosed","osProcessClosureObserved"))attempt.addProperty(key,true);
            attempt.addProperty("observedProcesses",3);attempt.addProperty("alive",0);attempts.add(attempt);
        }
        observed.add("attempts",attempts);
        observed.add("verifier",LabRun.JSON.toJsonTree(Map.of("upstream",false,"contexts",4,"drivers",1,"processes",4,"alive",0,
                "missingCookieRejected",true,"otherAccountIdentified",true,"wrongServiceRejected",true,"passwordSubmissions",0)));
        assertTrue(LabProductionEvidence.validFederationCapture(browser,observed));
        assertEquals(browser.expected(),LabProductionEvidence.establishedFacts(browser,observed));
        var reused=observed.deepCopy();reused.getAsJsonArray("attempts").get(1).getAsJsonObject().addProperty("contextId",1);
        assertFalse(LabProductionEvidence.validFederationCapture(browser,reused));
        var alive=observed.deepCopy();alive.getAsJsonArray("attempts").get(0).getAsJsonObject().addProperty("alive",1);
        assertFalse(LabProductionEvidence.validFederationCapture(browser,alive));
        var seeded=observed.deepCopy();seeded.getAsJsonObject("verifier").addProperty("passwordSubmissions",1);
        assertFalse(LabProductionEvidence.validFederationCapture(browser,seeded));
        var foreign=observed.deepCopy();foreign.addProperty("ownerMethod","someOtherPassingTest");
        assertFalse(LabProductionEvidence.validFederationCapture(browser,foreign));

        var backend=catalog.requirement("FED.flow.backend-oidc");var hidden=observed.deepCopy();
        for(String key:List.of("protectedProofs","freshInteractiveAccounts","repeatedAccountLogins","freshAfterVerifier"))hidden.remove(key);
        hidden.addProperty("ownerMethod","realBackendOidcPublishesOnlyACookieAfterItsHiddenTokenReachesTheApi");hidden.addProperty("caseId",backend.id());
        var single=new JsonArray();single.add(attempts.get(0).deepCopy());hidden.add("attempts",single);hidden.add("verifier",JsonNull.INSTANCE);
        hidden.addProperty("backendApiAcceptance",true);hidden.addProperty("clientCookieAccepted",true);hidden.addProperty("hiddenTokenReturned",false);
        assertTrue(LabProductionEvidence.validFederationCapture(backend,hidden));
        hidden.addProperty("hiddenTokenReturned",true);assertFalse(LabProductionEvidence.validFederationCapture(backend,hidden));
        hidden.addProperty("hiddenTokenReturned",false);hidden.addProperty("childJvmsClosed",false);assertFalse(LabProductionEvidence.validFederationCapture(backend,hidden));

        var cancelled=catalog.requirement("FED.broker.cancelled");var forced=hidden.deepCopy();
        for(String key:List.of("backendApiAcceptance","clientCookieAccepted","hiddenTokenReturned"))forced.remove(key);
        forced.addProperty("childJvmsClosed",true);forced.addProperty("caseId",cancelled.id());
        forced.addProperty("ownerMethod","brokeredJourneyCancellationClosesItsBrowserBeforeReturningPartialCredentials");
        for(String key:List.of("actualClientPublicationCheckpointObserved","cancellationReturned","noPartialCredentialReturned","ownedBrowserProcessesClosed"))forced.addProperty(key,true);
        var attempt=forced.getAsJsonArray("attempts").get(0).getAsJsonObject();
        attempt.addProperty("closedContexts",0);attempt.addProperty("closedBrowsers",0);attempt.addProperty("contextClosed",false);attempt.addProperty("browserClosed",false);
        attempt.addProperty("failurePhase","EXTRACTION");attempt.addProperty("failureCause","CANCELLED");
        assertTrue(LabProductionEvidence.validFederationCapture(cancelled,forced),"Cancellation may destroy the owned pipe before graceful close notifications.");
        attempt.addProperty("alive",1);assertFalse(LabProductionEvidence.validFederationCapture(cancelled,forced),"Missing notifications require actual process-tree closure, never an assumed close.");
        attempt.addProperty("alive",0);attempt.addProperty("contextClosed",true);assertFalse(LabProductionEvidence.validFederationCapture(cancelled,forced),"Do not invent an SDK notification.");
    }
    @Test void freshStateRequiresActualPairOrderingAndClosedDistinctContexts() {
        for (var row : ScenarioCatalog.load().requirements()) if (row.group().equals("BROW.fresh")) {
            var capture = capture(row); assertTrue(LabProductionEvidence.validCapture(capture, row, contextFor(row)), row.id());
            assertEquals(new HashSet<>(row.expected()), new HashSet<>(LabProductionEvidence.establishedFacts(row, capture.getAsJsonObject("observed"))), row.id());
        }
    }
    @Test void transportObservationsCannotBorrowAnotherInputOrHideALiveBrowser() throws Exception {
        var c=context.deepCopy();c.addProperty("taskPath",":authLabBrowserTest");
        var process=c.deepCopy();process.addProperty("version",1);process.addProperty("input","TLS.proxy.direct");process.addProperty("cleanup","COMPLETE");
        process.add("observed",LabRun.JSON.toJsonTree(Map.of("drivers",2,"processes",8,"alive",0)));
        process.add("timings",LabRun.JSON.toJsonTree(Map.of("startupMs",0,"caseMs",2,"cleanupMs",1)));
        var facts=c.deepCopy();facts.addProperty("version",1);facts.addProperty("input","TLS.proxy.direct");facts.addProperty("label","direct-route");
        facts.add("observed",LabRun.JSON.toJsonTree(Map.of("primeProxyRequests",3,"directProxyRequests",0,"tokenRequests",2,"expectedOutputsReturned",2,"directHadMarker",false)));
        var spec=LabTransportEvidence.input("TLS.proxy.direct");
        assertTrue(LabTransportEvidence.valid(process,facts,"TLS.proxy.direct",spec,c));
        facts.addProperty("input","TLS.proxy.http-proxy");assertFalse(LabTransportEvidence.valid(process,facts,"TLS.proxy.direct",spec,c));
        facts.addProperty("input","TLS.proxy.direct");process.getAsJsonObject("observed").addProperty("alive",1);
        assertFalse(LabTransportEvidence.valid(process,facts,"TLS.proxy.direct",spec,c));
        process.getAsJsonObject("observed").addProperty("alive",0);facts.addProperty("invocationId","previous");
        assertFalse(LabTransportEvidence.valid(process,facts,"TLS.proxy.direct",spec,c));
        Files.createDirectories(directory.resolve("process-observations"));
        Files.writeString(directory.resolve("process-observations/"+LabEvidence.sha256("TLS.proxy.direct".getBytes(java.nio.charset.StandardCharsets.UTF_8))+".json"),process.toString());
        var onlyCleanup=LabTransportEvidence.read(directory,ScenarioCatalog.load().requirement("TLS.proxy.direct"),c);
        assertNotNull(onlyCleanup,"Observed process closure remains available when the body fails before its semantic capture.");
        assertNull(onlyCleanup.observed(),"Process closure cannot invent a successful authentication observation.");
        var pickerRow=ScenarioCatalog.load().requirement("TLS.mtls.token-unavailable");
        String pickerInput=pickerRow.binding().methodSignature().replaceFirst("\\(\\)$","");
        var pickerContext=context.deepCopy();pickerContext.addProperty("taskPath",":authLabTransportTest");
        var picker=pickerContext.deepCopy();picker.addProperty("version",1);picker.addProperty("input",pickerInput);picker.addProperty("cleanup","COMPLETE");
        picker.add("timings",process.get("timings"));picker.add("observed",LabRun.JSON.toJsonTree(Map.of("drivers",0,"processes",1,"alive",0)));
        Path pickerFile=directory.resolve("process-observations/"+LabEvidence.sha256(pickerInput.getBytes(java.nio.charset.StandardCharsets.UTF_8))+".json");
        Files.writeString(pickerFile,picker.toString());assertNotNull(LabTransportEvidence.read(directory,pickerRow,pickerContext),"PIN-free discovery has an owned helper even though no browser is opened.");
        picker.getAsJsonObject("observed").addProperty("alive",1);Files.writeString(pickerFile,picker.toString());assertNull(LabTransportEvidence.read(directory,pickerRow,pickerContext),"A surviving discovery helper must reject cleanup.");
        picker.getAsJsonObject("observed").addProperty("alive",0);picker.getAsJsonObject("observed").addProperty("processes",0);Files.writeString(pickerFile,picker.toString());assertNull(LabTransportEvidence.read(directory,pickerRow,pickerContext),"Absent helper observation cannot establish discovery cleanup.");
    }
    @Test void unavailableTransportCannotEarnTheExpectedResultFromAnAuthenticationMisclassification() {
        var a=LabRun.JSON.toJsonTree(Map.of("phase","PROXY","cause","PROXY_AUTH","retryable",false,"originRequests",0,"configuredProxyHadCredentials",false)).getAsJsonObject();
        assertTrue(LabTransportEvidence.facts("TLS.proxy.proxy-unavailable",a).isEmpty());
        a.addProperty("cause","TRANSPORT");a.addProperty("retryable",true);
        assertEquals(ScenarioCatalog.load().requirement("TLS.proxy.proxy-unavailable").expected(),LabTransportEvidence.facts("TLS.proxy.proxy-unavailable",a));
        a.addProperty("originRequests",1);assertTrue(LabTransportEvidence.facts("TLS.proxy.proxy-unavailable",a).isEmpty());
    }
    @ParameterizedTest @ValueSource(strings = {"sameDefinition", "firstAccount", "secondAccount", "differentIssuance", "differentToken", "primeSequence", "firstLoginSequence", "probeSequence", "secondLoginSequence", "firstContext", "secondContext", "firstClosedBeforeSecond", "closedContexts", "openedBrowsers", "closedBrowsers", "drivers", "processes", "alive"})
    void missingOrContradictoryFreshWitnessesCannotEstablishAPass(String key) {
        var row = ScenarioCatalog.load().requirement("BROW.fresh.cookies"); var capture = capture(row); var actual = capture.getAsJsonObject("observed");
        if (key.endsWith("Account")) actual.addProperty(key, "admin");
        else if (Set.of("sameDefinition", "differentIssuance", "differentToken", "firstClosedBeforeSecond").contains(key)) actual.addProperty(key, false);
        else actual.addProperty(key, key.equals("alive") ? 1 : 0);
        assertFalse(LabProductionEvidence.validCapture(capture, row, contextFor(row)));
        capture = capture(row); capture.getAsJsonObject("observed").remove(key); assertFalse(LabProductionEvidence.validCapture(capture, row, contextFor(row)));
    }
    @Test void everyRecoveryInputRequiresItsOwnCountsIdentityAndProtectedProofShape() {
        int count = 0;
        for (var row : ScenarioCatalog.load().requirements()) if (row.group().equals("CORE.recovery")) {
            var capture = capture(row); assertTrue(LabProductionEvidence.validCapture(capture, row, context), row.id());
            assertEquals(new HashSet<>(row.expected()), new HashSet<>(LabProductionEvidence.establishedFacts(row, capture.getAsJsonObject("observed"))), row.id()); count++;
        }
        assertEquals(80, count);
    }
    @ParameterizedTest @ValueSource(strings = {"trigger", "tagged", "combined", "originals", "recoveryAttempts", "replays", "protectedProofs", "actions", "bytesMatch", "waitingRequests", "state"})
    void recoveryContradictionsCannotEarnPassingEvidence(String key) {
        var row = ScenarioCatalog.load().requirement("CORE.recovery.trigger=post-action~requestMode=auto~outputs=combined~originals=8");
        var capture = capture(row); var actual = capture.getAsJsonObject("observed");
        switch (key) {
            case "trigger", "state" -> actual.addProperty(key, "OTHER");
            case "tagged" -> actual.addProperty(key, true);
            case "combined", "bytesMatch" -> actual.addProperty(key, false);
            case "waitingRequests", "recoveryAttempts" -> actual.addProperty(key, 4);
            default -> actual.addProperty(key, 0);
        }
        assertFalse(LabProductionEvidence.validCapture(capture, row, context));
        capture = capture(row); capture.getAsJsonObject("observed").remove(key); assertFalse(LabProductionEvidence.validCapture(capture, row, context));
    }
    @Test void inspectedDiagnosticCapturesEstablishOnlyTheirDeclaredFacts() {
        int count = 0;
        for (var row : ScenarioCatalog.load().requirements()) if (LabProductionEvidence.diagnosticSpec(row) != null) {
            var capture = capture(row); assertTrue(LabProductionEvidence.validCapture(capture, row, context), row.id());
            var facts = LabProductionEvidence.establishedFacts(row, capture.getAsJsonObject("observed"));
            assertEquals(new HashSet<>(row.expected()), new HashSet<>(facts), row.id()); count++;
        }
        assertEquals(17, count);
    }
    @Test void aCoherentTimeoutMessageStillRequiresTheActualCurrentStepLink() {
        var row=ScenarioCatalog.load().requirement("CORE.diagnostics.step-target-missing");var capture=capture(row);capture.getAsJsonObject("observed").addProperty("stepAttributionMatches",false);
        assertTrue(LabProductionEvidence.validCapture(capture,row,context));assertFalse(LabProductionEvidence.establishedFacts(row,capture.getAsJsonObject("observed")).containsAll(row.expected()));
    }
    @ParameterizedTest @ValueSource(strings = {"summaryMatches", "detailsMatch", "stateMatches", "currentRevision", "requiredMessageMatches", "forbiddenClaimAbsent", "redacted", "requestFeedbackMatches", "noPartialPublication"})
    void diagnosticContradictionsRemainVisibleWithoutEarningAllRequiredFacts(String field) {
        var row = ScenarioCatalog.load().requirement("CORE.diagnostics.missing-cookie"); var capture = capture(row);
        capture.getAsJsonObject("observed").addProperty(field, false);
        assertTrue(LabProductionEvidence.validCapture(capture, row, context));
        assertFalse(LabProductionEvidence.establishedFacts(row, capture.getAsJsonObject("observed")).containsAll(row.expected()));
    }
    @Test void diagnosticShapesRejectForeignCausesCoercionSecretsAndInventedProtectedProof() {
        var row = ScenarioCatalog.load().requirement("CORE.diagnostics.missing-cookie");
        for (String field : capture(row).getAsJsonObject("observed").keySet()) {
            var capture = capture(row); capture.getAsJsonObject("observed").remove(field); assertFalse(LabProductionEvidence.validCapture(capture, row, context));
        }
        for (String field : List.of("nativePhase", "nativeCause", "requiredMessageMatches", "token")) {
            var capture = capture(row); capture.getAsJsonObject("observed").addProperty(field, "untrusted"); assertFalse(LabProductionEvidence.validCapture(capture, row, context));
        }
        row = ScenarioCatalog.load().requirement("CORE.diagnostics.extraction-only-success"); var capture = capture(row);
        capture.getAsJsonObject("observed").addProperty("protectedUseVerified", true); assertFalse(LabProductionEvidence.validCapture(capture, row, context));
        capture = capture(row); capture.getAsJsonObject("observed").addProperty("requiredMessageMatches", false);
        assertTrue(LabProductionEvidence.validCapture(capture, row, context));
        assertFalse(LabProductionEvidence.establishedFacts(row, capture.getAsJsonObject("observed")).containsAll(row.expected()));
    }
    @Test void allDeclaredToolInputsHaveAnIndependentConsistentCaptureShape() {
        int count = 0;
        for (var row : ScenarioCatalog.load().requirements()) if (row.group().equals("CORE.tool-policy")) { assertTrue(LabProductionEvidence.validCapture(capture(row), row, context), row.id()); count++; }
        assertEquals(60, count);
    }
    @Test void allTagInputsAndTheRetainedLiteralOwnerHaveDistinctCheckedCaptureShapes() {
        int count = 0;
        for (var row : ScenarioCatalog.load().requirements()) if (row.group().equals("CORE.tag-matrix") || row.id().equals("CORE.encoding.literal-prefix")) {
            var actual = capture(row); assertTrue(LabProductionEvidence.validCapture(actual, row, context), row.id());
            assertTrue(row.expected().stream().allMatch(LabProductionEvidence.establishedFacts(row, actual.getAsJsonObject("observed"))::contains), row.id());
            count++;
        }
        assertEquals(49, count);
    }
    @ParameterizedTest @ValueSource(strings = {"location", "mode", "references", "plans", "bytesMatch", "snapshotVersionsMatch", "cachedBytesMatch", "extraAttemptsOnCacheUse", "attempts", "usedSnapshots", "waitingRequests"})
    void tagPublicationAndCachedByteContradictionsCannotPass(String key) {
        var row = ScenarioCatalog.load().requirement("CORE.tag-matrix.location=query~mode=form~references=3");
        var capture = capture(row); var actual = capture.getAsJsonObject("observed");
        if (Set.of("location", "mode").contains(key)) actual.addProperty(key, "OTHER");
        else if (Set.of("bytesMatch", "snapshotVersionsMatch", "cachedBytesMatch").contains(key)) actual.addProperty(key, false);
        else actual.addProperty(key, Set.of("waitingRequests", "extraAttemptsOnCacheUse").contains(key) ? 1 : 0);
        assertFalse(LabProductionEvidence.validCapture(capture, row, context));
    }
    @ParameterizedTest @ValueSource(strings = {"wrapperBytesMatch", "literalBytesMatch", "wrapperAttempts", "outputAttempts", "waitingRequests"})
    void literalOutputAndNoExtraAuthenticationContradictionsCannotPass(String key) {
        var row = ScenarioCatalog.load().requirement("CORE.encoding.literal-prefix");
        var capture = capture(row); var actual = capture.getAsJsonObject("observed");
        if (key.endsWith("BytesMatch")) actual.addProperty(key, false); else actual.addProperty(key, key.equals("outputAttempts") ? 0 : 1);
        assertFalse(LabProductionEvidence.validCapture(capture, row, context));
    }
    @ParameterizedTest @ValueSource(strings = {"invocationId", "taskPath", "productionRevision", "configurationHash", "requirementId", "cleanup"})
    void foreignOrUnfinishedCapturesCannotEstablishAPass(String key) {
        var row = tagged(); var capture = capture(row); capture.addProperty(key, "foreign");
        assertFalse(LabProductionEvidence.validCapture(capture, row, context));
    }
    @ParameterizedTest @ValueSource(strings = {"bytesMatch", "continued", "waitingRequests", "policyChecks", "attempts", "urlHelperCalls", "tool", "urlMode", "tagged", "enabled"})
    void ContradictoryObservedFactsCannotEstablishAPass(String key) {
        var row = tagged(); var capture = capture(row); var facts = capture.getAsJsonObject("observed");
        switch (key) {
            case "bytesMatch", "continued", "tagged" -> facts.addProperty(key, false);
            case "enabled" -> facts.addProperty(key, true);
            case "tool", "urlMode" -> facts.addProperty(key, "OTHER");
            case "policyChecks", "attempts" -> facts.addProperty(key, 0);
            default -> facts.addProperty(key, 1);
        }
        assertFalse(LabProductionEvidence.validCapture(capture, row, context));
    }
    @Test void MissingFactsOldSchemaAndExtraSecretFieldsAreRejected() {
        var row = tagged();
        for (String key : capture(row).getAsJsonObject("observed").keySet()) {
            var capture = capture(row); capture.getAsJsonObject("observed").remove(key); assertFalse(LabProductionEvidence.validCapture(capture, row, context));
        }
        var capture = capture(row); capture.addProperty("version", 1); assertFalse(LabProductionEvidence.validCapture(capture, row, context));
        capture = capture(row); capture.getAsJsonObject("observed").addProperty("token", "must-not-be-published"); assertFalse(LabProductionEvidence.validCapture(capture, row, context));
    }
    @Test void XmlKeepsDuplicateSkippedAndFailedCasesVisibleToTheJoin() throws Exception {
        var xml = directory.resolve("junit-xml"); Files.createDirectories(xml);
        Files.writeString(xml.resolve("TEST-safe.xml"), "<testsuite><testcase classname='Owner' name='[case=safe]'/><testcase classname='Owner' name='[case=safe]'><failure/></testcase><testcase classname='Owner' name='[case=skip]'><skipped/></testcase></testsuite>");
        var cases = LabEvidence.junitCases(directory); assertEquals(3, cases.size());
        assertEquals(List.of("PASS", "FAIL", "BLOCKED"), cases.stream().map(LabEvidence.XmlCase::outcome).toList());
    }
    @Test void XmlDoctypeCannotReadAnExternalFile() throws Exception {
        var xml = directory.resolve("junit-xml"); Files.createDirectories(xml);
        Files.writeString(xml.resolve("TEST-unsafe.xml"), "<!DOCTYPE testsuite SYSTEM 'file:///must-not-read'><testsuite/>");
        assertThrows(org.xml.sax.SAXParseException.class, () -> LabEvidence.junitCases(directory));
    }
}

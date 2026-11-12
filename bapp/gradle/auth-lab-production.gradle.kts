import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.UUID
import java.nio.file.StandardOpenOption

// Capture current production bytes independently of the acceptance overlays.
val labWorkspace = rootProject.projectDir.parentFile
val labPolicyFile = labWorkspace.resolve("test/authentication-lab/src/main/resources/production-policy.json")
val predecessorRoot = providers.gradleProperty("labPredecessor").map { file(it) }.getOrElse(labWorkspace)
@Suppress("UNCHECKED_CAST")
val labPolicy = JsonSlurper().parse(labPolicyFile) as Map<String, Any?>
fun labSha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
fun labFileSha(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input -> val buffer = ByteArray(65536); while (true) { val size = input.read(buffer); if (size < 0) break; digest.update(buffer, 0, size) } }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

val auditedTrees = listOf("bapp/src", "bapp/gradle", "bapp/third-party", "test/authentication-lab/src/main/java",
    "test/authentication-lab/src/test/java", "test/authentication-lab/src/hostGui", "test/authentication-lab/src/hostProbe",
    "test/authentication-lab/production-tests")
val auditedConfiguration = (JsonSlurper().parse(labWorkspace.resolve("test/authentication-lab/src/main/resources/configuration-inputs.json")) as Map<*, *>)["configurationFiles"] as List<*>
val productionFiles = (listOf("bapp/build.gradle.kts", "bapp/gradle.properties", "bapp/settings.gradle.kts", "bapp/gradle.lockfile", "bapp/driver-assets.lock.json", "bapp/gradlew", "bapp/gradlew.bat", "bapp/settings-gradle.lockfile", "docs/designs/bapp-owned-authentication.md", "docs/designs/interface.md", "docs/designs/universal-packaging.md", "docs/designs/burp-host-acceptance-plan.md", "docs/product.md", "test/authentication-lab/Build-HostProbe.ps1") +
    auditedConfiguration.map { it.toString() } +
    auditedTrees.flatMap { subtree ->
        predecessorRoot.resolve(subtree).walkTopDown().filter { it.isFile }.map { it.relativeTo(predecessorRoot).invariantSeparatorsPath }.toList()
    }).distinct().sorted()
val productionHashes = productionFiles.associateWith { labFileSha(predecessorRoot.resolve(it)) }
val labBoundary = labSha(productionHashes.entries.joinToString("\n") { "${it.key}:${it.value}" }.toByteArray(Charsets.UTF_8))
val labAudit = labPolicy + mapOf("files" to productionHashes, "sourceTrees" to auditedTrees, "boundaryHash" to labBoundary,
    "head" to providers.exec { workingDir(predecessorRoot); commandLine("git", "rev-parse", "HEAD") }.standardOutput.asText.get().trim(),
    "productionRoot" to predecessorRoot.canonicalPath, "packaging" to "universal", "workingCopy" to true)
val captureRoot = project(":auth-lab").layout.buildDirectory.dir("captures/${rootProject.extra["authLabInvocationId"]}").get().asFile
val labAuditFile = captureRoot.resolve("production-audit.json")
val productionSnapshot = captureRoot.resolve("production")

fun labOverlayName(file: File) = file.relativeTo(labWorkspace.resolve("test/authentication-lab/production-tests")).invariantSeparatorsPath
fun labOverlayFiles() = labWorkspace.resolve("test/authentication-lab/production-tests").walkTopDown()
    .filter { it.isFile && it.extension == "java" }.sortedBy { labOverlayName(it) }.toList()

val prepareAuthLabProduction = tasks.register("prepareAuthLabProduction") {
    group = "authentication lab"
    description = "Capture and recheck current production sources without changing their working copy."
    doLast {
        @Suppress("UNCHECKED_CAST")
        val expected = labAudit["files"] as Map<String, String>
        val source = predecessorRoot.toPath().toRealPath()
        val bytes = expected.mapValues { (name, hash) ->
            val path = source.resolve(name).normalize()
            check(path.startsWith(source) && Files.isRegularFile(path)) { "Audited predecessor file is missing: $name. Rerun to capture current source." }
            Files.readAllBytes(path).also { check(labSha(it) == hash) { "Audited predecessor changed: $name. Rerun the command to capture the new source." } }
        }
        for (subtree in auditedTrees) {
            val actual = Files.walk(source.resolve(subtree)).use { paths ->
                paths.filter { Files.isRegularFile(it) }.map { source.relativize(it).toString().replace('\\', '/') }.toList().toSet()
            }
            check(actual == expected.keys.filter { it.startsWith("$subtree/") }.toSet()) { "Predecessor inventory changed under $subtree. Rerun to capture current inventory." }
        }
        // Check again before publishing any captured files; execute the retained bytes, not live paths.
        bytes.forEach { (name, captured) -> check(Files.readAllBytes(source.resolve(name)).contentEquals(captured)) { "Predecessor changed during capture." } }
        val destination = productionSnapshot.toPath().toAbsolutePath().normalize()
        bytes.forEach { (name, captured) ->
            val target = destination.resolve(name).normalize()
            check(target.startsWith(destination))
            Files.createDirectories(target.parent)
            if (!Files.exists(target) || !Files.readAllBytes(target).contentEquals(captured)) Files.write(target, captured)
        }
        labAuditFile.parentFile.mkdirs()
        labAuditFile.writeText(JsonOutput.toJson(labAudit), Charsets.UTF_8)
        logger.lifecycle("Captured production: $labBoundary (${bytes.size} unchanged source/configuration files).")
    }
}

listOf("authLabComponentTest", "authLabBrowserTest", "authLabFederationTest", "authLabTransportTest", "authLabExamples", "authLabHostExporter").forEach { taskName ->
    tasks.register<Exec>(taskName) {
        group = "authentication lab"
        description = "Run scoped production checks in the audited isolated predecessor."
        dependsOn(prepareAuthLabProduction, ":auth-lab:jar")
        if(taskName == "authLabFederationTest") dependsOn(":federation-client:prepareFederationRuntime")
        val invocation = rootProject.extra["authLabInvocationId"].toString()
        val taskKey = labSha(":$taskName".toByteArray(Charsets.UTF_8))
        val report = project(":auth-lab").layout.buildDirectory.dir("authlab/$invocation/$taskKey").get().asFile
        isIgnoreExitValue = true
        outputs.upToDateWhen { false }
        doFirst {
            check(!report.resolve("plan.json").exists()) { "Production invocation already has retained evidence." }
            report.mkdirs()
            if (taskName in listOf("authLabBrowserTest", "authLabFederationTest", "authLabTransportTest")) {
                @Suppress("UNCHECKED_CAST")
                val sourceLock = JsonSlurper().parse(predecessorRoot.resolve("bapp/third-party/jcifs-source.lock.json")) as Map<String, Any?>
                val source = predecessorRoot.resolve("bapp/build/third-party/jcifs-ng-source.zip")
                check(source.isFile && labFileSha(source) == sourceLock["sha256"]) { "Prepare the pinned jcifs source before captured browser acceptance." }
                val target = productionSnapshot.resolve("bapp/build/third-party/jcifs-ng-source.zip")
                target.parentFile.mkdirs(); Files.copy(source.toPath(), target.toPath())
            }
            // Running target JVMs must never load a JAR being replaced by another lab build.
            val labClasspath = rootProject.configurations.getByName("authLabRuntime").files.sortedBy { it.name }.map { source ->
                val hash = labFileSha(source)
                val retained = report.resolve("lab-runtime/${source.name}")
                retained.parentFile.mkdirs()
                Files.copy(source.toPath(), retained.toPath())
                check(labFileSha(retained) == hash && labFileSha(source) == hash) { "Lab runtime changed while being captured." }
                retained
            }
            val builtJar = project(":auth-lab").tasks.named<Jar>("jar").get().archiveFile.get().asFile
            val jar = labClasspath.single { it.name == builtJar.name }
            val configurationParts = mutableListOf("authlab-production-config-v1", ":$taskName")
            @Suppress("UNCHECKED_CAST")
            val configurationInputs = (JsonSlurper().parse(labWorkspace.resolve("test/authentication-lab/src/main/resources/configuration-inputs.json")) as Map<String, Any?>)["configurationFiles"] as List<String>
            configurationInputs.forEach { configurationParts.add("$it:${labSha(labWorkspace.resolve(it).readBytes())}") }
            labOverlayFiles().forEach { configurationParts.add("test/authentication-lab/production-tests/${labOverlayName(it)}:${labSha(it.readBytes())}") }
            val federationInputs=linkedMapOf<String,String>()
            val federationInputHashes=linkedMapOf<String,String>()
            if(taskName == "authLabFederationTest") {
                val inputs=listOf("test/federation-client/build.gradle.kts","test/federation-client/gradle.lockfile","test/federation-client/provider-assets.lock.json") +
                        labWorkspace.resolve("test/federation-client/src/main").walkTopDown().filter { it.isFile }.map { it.relativeTo(labWorkspace).invariantSeparatorsPath }.toList()
                inputs.sorted().forEach { name ->
                    val bytes=labWorkspace.resolve(name).readBytes()
                    val retained=report.resolve("federation-inputs/$name");retained.parentFile.mkdirs();retained.writeBytes(bytes)
                    federationInputs[name]=retained.absolutePath;federationInputHashes[name]=labSha(bytes)
                    configurationParts.add("$name:${labSha(bytes)}")
                }
            }
            val plan = linkedMapOf<String, Any?>(
                "version" to 1, "invocationId" to invocation, "taskName" to taskName,
                "burpBrowserExecutable" to providers.gradleProperty("burpBrowserExecutable").orNull?.let { file(it).canonicalPath },
                "boundaryHash" to labBoundary, "productionRevision" to "${labAudit["head"]}+working-copy:$labBoundary",
                "productionRoot" to productionSnapshot.absolutePath, "configurationHash" to labSha(configurationParts.joinToString("\n").toByteArray(Charsets.UTF_8)),
                "auditFile" to labAuditFile.absolutePath, "auditSha256" to labFileSha(labAuditFile), "overlay" to labWorkspace.resolve("test/authentication-lab/production-tests").absolutePath,
                "reportDirectory" to report.absolutePath, "labJar" to jar.absolutePath,
                "labClasspath" to labClasspath.map { it.absolutePath },
                "labArtifactHashes" to labClasspath.associate { it.name to labSha(it.readBytes()) },
                "testDependencies" to rootProject.configurations.getByName("testRuntimeClasspath").resolvedConfiguration.resolvedArtifacts
                    .filter { it.id.componentIdentifier is org.gradle.api.artifacts.component.ModuleComponentIdentifier }
                    .filter { test -> rootProject.configurations.getByName("runtimeClasspath").resolvedConfiguration.resolvedArtifacts.none {
                        it.moduleVersion.id.group == test.moduleVersion.id.group && it.name == test.name
                    } }
                    .map { mapOf("coordinates" to "${it.moduleVersion.id.group}:${it.name}:${it.moduleVersion.id.version}", "sha256" to labFileSha(it.file)) }
                    .sortedBy { it.getValue("coordinates") },
                "overlayHashes" to labOverlayFiles().associate { labOverlayName(it) to labSha(it.readBytes()) },
                "selectionSha256" to labSha(labWorkspace.resolve("test/authentication-lab/src/main/resources/production-selection.json").readBytes()),
                "buildScriptHashes" to listOf("bapp/build.gradle.kts", "bapp/gradle/auth-lab-production.gradle.kts").associateWith { labSha(labWorkspace.resolve(it).readBytes()) },
                "initSha256" to labSha(labWorkspace.resolve("bapp/gradle/auth-lab-production.init.gradle").readBytes()),
                "selectionFile" to labWorkspace.resolve("test/authentication-lab/src/main/resources/production-selection.json").absolutePath,
                "workspace" to labWorkspace.absolutePath
            )
            val transportProfile=rootProject.extra["authLabTransportProfile"]==true
            val requestedTests=providers.gradleProperty("labTests").orNull?:if(transportProfile&&taskName=="authLabBrowserTest")
                "bpsh.browser.BrowserJourneyIntegrationTest.actualUserAgentMarkerCoversRedirectsPopupsFramesFetchWorkersAndWebsocketHandshake" else null
            requestedTests?.let { plan["requestedTests"] = it }
            @Suppress("UNCHECKED_CAST")
            val focusedProfiles = rootProject.extra["authLabFocusedProfiles"] as List<String>
            if (focusedProfiles.isNotEmpty() && taskName in listOf("authLabComponentTest", "authLabBrowserTest")) {
                @Suppress("UNCHECKED_CAST")
                val rows = rootProject.extra["authLabFocusedRows"] as List<Map<String, Any?>>
                @Suppress("UNCHECKED_CAST")
                val methods = rows.mapNotNull { it["binding"] as? Map<String, Any?> }
                    .filter { it["taskPath"] == ":$taskName" }
                    .map { "${it["className"]}.${it["methodSignature"].toString().substringBefore('(')}" }.distinct().sorted()
                check(methods.isNotEmpty()) { "Selected profile has no owner for $taskName." }
                plan["selectedProfiles"] = focusedProfiles
                plan["selectedRequirementIds"] = rows.map { it["id"] }
                plan["selectedMethods"] = methods
            }
            if(taskName=="authLabExamples") {
                check(requestedTests==null) { "Example generation accepts no test filter." }
                plan["liveRunId"]=UUID.fromString(providers.gradleProperty("labRun").orNull?:error("Supply -PlabRun=<live owned run UUID>.")).toString()
                plan["liveRunsRoot"]=project(":auth-lab").layout.buildDirectory.dir("runs").get().asFile.canonicalPath
            }
            if(taskName=="authLabTransportTest") {
                val supplied=providers.gradleProperty("labPkcs11Fixture").orNull?:error("Prepare a fresh disposable software-token fixture and supply -PlabPkcs11Fixture=<fixture.json>.")
                val fixture=file(supplied).canonicalFile
                val owned=fixture.parentFile.canonicalFile
                val prepared=project(":auth-lab").layout.buildDirectory.dir("prepared/pkcs11").get().asFile.canonicalFile
                check(fixture.isFile&&fixture.name=="fixture.json"&&owned.toPath().startsWith(prepared.toPath())) { "Use only a prepared lab software-token store." }
                UUID.fromString(owned.name)
                val data=try{JsonSlurper().parse(fixture) as Map<*,*>}catch(_:Exception){error("Private software-token manifest could not be parsed.")}
                val marker=JsonSlurper().parse(owned.resolve(".fixture-owned.json")) as Map<*,*>
                check(marker["purpose"]=="isolated-bpsh-tests"&&marker["fixtureId"]==data["fixtureId"]&&file(data["root"].toString()).canonicalFile==owned)
                val configuration=owned.resolve("softhsm2.conf")
                check(configuration.readLines()==listOf("directories.tokendir = ${owned.resolve("tokens").invariantSeparatorsPath}","objectstore.backend = file","log.level = ERROR")) { "Software-token configuration must name only this fresh owned store." }
                val module=file(data["module"].toString()).canonicalFile
                check(module.isFile&&module.name.lowercase().contains("softhsm")) { "Only disposable SoftHSM middleware is allowed." }
                val claim=owned.resolve(".authlab-claimed.json")
                Files.writeString(claim.toPath(),JsonOutput.toJson(mapOf("invocationId" to invocation,"task" to taskName)),StandardOpenOption.CREATE_NEW)
                plan["pkcs11Fixture"]=fixture.absolutePath;plan["pkcs11OwnedRoot"]=owned.absolutePath
                plan["pkcs11FixtureSha256"]=labFileSha(fixture);plan["pkcs11ConfigurationSha256"]=labFileSha(configuration)
                plan["pkcs11Module"]=module.absolutePath;plan["pkcs11ModuleSha256"]=labFileSha(module)
                plan["pkcs11InputHashes"]=listOf("fixture.json",".fixture-owned.json","softhsm2.conf","ca.crt","server.key","server.crt","wrong-host.crt").associateWith { labFileSha(owned.resolve(it)) }
            }
            if(taskName == "authLabFederationTest") {
                val prepared=project(":federation-client").layout.buildDirectory.file("p3/runtime/prepared.json").get().asFile
                val identity=(JsonSlurper().parse(prepared) as Map<*,*>)["identity"].toString()
                check(identity.matches(Regex("[a-f0-9]{64}")))
                val manifest=prepared.parentFile.resolve("runtime-$identity.json")
                plan["federationRuntimeManifest"]=manifest.absolutePath
                plan["federationRuntimeManifestSha256"]=labFileSha(manifest)
                plan["federationInputs"]=federationInputs
                plan["federationInputHashes"]=federationInputHashes
            }
            report.resolve("plan.json").writeText(JsonOutput.toJson(plan), Charsets.UTF_8)
            val java = File(System.getProperty("java.home"), "bin/java${if (System.getProperty("os.name").startsWith("Windows")) ".exe" else ""}")
            workingDir(productionSnapshot.resolve("bapp"))
            commandLine(java.absolutePath, "-classpath", productionSnapshot.resolve("bapp/gradle/wrapper/gradle-wrapper.jar").absolutePath,
                "org.gradle.wrapper.GradleWrapperMain", "-p", productionSnapshot.resolve("bapp").absolutePath,
                "-I", labWorkspace.resolve("bapp/gradle/auth-lab-production.init.gradle").absolutePath,
                "-Dauthlab.plan=${report.resolve("plan.json").absolutePath}", taskName, "--offline", "--console=plain")
            requestedTests?.let { args("--tests", it) }
        }
        doLast {
            val code = executionResult.get().exitValue
            if(taskName=="authLabHostExporter") {
                check(code==0&&report.resolve("exporter-runtime.json").isFile) { "Captured native exporter preparation failed. Retain $report" }
                logger.lifecycle("Captured native exporter prepared; no authentication or host acceptance executed.")
                return@doLast
            }
            if(taskName=="authLabExamples") {
                check(code==0&&report.resolve("native-examples-completion.json").isFile) { "Native examples were not prepared. Retained directory: $report" }
                val completion=JsonSlurper().parse(report.resolve("native-examples-completion.json")) as Map<*,*>
                check(completion["authenticationExecuted"]==false&&(completion["files"] as List<*>).isNotEmpty()) { "Invalid native example completion." }
                logger.lifecycle("Native examples: ${report.resolve("native-examples")}. No authentication acceptance is claimed.")
                return@doLast
            }
            if (report.resolve("report-context.json").isFile) {
                @Suppress("UNCHECKED_CAST")
                val context = JsonSlurper().parse(report.resolve("report-context.json")) as MutableMap<String, Any?>
                context["state"] = if (code == 0) "COMPLETED" else "FAILED"
                report.resolve("report-context.json").writeText(JsonOutput.toJson(context), Charsets.UTF_8)
                if (taskName in listOf("authLabComponentTest", "authLabBrowserTest", "authLabFederationTest", "authLabTransportTest")) {
                    val java = File(System.getProperty("java.home"), "bin/java${if (System.getProperty("os.name").startsWith("Windows")) ".exe" else ""}")
                    @Suppress("UNCHECKED_CAST")
                    val retainedPlan = JsonSlurper().parse(report.resolve("plan.json")) as Map<String, Any?>
                    @Suppress("UNCHECKED_CAST")
                    val classpath = (retainedPlan["labClasspath"] as List<String>).joinToString(File.pathSeparator)
                    val collector = ProcessBuilder(java.absolutePath, "-classpath", classpath, "lab.auth.LabMain", "collect-components",
                        "--report-directory", report.absolutePath, "--workspace", labWorkspace.absolutePath)
                        .redirectErrorStream(true).redirectOutput(report.resolve("collection-console.txt")).start()
                    if (!collector.waitFor(30, TimeUnit.SECONDS)) { collector.destroyForcibly(); error("Production report collection did not finish. Retain $report") }
                    check(collector.exitValue() in listOf(0, 3) && report.resolve("report.jsonl").isFile) { "Production report collection failed. Retain $report" }
                    @Suppress("UNCHECKED_CAST")
                    val completion = JsonSlurper().parseText(report.resolve("report.jsonl").readLines().last()) as Map<String, Any?>
                    check(completion["type"] == "RUN_COMPLETED") { "Production result stream has no final completion record. Retain $report" }
                    logger.lifecycle("Bound production CASE_RESULT records: ${report.resolve("report.jsonl")}")
                }
            }
            @Suppress("UNCHECKED_CAST")
            val focusedProfiles = rootProject.extra["authLabFocusedProfiles"] as List<String>
            check((code == 0 || (rootProject.extra["authLabTransportProfile"]==true&&taskName in listOf("authLabBrowserTest","authLabTransportTest")) ||
                (focusedProfiles.isNotEmpty() && taskName in listOf("authLabComponentTest", "authLabBrowserTest"))) && report.resolve("junit-summary.json").isFile) { "Production checks failed or did not complete. Retained evidence: $report" }
            if(code!=0)logger.lifecycle("Scoped production failures retained for the selected-profile aggregate: $report")
            logger.lifecycle("Scoped production checks ${if(code==0) "completed" else "failed"}. Evidence: $report")
            logger.lifecycle("Catalog requirements without complete current witnesses remain BLOCKED; this is not full profile acceptance.")
        }
    }
}

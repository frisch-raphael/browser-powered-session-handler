import java.util.UUID
import groovy.json.JsonSlurper
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

extra["authLabInvocationId"] = UUID.randomUUID().toString()
val focusedProfileNames = setOf("baseline", "revised", "credentials", "diagnostics", "browser", "recovery")
val requestedLabProfiles = providers.gradleProperty("labProfiles").getOrElse("baseline").split(",").toSet()
val focusedProfiles = if (gradle.startParameter.taskNames.any { it.substringAfterLast(':') == "authLab" } &&
    requestedLabProfiles.isNotEmpty() && focusedProfileNames.containsAll(requestedLabProfiles)) requestedLabProfiles.toList() else emptyList()
extra["authLabFocusedProfiles"] = focusedProfiles
@Suppress("UNCHECKED_CAST")
val focusedRows: List<Map<String, Any?>> = if (focusedProfiles.isEmpty()) emptyList() else {
    val catalogRoot = projectDir.parentFile.resolve("test/authentication-lab/src/main/resources/catalog")
    val catalog = JsonSlurper().parse(catalogRoot.resolve("catalog.json")) as Map<String, Any?>
    val profileIds = catalog["profiles"] as Map<String, List<String>>
    val ids = focusedProfiles.flatMap { profileIds.getValue(it) }.toSet()
    (catalog["dataFiles"] as List<String>).flatMap { name ->
        (JsonSlurper().parse(catalogRoot.resolve(name)) as Map<String, Any?>)["requirements"] as List<Map<String, Any?>>
    }.filter { it["id"] in ids }.also { check(it.size == ids.size) { "Incomplete selected-profile catalog." } }
}
extra["authLabFocusedRows"] = focusedRows
extra["authLabTransportProfile"] = gradle.startParameter.taskNames.any { it.substringAfterLast(':') == "authLab" } &&
        providers.gradleProperty("labProfiles").orNull == "transport"

// This configuration never enters the extension's runtimeClasspath or release JAR.
val authLabRuntime by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}
dependencies {
    authLabRuntime(project(":auth-lab"))
}

mapOf(
    "authLabMatrix" to "matrix",
    "authLabDoctor" to "doctor",
    "authLabUnavailable" to "run",
    "authLabServe" to "serve",
    "authLabReset" to "reset",
    "authLabStop" to "stop",
    "authLabPrepareCase" to "prepare-case"
).forEach { (taskName, command) ->
    tasks.register<JavaExec>(taskName) {
        group = "authentication lab"
        description = "Authentication lab: $command. Production execution requires audited bindings."
        classpath = authLabRuntime
        mainClass.set("lab.auth.LabMain")
        args(command, "--profiles", providers.gradleProperty("labProfiles").getOrElse("baseline"))
        systemProperty("lab.environmentRoot", project(":auth-lab").layout.buildDirectory.dir("runs").get().asFile.absolutePath)
        systemProperty("lab.workspaceRoot", projectDir.parentFile.absolutePath)
        providers.gradleProperty("labRun").orNull?.let { args("--run", it) }
        providers.gradleProperty("labCase").orNull?.let { args("--case", it) }
        providers.gradleProperty("labPkcs11Fixture").orNull?.let { systemProperty("lab.pkcs11Fixture",file(it).absolutePath) }
        if(taskName=="authLabServe") {
            if(providers.gradleProperty("labProfiles").getOrElse("baseline")=="federation")dependsOn(":federation-client:prepareFederationRuntime")
            doFirst {
                val invocation=rootProject.extra["authLabInvocationId"].toString()
                systemProperty("lab.invocationId",invocation)
                val retainedRoot=project(":auth-lab").layout.buildDirectory.dir("serve-runtime/$invocation").get().asFile
                check(!retainedRoot.exists()) { "Serve invocation runtime already exists." };retainedRoot.mkdirs()
                fun hash(file:File)=MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
                classpath=files(authLabRuntime.files.sortedBy { it.name }.map { source ->
                    check(source.isFile);val expected=hash(source);val retained=retainedRoot.resolve(source.name);source.copyTo(retained)
                    check(hash(retained)==expected&&hash(source)==expected) { "Serve runtime changed during capture." };retained
                })
                if(providers.gradleProperty("labProfiles").getOrElse("baseline")=="federation") {
                    val runtime=project(":federation-client").layout.buildDirectory.dir("p3/runtime").get().asFile
                    val identity=(JsonSlurper().parse(runtime.resolve("prepared.json")) as Map<*,*>)["identity"].toString()
                    check(identity.matches(Regex("[a-f0-9]{64}")))
                    systemProperty("lab.federationRuntimeManifest",runtime.resolve("runtime-$identity.json").absolutePath)
                }
            }
        }
        // Explicit lab tasks must never reuse a cached execution as evidence.
        outputs.upToDateWhen { false }
    }
}

tasks.register("authLab") {
    group = "authentication lab"
    description = "Execute audited profile owners and require complete selected-profile evidence."
    val profiles = providers.gradleProperty("labProfiles").getOrElse("baseline").split(",").toSet()
    if (profiles == setOf("fixtures")) dependsOn(":auth-lab:test")
    else if (profiles == setOf("federation")) {
        dependsOn("authLabFederationTest")
        doLast {
            val invocation = rootProject.extra["authLabInvocationId"].toString()
            val key = MessageDigest.getInstance("SHA-256").digest(":authLabFederationTest".toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
            val report = project(":auth-lab").layout.buildDirectory.file("authlab/$invocation/$key/report.jsonl").get().asFile
            val terminal = JsonSlurper().parseText(report.readLines().last()) as Map<*, *>
            val completion = terminal["data"] as Map<*, *>
            val outcomes = completion["outcomes"] as Map<*, *>
            check(terminal["type"] == "RUN_COMPLETED" && completion["complete"] == true && completion["cleanupOutcome"] == "COMPLETE" &&
                    (outcomes["PASS"] as Number).toInt() == 17 && (outcomes["EXCLUDED"] as Number).toInt() == 14 &&
                    listOf("FAIL", "BLOCKED", "NOT_RUN", "INTERRUPTED").all { (outcomes[it] as Number).toInt() == 0 }) {
                "Federation profile is incomplete. Retained evidence: $report"
            }
            logger.lifecycle("Federation profile: 17 requirements proven by 7 shared native owners; 14 provider-validation entries excluded. Evidence: $report")
        }
    }
    else if(profiles==setOf("transport")) {
        check(!providers.gradleProperty("labTests").isPresent) { "The transport profile requires its complete owner set; use an explicit scoped task for -PlabTests." }
        dependsOn("authLabBrowserTest","authLabTransportTest")
        doLast {
            val invocation=rootProject.extra["authLabInvocationId"].toString()
            val directory=project(":auth-lab").layout.buildDirectory.dir("authlab/$invocation").get().asFile
            val key=MessageDigest.getInstance("SHA-256").digest(":authLabTransportTest".toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
            val plan=JsonSlurper().parse(directory.resolve("$key/plan.json")) as Map<*,*>
            val classpath=(plan["labClasspath"] as List<*>).joinToString(File.pathSeparator)
            val java=File(System.getProperty("java.home"),"bin/java${if(System.getProperty("os.name").startsWith("Windows")) ".exe" else ""}")
            val collector=ProcessBuilder(java.absolutePath,"-classpath",classpath,"lab.auth.LabMain","collect-transport-profile",
                "--report-directory",directory.absolutePath,"--workspace",projectDir.parentFile.absolutePath)
                .redirectErrorStream(true).redirectOutput(directory.resolve("transport-collection-console.txt")).start()
            if(!collector.waitFor(30,TimeUnit.SECONDS)){collector.destroyForcibly();error("Transport profile collection timed out. Retain $directory")}
            check(collector.exitValue()==0) { "Transport profile failed or is incomplete. Evidence: ${directory.resolve("report-transport.jsonl")}" }
            logger.lifecycle("Transport profile: 18 active requirements proven by 12 shared native cases; one Chromium-only case excluded. Evidence: ${directory.resolve("report-transport.jsonl")}")
        }
    } else if (focusedProfiles.isNotEmpty()) {
        check(!providers.gradleProperty("labTests").isPresent) { "A selected profile requires all its owners; use explicit scoped tasks for -PlabTests." }
        @Suppress("UNCHECKED_CAST")
        val ownerTasks = focusedRows.mapNotNull { (it["binding"] as? Map<String, Any?>)?.get("taskPath") as? String }.distinct()
        check(ownerTasks.isNotEmpty() && ownerTasks.all { it in listOf(":authLabComponentTest", ":authLabBrowserTest") })
        dependsOn(ownerTasks)
        doLast {
            val invocation = rootProject.extra["authLabInvocationId"].toString()
            val directory = project(":auth-lab").layout.buildDirectory.dir("authlab/$invocation").get().asFile
            val key = MessageDigest.getInstance("SHA-256").digest(ownerTasks.first().toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
            val plan = JsonSlurper().parse(directory.resolve("$key/plan.json")) as Map<*, *>
            val classpath = (plan["labClasspath"] as List<*>).joinToString(File.pathSeparator)
            val java = File(System.getProperty("java.home"), "bin/java${if (System.getProperty("os.name").startsWith("Windows")) ".exe" else ""}")
            val collector = ProcessBuilder(java.absolutePath, "-classpath", classpath, "lab.auth.LabMain", "collect-profiles",
                "--profiles", focusedProfiles.joinToString(","), "--report-directory", directory.absolutePath, "--workspace", projectDir.parentFile.absolutePath)
                .redirectErrorStream(true).redirectOutput(directory.resolve("profile-collection-console.txt")).start()
            if (!collector.waitFor(30, TimeUnit.SECONDS)) { collector.destroyForcibly(); error("Selected-profile collection timed out. Retain $directory") }
            check(collector.exitValue() == 0) { "Selected profiles failed or are incomplete. Evidence: ${directory.resolve("report-profiles.jsonl")}" }
            logger.lifecycle("Selected profiles completed: ${focusedProfiles.joinToString(",")}. Evidence: ${directory.resolve("report-profiles.jsonl")}")
        }
    } else dependsOn("authLabUnavailable")
}

apply(from = "gradle/auth-lab-production.gradle.kts")

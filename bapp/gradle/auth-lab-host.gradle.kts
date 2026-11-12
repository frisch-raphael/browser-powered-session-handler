import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.security.MessageDigest

// Explicit host verification only. No task here is a dependency of ordinary check.
val hostWorkspace = rootProject.projectDir.parentFile
val hostInvocation = rootProject.extra["authLabInvocationId"].toString()
fun hostHash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
fun hostFileHash(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { stream ->
        val buffer = ByteArray(65536)
        while (true) { val size = stream.read(buffer); if (size < 0) break; digest.update(buffer, 0, size) }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

listOf("authLabHostTest", "authLabHostQualify").forEach { taskName ->
    tasks.register<JavaExec>(taskName) {
        group = "authentication lab"
        description = if (taskName == "authLabHostTest") "Verify the exact development JAR unattended in both Burp VMs." else "Qualify VM GUI primitives/scenarios without claiming catalog acceptance."
        dependsOn("check", "verifyNativeDocumentation", "jar", "authLabHostExporter", ":auth-lab:test", ":auth-lab:hostProbeJar")
        mainClass.set("lab.auth.LabMain")
        outputs.upToDateWhen { false }
        doFirst {
            val acceptance = taskName == "authLabHostTest"
            check(!acceptance || !providers.gradleProperty("hostPlatform").isPresent && !providers.gradleProperty("hostStage").isPresent) {
                "Acceptance runs both complete platforms; use authLabHostQualify for scoped diagnostics."
            }
            val platform = providers.gradleProperty("hostPlatform").getOrElse("both")
            val stage = providers.gradleProperty("hostStage").getOrElse("scenarios")
            check(platform in listOf("both", "windows", "linux") && stage in listOf("primitives", "scenarios")) { "Unknown host platform/stage." }
            val supplied = providers.gradleProperty("hostVmConfig").orNull ?: error("Supply -PhostVmConfig=<repository-relative or absolute local JSON path>.")
            val config = File(supplied).let { if (it.isAbsolute) it else hostWorkspace.resolve(supplied) }.canonicalFile
            check(config.isFile) { "Create the ignored local host VM configuration during provisioning." }
            val runtimeRoot = project(":auth-lab").layout.buildDirectory.dir("host-runtime/$hostInvocation").get().asFile
            val capture = runtimeRoot.resolve("capture")
            check(!capture.exists()) { "Host invocation capture already exists." }; capture.mkdirs()
            fun retain(source: File, role: String? = null): Map<String, Any> {
                check(source.isFile) { "Missing prepared host artifact." }
                val before = hostFileHash(source)
                val destination = capture.resolve(before + if (source.extension == "jar") ".jar" else ".json")
                if (!destination.exists()) source.copyTo(destination)
                check(hostFileHash(source) == before && hostFileHash(destination) == before) { "Host artifact changed during capture." }
                val fields = linkedMapOf<String, Any>("path" to destination.absolutePath, "sha256" to before, "bytes" to destination.length())
                role?.let { fields["role"] = it }; return fields
            }
            val auditFile = project(":auth-lab").layout.buildDirectory.file("captures/$hostInvocation/production-audit.json").get().asFile
            val audit = JsonSlurper().parse(auditFile) as Map<*, *>
            (audit["files"] as Map<*, *>).forEach { (path, hash) ->
                check(hostFileHash(hostWorkspace.resolve(path.toString())) == hash) { "Product sources changed after capture; start a new host invocation." }
            }
            val exporterKey = hostHash(":authLabHostExporter".toByteArray(Charsets.UTF_8))
            val exporter = JsonSlurper().parse(project(":auth-lab").layout.buildDirectory.file("authlab/$hostInvocation/$exporterKey/exporter-runtime.json").get().asFile) as Map<*, *>
            check(exporter["invocationId"] == hostInvocation && exporter["sourceRevision"] == audit["boundaryHash"]) { "Foreign captured exporter runtime." }
            val runtime = configurations.getByName("authLabRuntime").files.sortedBy { it.name }.map { retain(it, "LAB") }.toMutableList()
            (exporter["runtime"] as List<*>).forEach { value ->
                val artifact = value as Map<*, *>
                val source = File(artifact["path"].toString())
                check(hostFileHash(source) == artifact["sha256"] && source.length() == (artifact["bytes"] as Number).toLong()) { "Captured exporter changed." }
                runtime.add(retain(source, "EXPORTER"))
            }
            val configInputs = (JsonSlurper().parse(hostWorkspace.resolve("test/authentication-lab/src/main/resources/configuration-inputs.json")) as Map<*, *>)["configurationFiles"] as List<*>
            val parts = mutableListOf("authlab-production-config-v1", ":$taskName")
            configInputs.forEach { value -> val path = value.toString(); parts.add("$path:${hostFileHash(hostWorkspace.resolve(path))}") }
            hostWorkspace.resolve("test/authentication-lab/production-tests").walkTopDown().filter { it.isFile && it.extension == "java" }
                .sortedBy { it.relativeTo(hostWorkspace).invariantSeparatorsPath }.forEach { parts.add("${it.relativeTo(hostWorkspace).invariantSeparatorsPath}:${hostFileHash(it)}") }
            val reportKey = hostHash(":$taskName".toByteArray(Charsets.UTF_8))
            val report = project(":auth-lab").layout.buildDirectory.dir("authlab/$hostInvocation/$reportKey").get().asFile
            check(!report.exists()) { "Host report already exists." }; report.mkdirs()
            val catalogHash = hostHash(hostWorkspace.resolve("test/authentication-lab/src/main/resources/catalog").listFiles()!!.filter { it.extension == "json" }
                .sortedBy { it.name }.joinToString("\n") { "${it.name}:${hostFileHash(it)}" }.toByteArray(Charsets.UTF_8))
            val product = tasks.named<Jar>("jar").get().archiveFile.get().asFile
            check(product.canonicalFile == hostWorkspace.resolve("bapp/build/libs/browser-powered-session-handler-dev.jar").canonicalFile)
            val plan = mapOf("version" to 1, "invocationId" to hostInvocation, "mode" to if (acceptance) "ACCEPTANCE" else "QUALIFICATION",
                "platforms" to if (platform == "both") listOf("windows", "linux") else listOf(platform), "taskPath" to ":$taskName",
                "configurationHash" to hostHash(parts.joinToString("\n").toByteArray(Charsets.UTF_8)), "catalogRevision" to catalogHash,
                "sourceRevision" to audit["boundaryHash"], "head" to audit["head"], "sourceHashes" to audit["files"],
                "audit" to retain(auditFile), "product" to retain(product),
                "helper" to retain(project(":auth-lab").layout.buildDirectory.file("host-probe/authentication-lab-host-probe.jar").get().asFile),
                "runtime" to runtime, "scenarios" to retain(hostWorkspace.resolve("test/authentication-lab/src/main/resources/host-scenarios.json")),
                "captureDirectory" to capture.absolutePath)
            val planFile = runtimeRoot.resolve("plan.json"); planFile.writeText(JsonOutput.toJson(plan), Charsets.UTF_8)
            (audit["files"] as Map<*, *>).forEach { (path, hash) ->
                check(hostFileHash(hostWorkspace.resolve(path.toString())) == hash) { "Product sources changed during host capture; start a new invocation." }
            }
            classpath = files(runtime.filter { it["role"] == "LAB" }.map { it.getValue("path") })
            args(if (acceptance) "host-test" else "host-qualify", "--workspace", hostWorkspace.absolutePath, "--report-directory", report.absolutePath,
                "--artifact", product.absolutePath, "--vm-config", config.absolutePath, "--plan", planFile.absolutePath)
            if (!acceptance) args("--platform", platform, "--stage", stage)
        }
    }
}

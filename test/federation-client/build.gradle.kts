import java.security.MessageDigest
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.Base64

plugins {
    java
    application
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://build.shibboleth.net/maven/releases/")
        content {
            includeGroupByRegex("org\\.opensaml.*")
            includeGroupByRegex("net\\.shibboleth.*")
        }
    }
}

java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.encoding = "UTF-8"
}

dependencyLocking { lockAllConfigurations() }
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.2"))
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-security-saml2")
    testImplementation(enforcedPlatform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(project(":auth-lab")) { isTransitive = false }
    testImplementation("com.google.code.gson:gson:2.13.2")
}

application { mainClass.set("lab.federation.FederationApplication") }

val adapterResources = layout.buildDirectory.dir("generated/federation-adapter")
sourceSets.main.get().resources.srcDir(adapterResources)
val prepareFederationBrowserAdapter = tasks.register("prepareFederationBrowserAdapter") {
    group = "authentication lab"
    description = "Explicitly prepare the pinned official adapter; ordinary tests never download it."
    doLast {
        @Suppress("UNCHECKED_CAST")
        val lock = (groovy.json.JsonSlurper().parse(file("provider-assets.lock.json")) as Map<String, Any?>)["browserAdapter"] as Map<String, Any?>
        val prepared = layout.buildDirectory.dir("p3/preparation").get().asFile.apply { mkdirs() }
        val archive = prepared.resolve("keycloak-js-${lock["version"]}.tgz")
        fun hash(algorithm: String, bytes: ByteArray) = MessageDigest.getInstance(algorithm).digest(bytes)
        fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
        if (!archive.isFile) {
            check(!gradle.startParameter.isOffline) { "The pinned adapter archive is not prepared; invoke this explicit preparation task online first." }
            val uri = URI(lock["url"].toString())
            check(uri.scheme == "https" && uri.host == "registry.npmjs.org" && uri.rawQuery == null && uri.rawUserInfo == null)
            val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build()
            val response = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).GET().build(), HttpResponse.BodyHandlers.ofInputStream())
            val bytes = response.body().use { it.readNBytes((lock["bytes"] as Number).toInt() + 1) }
            check(response.statusCode() == 200 && bytes.size == (lock["bytes"] as Number).toInt()) { "Adapter archive response does not match the prepared size." }
            check(hex(hash("SHA-256", bytes)) == lock["sha256"] && "sha512-" + Base64.getEncoder().encodeToString(hash("SHA-512", bytes)) == lock["integrity"]) { "Adapter archive integrity differs." }
            archive.writeBytes(bytes)
        }
        val bytes = archive.inputStream().use { it.readNBytes((lock["bytes"] as Number).toInt() + 1) }
        check(bytes.size == (lock["bytes"] as Number).toInt() && hex(hash("SHA-256", bytes)) == lock["sha256"]
                && "sha512-" + Base64.getEncoder().encodeToString(hash("SHA-512", bytes)) == lock["integrity"]) { "Prepared adapter archive integrity differs." }
        var module: ByteArray? = null
        tarTree(resources.gzip(archive)).visit {
            val name = relativePath.pathString
            check(!name.startsWith("/") && !name.contains('\\') && !name.contains(':') && relativePath.segments.none { it == ".." || it == "." }) { "Unsafe adapter archive path." }
            if (!isDirectory && name == lock["archiveEntry"]) {
                check(module == null) { "Duplicate adapter module entry." }
                module = open().use { it.readNBytes((lock["moduleBytes"] as Number).toInt() + 1) }
            }
        }
        val source = requireNotNull(module) { "Declared adapter module entry absent." }
        check(source.size == (lock["moduleBytes"] as Number).toInt() && hex(hash("SHA-256", source)) == lock["moduleSha256"]) { "Adapter module identity differs." }
        val output = adapterResources.get().file("static/vendor/keycloak.js").asFile
        output.parentFile.mkdirs(); output.writeBytes(source)
        @Suppress("UNCHECKED_CAST")
        val imports = lock["imports"] as List<Map<String, Any?>>
        imports.forEach { entry ->
            val name=entry["file"].toString()
            check(name.matches(Regex("[A-Za-z0-9_-]+\\.js")) && entry["archiveEntry"] == "package/lib/$name")
            var imported: ByteArray? = null
            tarTree(resources.gzip(archive)).visit {
                if(!isDirectory && relativePath.pathString == entry["archiveEntry"]) {
                    check(imported == null) { "Duplicate imported adapter module." }
                    imported=open().use { it.readNBytes((entry["bytes"] as Number).toInt()+1) }
                }
            }
            val body=requireNotNull(imported) { "Imported adapter module absent." }
            check(body.size == (entry["bytes"] as Number).toInt() && hex(hash("SHA-256",body)) == entry["sha256"]) { "Imported adapter module identity differs." }
            output.parentFile.resolve(name).writeBytes(body)
        }
        logger.lifecycle("Prepared official keycloak-js ${lock["version"]}: archive integrity and complete declared ESM imports verified.")
    }
}
tasks.named<ProcessResources>("processResources") {
    mustRunAfter(prepareFederationBrowserAdapter)
    from("provider-assets.lock.json") { into("provider"); rename { "provider-lock.json" } }
}
tasks.test {
    useJUnitPlatform { excludeTags("federation-infrastructure") }
    failOnNoDiscoveredTests.set(true)
    testLogging { events("failed", "skipped") }
    systemProperty("federation.childClasspath", sourceSets.main.get().runtimeClasspath.asPath)
}
// Child JVMs consume copies: rebuilding source JARs must not change a running service.
val federationRuntimeManifest = layout.buildDirectory.file("p3/runtime/prepared.json")
val prepareFederationRuntime = tasks.register("prepareFederationRuntime") {
    group = "authentication lab"
    description = "Freeze verified local federation JVM artifacts for owned child processes."
    dependsOn(tasks.jar)
    doLast {
        @Suppress("UNCHECKED_CAST")
        val adapter = (groovy.json.JsonSlurper().parse(file("provider-assets.lock.json")) as Map<String, Any?>)["browserAdapter"] as Map<String, Any?>
        val module = adapterResources.get().file("static/vendor/keycloak.js").asFile
        check(module.isFile && module.length() == (adapter["moduleBytes"] as Number).toLong()
                && MessageDigest.getInstance("SHA-256").digest(module.readBytes()).joinToString("") { "%02x".format(it) } == adapter["moduleSha256"]) {
            "Prepare the pinned browser adapter explicitly before preparing federation services."
        }
        @Suppress("UNCHECKED_CAST")
        val imports=adapter["imports"] as List<Map<String,Any?>>
        imports.forEach { entry ->
            val imported=module.parentFile.resolve(entry["file"].toString())
            check(imported.isFile && imported.length() == (entry["bytes"] as Number).toLong()
                    && MessageDigest.getInstance("SHA-256").digest(imported.readBytes()).joinToString("") { "%02x".format(it) } == entry["sha256"]) {
                "Prepare all pinned adapter imports explicitly before preparing federation services."
            }
        }
        val inputs = (listOf(tasks.jar.get().archiveFile.get().asFile) + configurations.runtimeClasspath.get().files).sortedBy { it.name }
        fun digest(file: File) = MessageDigest.getInstance("SHA-256").let { hash ->
            file.inputStream().use { input -> val buffer = ByteArray(65536); while (true) { val count = input.read(buffer); if (count < 0) break; hash.update(buffer, 0, count) } }
            hash.digest().joinToString("") { "%02x".format(it) }
        }
        val entries = inputs.mapIndexed { index, file ->
            check(file.isFile && file.extension == "jar") { "Federation runtime must contain prepared JAR files only." }
            mapOf("file" to "%03d-%s".format(index, file.name), "bytes" to file.length(), "sha256" to digest(file))
        }
        val identity = MessageDigest.getInstance("SHA-256").digest(entries.joinToString("\n") { "${it["file"]}:${it["sha256"]}" }.toByteArray())
            .joinToString("") { "%02x".format(it) }
        val root = layout.buildDirectory.dir("p3/runtime/$identity").get().asFile.apply { mkdirs() }
        entries.zip(inputs).forEach { (entry, input) ->
            val target = root.resolve(entry["file"].toString())
            if (!target.exists()) input.copyTo(target, overwrite = false)
            check(target.length() == entry["bytes"] && digest(target) == entry["sha256"]) { "Frozen federation artifact differs." }
        }
        val manifest = groovy.json.JsonOutput.toJson(mapOf("runtimeVersion" to 1, "identity" to identity, "directory" to identity, "artifacts" to entries))
        val frozenManifest = root.parentFile.resolve("runtime-$identity.json")
        if(!frozenManifest.exists()) frozenManifest.writeText(manifest)
        check(frozenManifest.readText() == manifest) { "Immutable runtime manifest differs." }
        federationRuntimeManifest.get().asFile.writeText(manifest)
        logger.lifecycle("Prepared immutable federation runtime $identity (${entries.size} JARs).")
    }
}

tasks.register<Test>("federationContractTest") {
    group = "authentication lab"
    description = "Explicit owned federation serving/control checks; no IdP protocol or extension coverage claims."
    dependsOn(prepareFederationRuntime)
    systemProperty("federation.runtimeManifest", federationRuntimeManifest.get().asFile.absolutePath)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform { includeTags("federation-infrastructure") }
    failOnNoDiscoveredTests.set(true)
    outputs.upToDateWhen { false }
    outputs.cacheIf { false }
    val invocation = rootProject.extra["authLabInvocationId"].toString()
    reports.junitXml.outputLocation.set(layout.buildDirectory.dir("p3/invocations/$invocation/junit-xml"))
    reports.html.outputLocation.set(layout.buildDirectory.dir("p3/invocations/$invocation/html"))
    testLogging { events("failed", "skipped") }
    systemProperty("federation.workspace", rootProject.projectDir.parentFile.absolutePath)
    systemProperty("federation.invocationId", invocation)
    systemProperty("federation.childClasspath", sourceSets.main.get().runtimeClasspath.asPath)
    afterSuite(KotlinClosure2<org.gradle.api.tasks.testing.TestDescriptor, org.gradle.api.tasks.testing.TestResult, Unit>({ descriptor, result ->
        if (descriptor.parent == null && (result.testCount == 0L || result.skippedTestCount != 0L))
            throw GradleException("Provider contract checks must discover and execute every selected test without skips.")
    }))
}

// Preparation resolves only this module. No application/provider/browser is started.
tasks.register("prepareFederationDependencies") {
    group = "authentication lab"
    doLast {
        listOf("compileClasspath", "runtimeClasspath", "testCompileClasspath", "testRuntimeClasspath").forEach { name ->
            val resolved = configurations.getByName(name).resolvedConfiguration.resolvedArtifacts
            logger.lifecycle("Prepared federation $name: ${resolved.size} verified artifacts.")
        }
    }
}

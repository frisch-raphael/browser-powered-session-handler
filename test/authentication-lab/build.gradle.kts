import java.security.MessageDigest
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

plugins {
    `java-library`
    application
}

repositories { mavenCentral() }

java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencyLocking { lockAllConfigurations() }
val hostProbe = sourceSets.create("hostProbe")
val montoyaApi = rootProject.configurations.getByName("compileOnly").dependencies.single { it.group == "net.portswigger.burp.extensions" && it.name == "montoya-api" }
tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("--add-modules", "jdk.httpserver"))
}

dependencies {
    implementation("com.google.code.gson:gson:2.13.2")
    implementation("io.github.littleproxy:littleproxy:2.9.1") // Same pin as the inspected native fixture.
    implementation("org.bouncycastle:bcprov-jdk18on:1.86") // Independent MD4/DES verifier; never the production NTLM encoder.
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    add(hostProbe.compileOnlyConfigurationName, "${montoyaApi.group}:${montoyaApi.name}:${montoyaApi.version}")
}

application { mainClass.set("lab.auth.LabMain") }
tasks.test {
    useJUnitPlatform()
    failOnNoDiscoveredTests.set(true)
    testLogging { events("failed", "skipped") }
    val temporary = layout.buildDirectory.dir("tmp/test")
    systemProperty("java.io.tmpdir", temporary.get().asFile.absolutePath)
    doFirst { temporary.get().asFile.mkdirs() }
}

fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
val workspace = rootProject.projectDir.parentFile
val fixtureTaskPath = ":auth-lab:test"
val invocationId = rootProject.extra["authLabInvocationId"].toString()
val fixtureReports = layout.buildDirectory.dir("authlab/$invocationId/${digest(fixtureTaskPath.toByteArray(Charsets.UTF_8))}")
val fixtureJar = tasks.named<Jar>("jar").flatMap { it.archiveFile }
val explicitFixtures = gradle.startParameter.taskNames.any { it.substringAfterLast(':') == "authLab" } && providers.gradleProperty("labProfiles").orNull?.split(",")?.toSet() == setOf("fixtures")
@Suppress("UNCHECKED_CAST")
fun configurationInputs(): List<String> = (JsonSlurper().parse(workspace.resolve("test/authentication-lab/src/main/resources/configuration-inputs.json")) as Map<String, Any?>)["configurationFiles"] as List<String>
fun fixtureConfiguration(): String = digest((listOf("authlab-fixture-config-v1", fixtureTaskPath) + configurationInputs().map { digest(workspace.resolve(it).readBytes()) }).joinToString("\n").toByteArray(Charsets.UTF_8))
fun catalogRevision(): String = digest(workspace.resolve("test/authentication-lab/src/main/resources/catalog").listFiles()!!.filter { it.extension == "json" }.sortedBy { it.name }.joinToString("\n") { "${it.name}:${digest(it.readBytes())}" }.toByteArray(Charsets.UTF_8))
val collectFixtureResults = tasks.register<JavaExec>("collectFixtureResults") {
    group = "authentication lab"
    description = "Join current-run JUnit XML and observed HTTP facts to fixture bindings."
    classpath(files(fixtureJar), configurations.runtimeClasspath)
    mainClass.set("lab.auth.LabMain")
    args("collect-fixtures", "--profiles", "fixtures", "--report-directory", fixtureReports.get().asFile.absolutePath, "--workspace", workspace.absolutePath, "--artifact", fixtureJar.get().asFile.absolutePath)
    outputs.upToDateWhen { false }
    doFirst {
        val contextFile = fixtureReports.get().file("report-context.json").asFile
        if (!contextFile.isFile) throw GradleException("No current fixture task context; run authLab -PlabProfiles=fixtures.")
        @Suppress("UNCHECKED_CAST")
        val context = JsonSlurper().parse(contextFile) as MutableMap<String, Any?>
        context["state"] = try { tasks.named<Test>("test").get().state.rethrowFailure(); "COMPLETED" } catch (_: Exception) { "FAILED" }
        contextFile.writeText(JsonOutput.toJson(context), Charsets.UTF_8)
    }
}
if (explicitFixtures) tasks.test {
    dependsOn(fixtureJar)
    reports.junitXml.outputLocation.set(fixtureReports.map { it.dir("junit-xml") })
    outputs.upToDateWhen { false }
    outputs.cacheIf { false }
    doFirst {
        val directory = fixtureReports.get().asFile
        if (directory.resolve("report-context.json").exists() || directory.resolve("observations").exists()) throw GradleException("Fixture invocation already has retained evidence.")
        directory.mkdirs()
        val context = linkedMapOf<String, Any?>("contextVersion" to 1, "invocationId" to invocationId, "taskPath" to fixtureTaskPath,
            "configurationHash" to fixtureConfiguration(), "productionRevision" to null, "artifactSha256" to digest(fixtureJar.get().asFile.readBytes()), "catalogRevision" to catalogRevision(), "state" to "STARTED")
        directory.resolve("report-context.json").writeText(JsonOutput.toJson(context), Charsets.UTF_8)
        systemProperty("lab.fixtureInvocationId", invocationId)
        systemProperty("lab.fixtureReportDirectory", directory.absolutePath)
    }
    finalizedBy(collectFixtureResults)
}

// This is an explicit maintenance operation: inspect the catalog diff before claiming coverage.
tasks.register<JavaExec>("refreshBindings") {
    group = "authentication lab"
    description = "Refresh reviewed source/configuration fingerprints after an intentional refactor; runs no acceptance tests."
    dependsOn(tasks.classes)
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("lab.auth.RefreshBindings")
    args(workspace.absolutePath)
}

import java.util.jar.JarFile

plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.1")
    implementation("com.microsoft.playwright:playwright:1.64.0")
    implementation("io.netty:netty-codec-http:4.2.17.Final")
    implementation("io.netty:netty-handler:4.2.17.Final")
    implementation("org.slf4j:slf4j-api:2.0.20")
    implementation("org.apache.httpcomponents.client5:httpclient5:5.6.5")
    implementation("eu.agno3.jcifs:jcifs-ng:2.1.10")
    implementation("com.google.re2j:re2j:1.8")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("org.bouncycastle:bcutil-jdk18on:1.86")
    implementation("org.apache.commons:commons-compress:1.28.0")
    implementation("org.tukaani:xz:1.12")
    implementation("net.java.dev.jna:jna:5.19.1")
    implementation("org.brotli:dec:0.1.2")

    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.4")
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // Captured acceptance builds receive their immutable lab JAR from the invocation plan.
    if (System.getProperty("authlab.plan") == null) {
        testImplementation(project(":auth-lab"))
    }
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

dependencyLocking {
    lockAllConfigurations()
}

val integrationClassNames = listOf("bpsh.browser.BrowserJourneyIntegrationTest", "bpsh.browser.mtls.Pkcs11JourneyIntegrationTest")
/**
 * Rejects missing browser/native test classes before explicit integration runs can report NO-SOURCE.
 *
 * Default unit tests deliberately do not depend on this verifier or browser asset preparation.
 */
val verifyIntegrationTestClasses by tasks.registering {
    group = "verification"
    dependsOn(tasks.testClasses)
    doLast {
        integrationClassNames.forEach { name ->
            check(sourceSets.test.get().output.classesDirs.files.any { it.resolve("${name.replace('.', '/')}.class").isFile }) {
                "Required integration test class $name was not compiled."
            }
        }
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.test {
    filter {
        integrationClassNames.forEach { excludeTestsMatching("$it*") }
    }
}

/** Verifies native source documentation, including private implementation helpers, without browser/native startup. */
tasks.register<Javadoc>("verifyNativeDocumentation") {
    group = "verification"
    description = "Validate native Java comments with private-member Javadoc doclint."
    dependsOn(tasks.classes)
    source = sourceSets.main.get().allJava
    classpath = sourceSets.main.get().compileClasspath + sourceSets.main.get().output
    destinationDir = layout.buildDirectory.dir("docs/native").get().asFile
    (options as org.gradle.external.javadoc.StandardJavadocDocletOptions).apply {
        memberLevel = org.gradle.external.javadoc.JavadocMemberLevel.PRIVATE
        addBooleanOption("Xdoclint:all,-missing", true)
        encoding = "UTF-8"
    }
    isFailOnError = true
}

/**
 * Creates an explicit JUnit task with prepared assets and fail-closed discovery checks.
 *
 * Both a missing compiled test tree and zero/all-skipped suites fail. Runtime classpaths include
 * Montoya for boundary doubles and generated assets only here; test dependencies stay out of jar.
 *
 * @param taskName Gradle verification task name.
 * @param className Required integration test class-name prefix.
 * @return Registered Test task provider with its own inclusion filter.
 */
fun registerIntegrationTest(taskName: String, className: String) = tasks.register<Test>(taskName) {
    group = "verification"
    description = "Run $className with its required browser/native fixtures."
    dependsOn(verifyIntegrationTestClasses)
    val external = providers.gradleProperty("packagedJar").orNull
    val candidate = if (external == null) files(tasks.named<Jar>("jar").flatMap { it.archiveFile }) else files(file(external))
    if (external == null) dependsOn(tasks.jar)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    val testOnly = configurations.testRuntimeClasspath.get() - configurations.runtimeClasspath.get()
    classpath = sourceSets.test.get().output + candidate + testOnly
    inputs.files(candidate)
    outputs.upToDateWhen { false }
    doFirst {
        providers.gradleProperty("burpBrowserExecutable").orNull?.let { systemProperty("bpsh.test.burpBrowserExecutable", file(it).canonicalPath) }
        val artifact = candidate.singleFile.canonicalFile
        check(artifact.isFile) { "The selected packagedJar must be an existing JAR." }
        JarFile(artifact).use { jar ->
            check(jar.getEntry("bpsh/browser/runtime/BrowserRuntimeManager.class") != null) { "The selected JAR is not the extension artifact." }
        }
        systemProperty("bpsh.packagedJar", artifact.absolutePath)
        systemProperty("bpsh.probeClasspath", classpath.asPath)
        systemProperty("bpsh.probeResultsDir", layout.buildDirectory.dir("reports/bpsh-runtime").get().asFile.absolutePath)
        if (taskName == "browserIntegrationTest") providers.gradleProperty("oldPackagedJar").orNull?.let { old ->
            val previous = file(old).canonicalFile
            check(previous.isFile) { "oldPackagedJar must exist; omit it when no compatible previous artifact is available." }
            systemProperty("bpsh.oldPackagedJar", previous.absolutePath)
        }
    }
    filter {
        includeTestsMatching("$className*")
        isFailOnNoMatchingTests = true
    }
    addTestListener(object : TestListener {
        override fun beforeSuite(suite: TestDescriptor) {}
        override fun beforeTest(testDescriptor: TestDescriptor) {}
        override fun afterTest(testDescriptor: TestDescriptor, result: TestResult) {}
        override fun afterSuite(suite: TestDescriptor, result: TestResult) {
            if (suite.parent == null) {
                logger.lifecycle("$taskName: ${result.testCount} discovered, ${result.skippedTestCount} skipped, ${result.failedTestCount} failed")
                check(result.testCount > 0 && result.skippedTestCount < result.testCount) {
                    "Required integration suite discovered no executable tests."
                }
            }
        }
    })
}

registerIntegrationTest("browserIntegrationTest", "bpsh.browser.BrowserJourneyIntegrationTest")
registerIntegrationTest("pkcs11IntegrationTest", "bpsh.browser.mtls.Pkcs11JourneyIntegrationTest")


// Native tests run in their own JVM with an explicitly selected disposable SoftHSM store.
tasks.named<Test>("pkcs11IntegrationTest") {
    doFirst {
        val fixture = providers.gradleProperty("pkcs11Fixture").orNull
            ?: error("Create a fresh fixture with test/pkcs11_fixture.py and supply -Ppkcs11Fixture=<fixture.json>; no user token store is used.")
        val manifest = file(fixture).canonicalFile
        check(manifest.isFile) { "The explicit disposable PKCS#11 fixture manifest is missing." }
        environment("BPSH_PKCS11_FIXTURE", manifest.absolutePath)
        environment("SOFTHSM2_CONF", manifest.parentFile.resolve("softhsm2.conf").absolutePath)
    }
}

apply(from = "gradle/driver-assets.gradle.kts")

// Recording metadata is shipped as source JavaScript; no npm or TypeScript installation is involved.
tasks.named<Jar>("jar") {
    val metadata = layout.projectDirectory.file("src/main/resources/bpsh/browser/recorder-action-metadata.js")
    inputs.file(metadata)
    doLast {
        val expected = metadata.asFile.readBytes()
        check(expected.isNotEmpty() && expected.size <= 64 * 1024) { "Recorder metadata resource is missing or excessive." }
        JarFile(archiveFile.get().asFile).use { jar ->
            val entry = jar.getJarEntry("bpsh/browser/recorder-action-metadata.js") ?: error("Recorder metadata is absent from the development JAR.")
            check(jar.getInputStream(entry).use { it.readNBytes(64 * 1024 + 1) }.contentEquals(expected)) { "Packaged recorder metadata differs from its maintained source." }
        }
    }
}

// Snapshot builds run only production configuration; the outer build owns lab orchestration.
if (System.getProperty("authlab.plan") == null) {
    apply(from = "gradle/auth-lab.gradle.kts")
}

apply(from = "gradle/architecture.gradle.kts")

// An explicit local replacement uses the existing compatible dependency graph.
providers.gradleProperty("jcifsReplacement").orNull?.let { replacement ->
    val binary=file(replacement)
    require(binary.isFile && providers.gradleProperty("jcifsReplacementSources").isPresent) { "Provide replacement JAR and complete source ZIP." }
    tasks.withType<JavaCompile>().configureEach { classpath=classpath.filter { it.name!="jcifs-ng-2.1.10.jar" } + files(binary) }
    tasks.withType<Test>().configureEach { classpath=classpath.filter { it.name!="jcifs-ng-2.1.10.jar" } + files(binary) }
}

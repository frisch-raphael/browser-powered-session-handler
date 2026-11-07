import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import org.apache.commons.compress.archivers.zip.ZipFile
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration
import java.util.HexFormat
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

buildscript {
    repositories { mavenCentral() }
    dependencies {
        classpath("com.fasterxml.jackson.core:jackson-databind:2.17.1")
        classpath("org.apache.commons:commons-compress:1.28.0")
    }
    configurations.getByName("classpath").resolutionStrategy.activateDependencyLocking()
}

/**
 * Parses source locks with duplicate/trailing-value rejection before the producer's semantic checks.
 */
val assetMapper = ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).enable(SerializationFeature.INDENT_OUTPUT)
/**
 * Requires an object with exactly the listed required fields.
 *
 * Unlike the runtime codec's optional-member helper, every allowed name here must also exist.
 *
 * @param node Candidate source-lock object.
 * @param path Safe object label for diagnostics.
 * @param allowed Complete required field set for this record shape.
 */
fun fields(node: JsonNode?, path: String, vararg allowed: String) {
    require(node != null && node.isObject) { "$path must be an object." }
    require(node.fieldNames().asSequence().all { it in allowed }) { "$path contains unknown fields." }
    require(allowed.all { node.has(it) }) { "$path is missing required fields." }
}
/**
 * Reads a nonblank lock string without coercing another JSON type.
 *
 * @param node Containing object already checked for its field set.
 * @param key Required string member name.
 * @return Exact nonblank content; whitespace is not trimmed.
 */
fun string(node: JsonNode, key: String): String {
    require(node.path(key).isTextual && node.path(key).textValue().isNotBlank()) { "$key must be a nonblank string." }
    return node.path(key).textValue()
}
/**
 * Reads an integral source-lock value within inclusive long bounds.
 *
 * @param node Containing source record.
 * @param key Required numeric member.
 * @param min Inclusive minimum.
 * @param max Inclusive maximum.
 * @return Value without floating-point coercion or narrowing.
 */
fun integer(node: JsonNode, key: String, min: Long, max: Long): Long {
    val value = node.path(key)
    require(value.isIntegralNumber && value.canConvertToLong() && value.longValue() in min..max) { "$key has an invalid integer value." }
    return value.longValue()
}
/**
 * Checks an unchanged bundle-relative POSIX path before copying or emitting archive members.
 *
 * Rejects absolute/drive forms, backslashes, colon, NUL, empty/dot/parent components and the
 * reserved root completion marker. Enforces 4096 UTF-8 bytes and 32 components; this is syntax
 * validation, not filesystem canonicalization or symlink resolution.
 *
 * @param value Source member, destination prefix or exact bundle selector.
 * @return The unchanged safe relative path.
 */
fun safePath(value: String): String {
    require(value.isNotEmpty() && !value.startsWith('/') && !value.contains('\\') && !value.contains(':') && !value.contains('\u0000')
        && value.toByteArray(Charsets.UTF_8).size <= 4096) { "Invalid relative asset path." }
    val parts = value.split('/')
    require(parts.size <= 32 && parts.none { it.isEmpty() || it == "." || it == ".." }) { "Invalid relative asset components." }
    require(value != ".complete.json") { "Reserved asset path." }
    return value
}
/**
 * Streams a complete archive/file digest without loading its contents into one byte array.
 *
 * @param path Local source archive or completed bundle ZIP.
 * @return Lowercase SHA-256 digest to compare with the lock or record in the manifest.
 */
fun hash(path: Path): String {
    val digest = MessageDigest.getInstance("SHA-256")
    Files.newInputStream(path).use { input ->
        val buffer = ByteArray(65536)
        while (true) { val n = input.read(buffer); if (n < 0) break; digest.update(buffer, 0, n) }
    }
    return HexFormat.of().formatHex(digest.digest())
}
/**
 * Validates the developer's explicit asset-download HTTP proxy origin.
 *
 * No credentials, path beyond slash, query or fragment are accepted. This is separate from a
 * journey's browser proxy and from Gradle's Maven dependency settings; no Burp config is inferred.
 *
 * @param value assetDownloadProxy property supplied for browser-source HTTPS fetches.
 * @return Parsed proxy URI; an omitted port is used as port 80 by the caller.
 */
fun exactOrigin(value: String): URI {
    val uri = URI.create(value)
    require(uri.scheme == "http" && uri.host != null && uri.userInfo == null && uri.port in -1..65535 && uri.port != 0
        && uri.rawPath in listOf("", "/") && uri.rawQuery == null && uri.rawFragment == null) { "assetDownloadProxy must be an HTTP proxy origin without credentials." }
    return uri
}

/**
 * Normalizes only known host OS/architecture names; unsupported hosts cannot select a guessed bundle.
 */
val hostPlatform = when {
    System.getProperty("os.name").lowercase().startsWith("windows") -> "windows"
    System.getProperty("os.name").lowercase().contains("mac") || System.getProperty("os.name").lowercase() == "darwin" -> "macos"
    System.getProperty("os.name").lowercase() == "linux" -> "linux"
    else -> "unsupported"
} + "-" + when (System.getProperty("os.arch").lowercase()) { "amd64", "x86_64" -> "x64"; "aarch64", "arm64" -> "arm64"; else -> "unsupported" }
/**
 * Holds generated manifest/ZIP resources added by jar and explicit integration tasks, not unit tests.
 */
val generatedAssets = layout.buildDirectory.dir("generated/browser-assets")
/**
 * Names the committed release-input lock; hashes and member prefixes come from measured archives.
 */
val assetLock = layout.projectDirectory.file("browser-assets.lock.json")

/** Pinned source ZIPs and isolated consumer-validator dependencies. */
val runtime = configurations.getByName("runtimeClasspath")
val supportedTargets = listOf("windows-x64", "linux-x64", "macos-x64")
require(!providers.gradleProperty("bundlePlatform").isPresent) { "bundlePlatform is retired. Build the universal JAR without it." }

/** Removes only a verified resolved child of this build's owned output. */
fun deleteBuildTree(path: Path, buildRoot: Path) {
    val root = buildRoot.toAbsolutePath().normalize(); val target = path.toAbsolutePath().normalize()
    require(target != root && target.startsWith(root)) { "Cleanup outside owned build output." }
    if (Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
        require(!Files.isSymbolicLink(target) && target.toRealPath().startsWith(root.toRealPath())) { "Linked build staging." }
        Files.walk(target).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) } }
    }
}

/** Checks target labels, helper inventory and the matching Node subtree. */
fun validateTarget(platform: JsonNode) {
    fields(platform, "platform", "platform", "browserName", "browserVersion", "browserRevision", "driverPackageVersion", "nodeVersion",
        "browserRoot", "browserExecutable", "nodeExecutable", "driverEntryPoint", "helpers", "sources")
    val target = string(platform, "platform"); require(target in supportedTargets)
    require(string(platform, "browserName") == "chromium" && string(platform, "browserRevision") == "1248"
        && string(platform, "browserVersion") == "156.0.8078.4" && string(platform, "driverPackageVersion") == "1.64.1"
        && string(platform, "nodeVersion") == "24.22.1") { "Pinned runtime labels differ." }
    listOf("browserRoot", "browserExecutable", "nodeExecutable", "driverEntryPoint").forEach { safePath(string(platform, it)) }
    require(platform.path("helpers").isArray && platform.path("sources").isArray)
    val helpers = platform.path("helpers").map {
        fields(it, "helper", "name", "revision", "path"); safePath(string(it, "path"))
        require(string(it, "revision").matches(Regex("[0-9]+"))); string(it, "name")
    }
    val expected = if (target == "windows-x64") setOf("ffmpeg", "winldd") else setOf("ffmpeg")
    require(helpers.size == expected.size && helpers.toSet() == expected) { "Target helper inventory differs." }
    val ids = platform.path("sources").map { string(it, "id") }
    require(ids.size == expected.size + 3 && ids.toSet() == expected + setOf("chromium", "node", "driver")) { "Source inventory differs." }
    val copies = platform.path("sources").single { string(it, "id") == "node" }.path("copies")
    val subtree = when (target) { "windows-x64" -> "win32_x64"; "linux-x64" -> "linux"; else -> "mac" }
    require(copies.isArray && copies.size() == 1 && copies[0].path("from").asText() == "driver/$subtree"
        && copies[0].path("to").asText() == "driver") { "Node source does not match target." }
}

/** Returns a whole-source verified ZIP; offline misses never invoke the downloader. */
fun loadVerifiedSource(source: JsonNode, cache: Path, offline: Boolean, resolved: Map<String, Path>,
                       download: (URI, Path, Long, String) -> Unit): Path {
    fields(source, "source record", "id", "revision", "source", "sha256", "bytes", "copies")
    string(source, "id"); string(source, "revision")
    val expected = string(source, "sha256"); require(expected.matches(Regex("[0-9a-f]{64}")))
    val size = integer(source, "bytes", 1, 2L shl 30); val location = source.path("source")
    val path = when (string(location, "type")) {
        "maven" -> { fields(location, "Maven source", "type", "coordinates")
            resolved[string(location, "coordinates")] ?: error("Missing locked Maven source.") }
        "https" -> {
            fields(location, "HTTPS source", "type", "url")
            val uri = URI.create(string(location, "url")); require(uri.scheme == "https" && uri.host != null && uri.userInfo == null && uri.fragment == null)
            val destination = cache.resolve("$expected.zip")
            if (!Files.exists(destination)) {
                require(!offline) { "Locked browser source missing in offline mode; prepare sources online first." }
                Files.createDirectories(cache); download(uri, destination, size, expected)
            }
            destination
        }
        else -> error("Unsupported source type.")
    }
    require(Files.isRegularFile(path) && Files.size(path) == size && hash(path) == expected) { "Locked source hash/size mismatch." }
    require(source.path("copies").isArray && !source.path("copies").isEmpty)
    source.path("copies").forEach {
        fields(it, "copy", "from", "to"); require(it.path("from").isTextual)
        if (it.path("from").textValue().isNotEmpty()) safePath(it.path("from").textValue()); safePath(string(it, "to"))
    }
    return path
}

/** Reuses only the compiled pure-data manifest parser, never the runtime/installer factory. */
fun withManifestValidator(action: ((ByteArray, String) -> Unit) -> Unit) {
    val classes = project.extensions.getByType<JavaPluginExtension>().sourceSets.getByName("main").output.classesDirs.files
    java.net.URLClassLoader((classes + runtime.files).map { it.toURI().toURL() }.toTypedArray(), ClassLoader.getPlatformClassLoader()).use { loader ->
        val manager = loader.loadClass("bpsh.runtime.BrowserRuntimeManager")
        val limitsType = loader.loadClass("bpsh.runtime.BrowserRuntimeManager" + "$" + "Limits")
        val standard = limitsType.getDeclaredMethod("standard").apply { isAccessible = true }.invoke(null)
        val parse = manager.getDeclaredMethod("parseManifest", ByteArray::class.java, String::class.java, limitsType).apply { isAccessible = true }
        action { bytes, target ->
            try { parse.invoke(null, bytes, target, standard); Unit }
            catch (ex: java.lang.reflect.InvocationTargetException) { throw IllegalArgumentException("Runtime validator rejected candidate.", ex.cause) }
        }
    }
}

/** Bounded selected source member and its output metadata. */
data class MappedAsset(val source: Path, val member: String, val path: String, val bytes: Long, val link: Boolean, val executable: Boolean)

/** Shared real/synthetic mapper, ZIP writer, consumer validator and target-pair publisher. */
fun prepareTargetPayload(platform: JsonNode, sources: List<Pair<JsonNode, Path>>, driver: Path,
                         output: Path, buildRoot: Path, validate: (ByteArray, String) -> Unit) {
    validateTarget(platform); val target = string(platform, "platform")
    java.util.zip.ZipFile(driver.toFile()).use { jar ->
        val registry = jar.getInputStream(jar.getEntry("driver/package/browsers.json")).use { assetMapper.readTree(it) }
        val chromium = registry.path("browsers").single { it.path("name").asText() == "chromium" }
        require(chromium.path("revision").asText() == string(platform, "browserRevision") && chromium.path("browserVersion").asText() == string(platform, "browserVersion"))
        val pkg = jar.getInputStream(jar.getEntry("driver/package/package.json")).use { assetMapper.readTree(it) }
        require(pkg.path("version").asText() == string(platform, "driverPackageVersion"))
        platform.path("helpers").forEach { helper ->
            require(registry.path("browsers").any { it.path("name").asText() == string(helper, "name") && it.path("revision").asText() == string(helper, "revision") })
        }
    }
    val mapped = mutableListOf<MappedAsset>(); val names = mutableSetOf<String>()
    sources.forEach { (source, path) ->
        ZipFile.builder().setFile(path.toFile()).get().use { input ->
            val members = input.entries.asSequence().toList(); require(members.size <= 100_000)
            source.path("copies").forEach { copy ->
                val from = copy.path("from").textValue(); val to = string(copy, "to")
                val selected = members.filter { !it.isDirectory && (from.isEmpty() || it.name == from || it.name.startsWith("$from/")) }
                require(selected.isNotEmpty()) { "A locked source prefix selected no files." }
                selected.forEach { entry ->
                    safePath(entry.name); require(input.canReadEntryData(entry))
                    val type = entry.unixMode and 61440; require(type == 0 || type == 32768 || type == 40960) { "Special Unix source file." }
                    val link = entry.isUnixSymlink; require(!link || target != "windows-x64")
                    val remainder = if (from.isEmpty()) entry.name else entry.name.removePrefix(from).removePrefix("/")
                    val name = safePath(if (remainder.isEmpty()) to else "$to/$remainder")
                    require(names.add(name.lowercase(java.util.Locale.ROOT))) { "Duplicate or case-colliding asset path." }
                    require(entry.size in 0..(if (link) 4096L else (1L shl 30)))
                    val executable = !link && if (target == "windows-x64") name.endsWith(".exe", true) else (entry.unixMode and 73) != 0
                    mapped.add(MappedAsset(path, entry.name, name, entry.size, link, executable)); require(mapped.size <= 100_000)
                }
            }
        }
    }
    Files.createDirectories(output.parent); val stage = Files.createTempDirectory(output.parent, ".$target-")
    try {
        val zip = stage.resolve("browser-assets.zip")
        val manifest = assetMapper.createObjectNode().put("formatVersion", 1).put("playwrightJavaVersion", "1.64.0")
        platform.fields().forEachRemaining { (key, value) -> if (key != "sources") manifest.set<JsonNode>(key, value) }
        val entries = manifest.putArray("entries"); var total = 0L
        val openSources = sources.map { it.second }.distinct().associateWith { ZipFile.builder().setFile(it.toFile()).get() }
        try {
            org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream(zip).use { out ->
                mapped.sortedBy { it.path }.forEach { member ->
                    val source = openSources.getValue(member.source)
                    val entry = org.apache.commons.compress.archivers.zip.ZipArchiveEntry(member.path)
                    entry.time = 0L; entry.setUnixMode(if (member.link) 41471 else if (member.executable) 33261 else 33188)
                    out.putArchiveEntry(entry)
                    source.getInputStream(source.getEntry(member.member)).use { input ->
                        if (member.link) {
                            val bytes = input.readNBytes(4097); require(bytes.size.toLong() == member.bytes && bytes.size <= 4096)
                            val linkTarget = Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString()
                            out.write(bytes); entries.addObject().put("path", member.path).put("type", "symlink").put("target", linkTarget)
                        } else {
                            val digest = MessageDigest.getInstance("SHA-256"); val buffer = ByteArray(65536); var bytes = 0L
                            while (true) {
                                val n = input.read(buffer); if (n < 0) break; bytes += n; total += n
                                require(bytes <= member.bytes && total <= (4L shl 30)); out.write(buffer, 0, n); digest.update(buffer, 0, n)
                            }
                            require(bytes == member.bytes)
                            entries.addObject().put("path", member.path).put("type", "file").put("bytes", bytes)
                                .put("sha256", HexFormat.of().formatHex(digest.digest())).put("executable", member.executable)
                        }
                    }
                    out.closeArchiveEntry()
                }
            }
        } finally { openSources.values.forEach { it.close() } }
        require(Files.size(zip) in 1..(2L shl 30))
        manifest.put("unpackedBytes", total)
        manifest.putObject("archive").put("resource", "META-INF/bpsh/$target/browser-assets.zip").put("sha256", hash(zip)).put("bytes", Files.size(zip))
        val bytes = assetMapper.writeValueAsBytes(manifest); validate(bytes, target)
        Files.write(stage.resolve("browser-assets.json"), bytes)
        deleteBuildTree(output, buildRoot); Files.move(stage, output, StandardCopyOption.ATOMIC_MOVE)
    } finally { deleteBuildTree(stage, buildRoot) }
}

/** Prepares all three target archives without executing a native program. */
tasks.register("prepareBrowserAssets") {
    group = "build"; dependsOn("compileJava"); mustRunAfter("verifyIntegrationTestClasses")
    inputs.file(assetLock); inputs.files(runtime)
    inputs.files(provider { project.extensions.getByType<JavaPluginExtension>().sourceSets.getByName("main").output.classesDirs.asFileTree.matching { include("BrowserRuntimeManager*.class") } })
    outputs.dir(generatedAssets)
    doLast {
        val lock = assetMapper.readTree(Files.readString(assetLock.asFile.toPath(), Charsets.UTF_8))
        fields(lock, "lock", "formatVersion", "playwrightJavaVersion", "platforms")
        require(integer(lock, "formatVersion", 1, 1) == 1L && string(lock, "playwrightJavaVersion") == "1.64.0" && lock.path("platforms").isArray)
        val targets = lock.path("platforms").map { string(it, "platform") }
        require(targets.size == 3 && targets.toSet() == supportedTargets.toSet()) { "Exactly three unique x64 targets are required." }
        val resolved = runtime.resolvedConfiguration.resolvedArtifacts.associate { "${it.moduleVersion.id.group}:${it.name}:${it.moduleVersion.id.version}" to it.file.toPath() }
        val driver = resolved.getValue("com.microsoft.playwright:driver:1.64.0")
        val cache = layout.buildDirectory.dir("browser-sources").get().asFile.toPath(); val buildRoot = layout.buildDirectory.get().asFile.toPath()
        val proxy = providers.gradleProperty("assetDownloadProxy").orNull?.let(::exactOrigin)
        val download: (URI, Path, Long, String) -> Unit = { uri, destination, size, expected ->
            val direct = object : ProxySelector() {
                override fun select(uri: URI): List<Proxy> = listOf(Proxy.NO_PROXY)
                override fun connectFailed(uri: URI, sa: SocketAddress, ioe: java.io.IOException) {}
            }
            val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(60)).followRedirects(HttpClient.Redirect.NORMAL)
                .proxy(if (proxy == null) direct else ProxySelector.of(InetSocketAddress(proxy.host, if (proxy.port == -1) 80 else proxy.port))).build()
            val temporary = Files.createTempFile(cache, "asset-", ".part")
            try {
                logger.lifecycle("Fetching locked browser source via ${if (proxy == null) "direct connection" else "explicit proxy"}")
                val response = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofMinutes(2)).GET().build(), HttpResponse.BodyHandlers.ofInputStream())
                response.body().use { input ->
                    require(response.statusCode() == 200) { "Locked source download failed; no direct fallback." }
                    Files.newOutputStream(temporary).use { out ->
                        val buffer = ByteArray(65536); var received = 0L
                        while (true) { val n = input.read(buffer); if (n < 0) break; received += n; require(received <= size); out.write(buffer, 0, n) }
                    }
                }
                require(Files.size(temporary) == size && hash(temporary) == expected)
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE)
            } finally { Files.deleteIfExists(temporary) }
        }
        withManifestValidator { validate ->
            supportedTargets.forEach { target ->
                val platform = lock.path("platforms").single { string(it, "platform") == target }; validateTarget(platform)
                val sources = platform.path("sources").map { it to loadVerifiedSource(it, cache, gradle.startParameter.isOffline, resolved, download) }
                prepareTargetPayload(platform, sources, driver, generatedAssets.get().asFile.toPath().resolve("META-INF/bpsh/$target"), buildRoot, validate)
                logger.lifecycle("Prepared verified $target browser payload.")
            }
        }
    }
}

/** Exercises the real producer with tiny local sources, including invalid input and publication. */
tasks.register("verifyBrowserAssetProducer") {
    group = "verification"; dependsOn("compileJava"); outputs.upToDateWhen { false }
    doLast {
        val buildRoot = layout.buildDirectory.get().asFile.toPath()
        val root = layout.buildDirectory.dir("tmp/verifyBrowserAssetProducer").get().asFile.toPath()
        deleteBuildTree(root, buildRoot); Files.createDirectories(root)
        val results = assetMapper.createArrayNode()
        fun sampleZip(path: Path, entries: List<Triple<String, ByteArray, Int>>) {
            Files.createDirectories(path.parent)
            org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream(path).use { out ->
                entries.forEach { (name, bytes, mode) ->
                    val entry = org.apache.commons.compress.archivers.zip.ZipArchiveEntry(name).apply { time = 0L; setUnixMode(mode) }
                    out.putArchiveEntry(entry); out.write(bytes); out.closeArchiveEntry()
                }
            }
        }
        fun reject(block: () -> Unit) { var rejected = false; try { block() } catch (expected: Exception) { rejected = true }; check(rejected) { "Invalid source was accepted." } }
        fun case(name: String, block: () -> Unit) {
            try { block(); results.addObject().put("case", name).put("status", "PASS") }
            catch (ex: Exception) { results.addObject().put("case", name).put("status", "FAIL").put("errorType", ex.javaClass.simpleName); logger.error("Producer case failed: " + name, ex) }
        }
        val ordinary = "sample data; never execute".toByteArray()
        val driver = root.resolve("driver.jar")
        val registry = """{"browsers":[{"name":"chromium","revision":"1248","browserVersion":"156.0.8078.4"},{"name":"ffmpeg","revision":"1013"},{"name":"winldd","revision":"1007"}]}""".toByteArray()
        sampleZip(driver, listOf(Triple("driver/package/cli.js", ordinary, 33188),
            Triple("driver/package/package.json", """{"version":"1.64.1"}""".toByteArray(), 33188),
            Triple("driver/package/browsers.json", registry, 33188)))
        val node = root.resolve("node.jar")
        sampleZip(node, listOf(Triple("driver/win32_x64/node.exe", ordinary, 33188),
            Triple("driver/linux/node", ordinary, 33261), Triple("driver/mac/node", ordinary, 33261)))
        val resolved = mapOf("com.microsoft.playwright:driver:1.64.0" to driver, "com.microsoft.playwright:driver-bundle:1.64.0" to node)
        val lock = assetMapper.readTree(Files.readString(assetLock.asFile.toPath()))
        var downloads = 0
        val noDownload: (URI, Path, Long, String) -> Unit = { _, _, _, _ -> downloads++; error("Unexpected download.") }
        fun fixture(target: String, folder: Path, extras: List<Triple<String, ByteArray, Int>> = emptyList()): JsonNode {
            Files.createDirectories(folder)
            val platform = lock.path("platforms").single { it.path("platform").asText() == target }.deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>()
            platform.path("sources").forEach { source ->
                val id = string(source, "id")
                val path = when (id) {
                    "node" -> node
                    "driver" -> driver
                    else -> {
                        val path = folder.resolve(id + ".zip")
                        val members = if (id == "chromium") listOf(
                            Triple(string(platform, "browserExecutable").removePrefix("browsers/chromium-1248/"), ordinary, 33261),
                            Triple("extra-helper", ordinary, 35309), Triple("data.js", ordinary, 33188)) + extras
                        else listOf(Triple(id + if (target == "windows-x64") ".exe" else "", ordinary, 33261))
                        sampleZip(path, members); path
                    }
                }
                (source as com.fasterxml.jackson.databind.node.ObjectNode).put("sha256", hash(path)).put("bytes", Files.size(path))
                if (source.path("source").path("type").asText() == "https") {
                    val cache = folder.resolve("cache"); Files.createDirectories(cache)
                    Files.copy(path, cache.resolve(hash(path) + ".zip"), StandardCopyOption.REPLACE_EXISTING)
                }
            }
            return platform
        }
        fun sources(platform: JsonNode, folder: Path) = platform.path("sources").map {
            it to loadVerifiedSource(it, folder.resolve("cache"), true, resolved, noDownload)
        }
        withManifestValidator { validate ->
            supportedTargets.forEach { target ->
                case("complete-" + target) {
                    val folder = root.resolve(target)
                    val extra = if (target == "windows-x64") emptyList() else listOf(Triple("alias", "extra-helper".toByteArray(), 41471))
                    val platform = fixture(target, folder, extra)
                    prepareTargetPayload(platform, sources(platform, folder), driver, folder.resolve("out"), buildRoot, validate)
                    val metadata = assetMapper.readTree(Files.readAllBytes(folder.resolve("out/browser-assets.json")))
                    check(metadata.path("archive").path("resource").asText() == "META-INF/bpsh/" + target + "/browser-assets.zip")
                    val rows = metadata.path("entries").associateBy { it.path("path").asText() }
                    check(rows.getValue(string(platform, "browserExecutable")).path("executable").booleanValue())
                    check(!rows.getValue("browsers/chromium-1248/data.js").path("executable").booleanValue())
                    if (target != "windows-x64") {
                        check(rows.getValue("browsers/chromium-1248/extra-helper").path("executable").booleanValue())
                        check(rows.getValue("browsers/chromium-1248/alias").path("target").asText() == "extra-helper")
                    }
                    ZipFile.builder().setFile(folder.resolve("out/browser-assets.zip").toFile()).get().use { zip ->
                        check(zip.getEntry(string(platform, "nodeExecutable")).unixMode == 33261)
                        check(zip.getEntry("browsers/chromium-1248/extra-helper").unixMode == if (target == "windows-x64") 33188 else 33261)
                    }
                    prepareTargetPayload(platform, sources(platform, folder), driver, folder.resolve("repeat"), buildRoot, validate)
                    listOf("browser-assets.json", "browser-assets.zip").forEach { check(Files.mismatch(folder.resolve("out").resolve(it), folder.resolve("repeat").resolve(it)) == -1L) }
                }
            }
            case("unrelated-targets-remain-identical") {
                val otherTargets = listOf("windows-x64", "macos-x64")
                val before = otherTargets.associateWith { target -> listOf("browser-assets.json", "browser-assets.zip").map { hash(root.resolve(target).resolve("out").resolve(it)) } }
                val oldLinux = hash(root.resolve("linux-x64/out/browser-assets.zip"))
                val folder = root.resolve("changed-linux")
                val platform = fixture("linux-x64", folder, listOf(Triple("new-data", "different input".toByteArray(), 33188)))
                prepareTargetPayload(platform, sources(platform, folder), driver, root.resolve("linux-x64/out"), buildRoot, validate)
                check(hash(root.resolve("linux-x64/out/browser-assets.zip")) != oldLinux)
                otherTargets.forEach { target -> check(before.getValue(target) == listOf("browser-assets.json", "browser-assets.zip").map { hash(root.resolve(target).resolve("out").resolve(it)) }) }
            }
            val invalid = listOf(
                "traversal" to listOf(Triple("../escape", ordinary, 33188)),
                "case-collision" to listOf(Triple("DATA.js", ordinary, 33188)),
                "duplicate" to listOf(Triple("data.js", ordinary, 33188)),
                "file-directory" to listOf(Triple("data.js/child", ordinary, 33188)),
                "device" to listOf(Triple("device", ordinary, 8630)),
                "escape-link" to listOf(Triple("alias", "../../../escape".toByteArray(), 41471)),
                "cycle-link" to listOf(Triple("a", "b".toByteArray(), 41471), Triple("b", "a".toByteArray(), 41471)),
                "bad-utf8-link" to listOf(Triple("alias", byteArrayOf(-1), 41471)))
            invalid.forEach { (name, extras) -> case(name) {
                val folder = root.resolve(name); val platform = fixture("linux-x64", folder, extras)
                reject { prepareTargetPayload(platform, sources(platform, folder), driver, folder.resolve("out"), buildRoot, validate) }
                check(!Files.exists(folder.resolve("out")))
            } }
            case("missing-copy-prefix") {
                val folder = root.resolve("missing-prefix"); val platform = fixture("linux-x64", folder)
                (platform.path("sources")[0].path("copies")[0] as com.fasterxml.jackson.databind.node.ObjectNode).put("from", "missing")
                reject { prepareTargetPayload(platform, sources(platform, folder), driver, folder.resolve("out"), buildRoot, validate) }
            }
            case("missing-selector") {
                val folder = root.resolve("missing-selector"); val platform = fixture("linux-x64", folder) as com.fasterxml.jackson.databind.node.ObjectNode
                platform.put("browserExecutable", "browsers/missing")
                reject { prepareTargetPayload(platform, sources(platform, folder), driver, folder.resolve("out"), buildRoot, validate) }
            }
            case("offline-miss") {
                val folder = root.resolve("offline"); val platform = fixture("linux-x64", folder)
                val first = platform.path("sources")[0]; Files.delete(folder.resolve("cache").resolve(string(first, "sha256") + ".zip"))
                reject { sources(platform, folder) }; check(downloads == 0); check(!Files.exists(folder.resolve("out")))
            }
            case("source-size-and-digest") {
                val folder = root.resolve("corrupt"); val platform = fixture("linux-x64", folder)
                val first = platform.path("sources")[0]
                Files.write(folder.resolve("cache").resolve(string(first, "sha256") + ".zip"), ordinary)
                reject { sources(platform, folder) }
                val nodeRecord = platform.path("sources").single { it.path("id").asText() == "node" }.deepCopy<com.fasterxml.jackson.databind.node.ObjectNode>()
                nodeRecord.put("bytes", Files.size(node) + 1)
                reject { loadVerifiedSource(nodeRecord, folder.resolve("cache"), true, resolved, noDownload) }
            }
            case("failed-candidate-preserves-published-pair") {
                val folder = root.resolve("preserve"); val platform = fixture("linux-x64", folder)
                prepareTargetPayload(platform, sources(platform, folder), driver, folder.resolve("out"), buildRoot, validate)
                val before = listOf("browser-assets.json", "browser-assets.zip").map { hash(folder.resolve("out").resolve(it)) }
                val bad = fixture("linux-x64", folder.resolve("bad"), listOf(Triple("alias", "../escape".toByteArray(), 41471)))
                reject { prepareTargetPayload(bad, sources(bad, folder.resolve("bad")), driver, folder.resolve("out"), buildRoot, validate) }
                check(before == listOf("browser-assets.json", "browser-assets.zip").map { hash(folder.resolve("out").resolve(it)) })
                Files.write(folder.resolve("blocked"), ordinary)
                reject { prepareTargetPayload(platform, sources(platform, folder), driver, folder.resolve("blocked/out"), buildRoot, validate) }
            }
        }
        check(downloads == 0)
        val report = layout.buildDirectory.file("reports/browser-asset-producer/results.json").get().asFile.toPath()
        Files.createDirectories(report.parent); Files.write(report, assetMapper.writeValueAsBytes(results))
        check(results.all { it.path("status").asText() == "PASS" }) { "Producer verification failed; see results.json." }
        logger.lifecycle("Producer verification: " + results.size() + " cases passed; zero downloads/native executions.")
    }
}
tasks.named("check") { dependsOn("verifyBrowserAssetProducer") }

/**
 * Owns the rebuilt dependency-resource staging tree; cleanup is restricted to this checked build path.
 */
val assembledRuntime = layout.buildDirectory.dir("platform-runtime")
/**
 * Assembles a platform-specific runtime tree with explicit duplicate handling.
 *
 * Keeps only selected driver/Node resources, merges service providers and Netty metadata, retains
 * versioned classes and distinct legal notices, and removes stale signatures/module descriptors.
 * Different duplicate content fails unless a named merge rule handles that resource.
 */
tasks.register("assemblePlatformRuntime") {
    group = "build"
    inputs.files(runtime)
    outputs.dir(assembledRuntime)
    doLast {
        val directory = assembledRuntime.get().asFile.toPath().toAbsolutePath().normalize()
        val buildRoot = layout.buildDirectory.get().asFile.toPath().toAbsolutePath().normalize()
        require(directory.parent == buildRoot && directory.fileName.toString() == "platform-runtime") { "Refusing cleanup outside owned build staging." }
        if (Files.exists(directory)) Files.walk(directory).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) } }
        Files.createDirectories(directory)
        val services = sortedMapOf<String, MutableSet<String>>()
        val versions = java.util.Properties()
        runtime.resolvedConfiguration.resolvedArtifacts.sortedBy { it.moduleVersion.id.toString() }.forEach { artifact ->
            val owner = "${artifact.moduleVersion.id.group}.${artifact.name}-${artifact.moduleVersion.id.version}"
            java.util.zip.ZipFile(artifact.file).use { zipFile ->
                zipFile.entries().asSequence().filterNot { it.isDirectory }.forEach entryLoop@ { entry ->
                    val name = safePath(entry.name)
                    if (name == "META-INF/MANIFEST.MF" || name == "META-INF/INDEX.LIST" || name.endsWith("module-info.class")
                        || name.matches(Regex("META-INF/[^/]+\\.(SF|RSA|DSA|EC)", RegexOption.IGNORE_CASE))) return@entryLoop
                    if (name.startsWith("driver/")) return@entryLoop
                    val bytes = zipFile.getInputStream(entry).use { it.readBytes() }
                    if (name.startsWith("META-INF/services/")) {
                        val lines = bytes.toString(Charsets.UTF_8).lineSequence().map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }
                        services.getOrPut(name) { sortedSetOf() }.addAll(lines.toList()); return@entryLoop
                    }
                    if (name == "META-INF/io.netty.versions.properties") {
                        val properties = java.util.Properties().apply { bytes.inputStream().use { load(it) } }
                        properties.forEach { key, value ->
                            require(versions[key] == null || versions[key] == value) { "Conflicting Netty version metadata." }; versions[key] = value
                        }
                        return@entryLoop
                    }
                    val leaf = name.substringAfterLast('/').uppercase(java.util.Locale.ROOT)
                    val legal = leaf.contains("LICENSE") || leaf.contains("NOTICE") || leaf.startsWith("COPYING") || leaf == "DEPENDENCIES"
                    val destination = when {
                        legal && !name.startsWith("driver/") -> "META-INF/notices/$owner/$name"
                        name.endsWith("OSGI-INF/MANIFEST.MF") -> "META-INF/dependency-manifests/$owner/$name"
                        else -> name
                    }
                    val target = directory.resolve(destination); Files.createDirectories(target.parent)
                    if (Files.exists(target)) require(Files.readAllBytes(target).contentEquals(bytes)) { "Conflicting runtime entry $name; define an explicit merge rule." }
                    else Files.write(target, bytes)
                }
            }
        }
        services.forEach { (name, providers) ->
            val target = directory.resolve(name); Files.createDirectories(target.parent)
            Files.writeString(target, providers.joinToString("\n", postfix = "\n"))
        }
        if (!versions.isEmpty) {
            val target = directory.resolve("META-INF/io.netty.versions.properties"); Files.createDirectories(target.parent)
            /**
             * Escapes backslashes, controls and non-ASCII characters in known Netty properties metadata.
             *
             * @param value Parsed metadata key/value; keys already have the fixed Netty identifier format.
             * @return ASCII representation for the merged Java properties resource.
             */
            fun escape(value: String): String = buildString {
                value.forEach { c -> when (c) {
                    '\\' -> append("\\\\"); '\n' -> append("\\n"); '\r' -> append("\\r"); '\t' -> append("\\t")
                    else -> if (c.code < 32 || c.code > 126) append("\\u%04x".format(c.code)) else append(c)
                } }
            }
            Files.writeString(target, versions.stringPropertyNames().sorted().joinToString("\n", postfix = "\n") { "${escape(it)}=${escape(versions.getProperty(it))}" })
        }
        require(Files.isRegularFile(directory.resolve("com/microsoft/playwright/Playwright.class"))) { "Playwright Java API is missing." }
    }
}

/**
 * Uses an explicit safe releaseVersion label or dev, avoiding an unqualified legacy artifact name.
 */
val artifactVersion = providers.gradleProperty("releaseVersion").orElse("dev").get()
require(artifactVersion.matches(Regex("[0-9A-Za-z][0-9A-Za-z._-]*"))) { "releaseVersion must be a safe version label." }
version = artifactVersion
/**
 * Packages the selected assets/runtime and verifies the resulting development/release JAR structure.
 *
 * Checks duplicate names, excluded host/test APIs, signatures/descriptors, platform resources,
 * notices and the exact embedded asset-archive digest. This structural gate does not claim live
 * browser, PKCS#11 or real-Burp acceptance; those require their explicit integration gates.
 */
tasks.named<Jar>("jar") {
    dependsOn("prepareBrowserAssets", "assemblePlatformRuntime")
    archiveFileName.set(provider { "browser-powered-session-handler-${project.version}.jar" })
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    duplicatesStrategy = DuplicatesStrategy.FAIL
    manifest.attributes("Multi-Release" to "true")
    from(assembledRuntime); from(generatedAssets)
    doLast {
        java.util.zip.ZipFile(archiveFile.get().asFile).use { jar ->
            val names = jar.entries().asSequence().map { it.name }.toList()
            require(names.toSet().size == names.size) { "Duplicate output JAR entries." }
            require("bpsh/Extension.class" in names) { "Packaged Montoya entry point is missing." }
            require(names.none { '/' !in it && it.endsWith(".class") }) { "Unpackaged or stale default-package classes leaked into the extension JAR." }
            require(names.none { it.startsWith("burp/api/") || it.startsWith("org/junit/") || it.endsWith("module-info.class")
                || it.matches(Regex("META-INF/[^/]+\\.(SF|RSA|DSA|EC)", RegexOption.IGNORE_CASE)) }) { "Host/test APIs, module descriptors or stale signatures leaked into the platform JAR." }
            val retired = setOf("ApiClient", "ApiServiceManager", "LocalTokenCache", "HackvertorTagBuilder", "TokenServiceProtocol")
            require(names.filter { '/' !in it && it.endsWith(".class") }.none { it.substringBefore('$').removeSuffix(".class") in retired }
                && names.none { it.startsWith("org/commonmark/") }) { "Retired runtime classes/dependencies leaked into the native platform JAR." }
            require(names.none { it.startsWith("driver/") }) { "Duplicate driver execution resources leaked into the universal JAR." }
            require(names.any { it.startsWith("META-INF/notices/") }) { "Third-party notices missing." }
            val pairs = names.filter { !it.endsWith("/") && it.startsWith("META-INF/bpsh/") }
            require(pairs.toSet() == supportedTargets.flatMap { listOf("META-INF/bpsh/$it/browser-assets.json", "META-INF/bpsh/$it/browser-assets.zip") }.toSet()) { "Universal target inventory differs." }
            withManifestValidator { validate ->
                supportedTargets.forEach { target ->
                    val raw = jar.getInputStream(jar.getEntry("META-INF/bpsh/$target/browser-assets.json")).use { it.readNBytes((32 shl 20) + 1) }
                    validate(raw, target); val metadata = assetMapper.readTree(raw)
                    val archive = jar.getEntry("META-INF/bpsh/$target/browser-assets.zip") ?: error("Browser archive missing.")
                    require(archive.size == metadata.path("archive").path("bytes").longValue())
                    val digest = MessageDigest.getInstance("SHA-256")
                    jar.getInputStream(archive).use { input ->
                        val buffer = ByteArray(65536)
                        while (true) { val n = input.read(buffer); if (n < 0) break; digest.update(buffer, 0, n) }
                    }
                    require(HexFormat.of().formatHex(digest.digest()) == metadata.path("archive").path("sha256").asText()) { "Packaged asset digest mismatch." }
                }
            }
            logger.lifecycle("Verified universal JAR and all three archive digests: ${archiveFile.get().asFile.name}")
        }
    }
}

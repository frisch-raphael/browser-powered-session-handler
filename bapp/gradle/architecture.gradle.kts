// Feature packages form a directed graph. Keep lower layers independent of their consumers.
val architectureDependencies = mapOf(
    "bpsh" to setOf("browser", "config", "diagnostics", "http", "model", "mtls", "runtime", "secrets", "session", "ui"),
    "bpsh.model" to emptySet(),
    "bpsh.events" to setOf("model"),
    "bpsh.io" to emptySet(),
    "bpsh.secrets" to setOf("model"),
    "bpsh.credentials" to setOf("model"),
    "bpsh.config" to setOf("credentials", "io", "model", "secrets"),
    "bpsh.runtime" to setOf("io", "model"),
    "bpsh.mtls" to setOf("credentials", "model"),
    "bpsh.session" to setOf("config", "credentials", "events", "model"),
    "bpsh.browser" to setOf("config", "credentials", "model", "mtls", "runtime", "secrets", "session"),
    "bpsh.diagnostics" to setOf("config", "model"),
    "bpsh.http" to setOf("browser", "config", "credentials", "diagnostics", "model", "session"),
    "bpsh.ui" to setOf("config", "credentials", "diagnostics", "events", "model", "mtls", "secrets", "session")
).mapValues { (_, dependencies) -> dependencies.map { "bpsh.$it" }.toSet() }

val verifyArchitecture = tasks.register("verifyArchitecture") {
    group = "verification"
    description = "Verify package paths, allowed dependencies and absence of package cycles."
    val sources = fileTree("src/main/java") { include("**/*.java") }
    inputs.files(sources)
    doLast {
        check(sources.files.isNotEmpty()) { "Production source tree is empty." }
        val root = projectDir.resolve("src/main/java").toPath()
        val graph = architectureDependencies.keys.associateWith { mutableSetOf<String>() }
        // Exclude comments and literals so examples and diagnostic labels are not dependencies.
        val nonCode = Regex("\"\"\"[\\s\\S]*?\"\"\"|/\\*[\\s\\S]*?\\*/|//[^\\n]*|\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'")
        val declaration = Regex("(?m)^package\\s+([\\w.]+)\\s*;")
        val references = Regex("\\bbpsh(?:\\.[a-z][A-Za-z0-9_]*)*\\.[A-Z][A-Za-z0-9_]*")
        val wildcardImports = Regex("(?m)^import\\s+(?:static\\s+)?(bpsh(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)\\.\\*\\s*;")
        val failures = mutableListOf<String>()
        sources.files.sortedBy { it.invariantSeparatorsPath }.forEach { file ->
            val code = nonCode.replace(file.readText(), " ")
            val name = declaration.find(code)?.groupValues?.get(1)
            val relative = root.relativize(file.toPath()).toString().replace('\\', '/')
            if (name == null || name !in architectureDependencies) {
                failures += "$relative: missing or unregistered package"
                return@forEach
            }
            if (relative.substringBeforeLast('/') != name.replace('.', '/')) failures += "$relative: package path differs from $name"
            val dependencies = references.findAll(code).map { it.value.substringBeforeLast('.') }.toSet() +
                wildcardImports.findAll(code).map { match ->
                    match.groupValues[1].split('.').takeWhile { it.first().isLowerCase() }.joinToString(".")
                }.toSet()
            dependencies.filter { it != name }.forEach { dependency ->
                if (dependency !in architectureDependencies.getValue(name)) failures += "$relative: $name must not depend on $dependency"
                graph.getValue(name).add(dependency)
            }
            if (name in setOf("bpsh.model", "bpsh.session")) {
                listOf("javax.swing.", "java.awt.", "burp.api.montoya.", "com.microsoft.playwright.").forEach { forbidden ->
                    if (code.contains(forbidden)) failures += "$relative: $forbidden belongs at an adapter boundary"
                }
            }
        }
        val visiting = mutableSetOf<String>()
        val visited = mutableSetOf<String>()
        fun visit(name: String, path: List<String>) {
            if (name in visiting) { failures += "Package cycle: ${(path + name).joinToString(" -> ")}"; return }
            if (!visited.add(name)) return
            visiting.add(name)
            graph[name].orEmpty().sorted().forEach { visit(it, path + name) }
            visiting.remove(name)
        }
        graph.keys.sorted().forEach { visit(it, emptyList()) }
        check(failures.isEmpty()) { failures.distinct().joinToString("\n") }
        logger.lifecycle("Architecture verified: ${sources.files.size} Java files, ${graph.size} packages, no package cycles.")
    }
}

tasks.named("check") { dependsOn(verifyArchitecture) }

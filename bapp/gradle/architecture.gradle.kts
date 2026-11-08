// Feature-owned boundaries. Concrete adapters may depend on core contracts; core never imports adapters.
val architectureDependencies = mapOf(
    "bpsh" to setOf("authentication", "authentication.session", "browser", "browser.mtls", "browser.runtime", "burp.http", "burp.ui", "journey", "journey.editing", "journey.persistence", "request"),
    "bpsh.journey" to emptySet(),
    "bpsh.authentication" to setOf("journey"),
    "bpsh.authentication.credentials" to setOf("journey", "authentication"),
    "bpsh.authentication.session" to setOf("journey", "authentication", "authentication.credentials"),
    "bpsh.request" to setOf("journey", "authentication"),
    "bpsh.platform.files" to emptySet(),
    "bpsh.journey.persistence" to setOf("journey", "authentication", "authentication.credentials", "request", "platform.files"),
    "bpsh.journey.editing" to setOf("journey", "journey.persistence", "request"),
    "bpsh.browser.runtime" to setOf("journey", "authentication", "platform.files"),
    "bpsh.browser.mtls" to setOf("journey", "authentication", "authentication.credentials"),
    "bpsh.browser" to setOf("journey", "authentication", "authentication.credentials", "authentication.session", "browser.runtime", "browser.mtls"),
    "bpsh.burp.http" to setOf("journey", "authentication", "authentication.credentials", "authentication.session", "browser", "request"),
    "bpsh.burp.ui" to setOf("journey", "journey.editing", "journey.persistence", "authentication", "authentication.credentials", "authentication.session", "browser.mtls", "burp.http", "request")
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
            if (name in setOf("bpsh.journey", "bpsh.authentication", "bpsh.authentication.session", "bpsh.authentication.credentials", "bpsh.request")) {
                listOf("javax.swing.", "java.awt.", "burp.api.montoya.", "com.microsoft.playwright.").forEach { forbidden ->
                    if (code.contains(forbidden)) failures += "$relative: $forbidden belongs at an adapter boundary"
                }
            }
            if (name != "bpsh.browser.runtime" && (code.contains("com.microsoft.playwright.impl.") || code.contains("com.google.gson.")))
                failures += "$relative: private Playwright/Gson protocol access belongs in browser.runtime"
        }
        listOf("bpsh.journey", "bpsh.authentication", "bpsh.authentication.session", "bpsh.request").forEach { core ->
            sources.files.filter { it.parentFile.toPath() == root.resolve(core.replace('.', '/')) }.forEach { file ->
                val imports = Regex("(?m)^import\\s+(?:static\\s+)?([^;]+);").findAll(nonCode.replace(file.readText(), " "))
                imports.forEach { imported ->
                    val target = imported.groupValues[1]
                    if (!target.startsWith("java.") && !target.startsWith("bpsh.")) failures += "${file.name}: $target is a framework import in core $core"
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

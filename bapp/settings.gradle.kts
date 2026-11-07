rootProject.name = "browser-powered-session-handler"
// Isolated production captures intentionally configure only the extension project.
if (System.getProperty("authlab.plan") == null) {
    include(":auth-lab", ":federation-client")
    project(":auth-lab").projectDir = file("../test/authentication-lab")
    project(":federation-client").projectDir = file("../test/federation-client")
}

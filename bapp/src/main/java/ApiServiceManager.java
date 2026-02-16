import burp.api.montoya.logging.Logging;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class ApiServiceManager {
    private final Logging logging;
    private final Path apiDir;
    private Process process;

    public ApiServiceManager(Logging logging, String extensionPath) {
        this.logging = logging;
        Path baseDir = null;
        if (extensionPath != null && !extensionPath.isBlank()) {
            baseDir = Paths.get(extensionPath).toAbsolutePath().getParent();
        }
        if (baseDir != null) {
            // extension JAR is under bapp/build/libs; API lives at ../../.. /api
            this.apiDir = baseDir.resolve("..")
                    .resolve("..")
                    .resolve("..")
                    .resolve("api")
                    .normalize()
                    .toAbsolutePath();
        } else {
            this.apiDir = Paths.get("api").toAbsolutePath();
        }
    }

    public synchronized VerificationResult verify(String pythonOverride) {
        List<String> issues = new ArrayList<>();
        List<String> commands = new ArrayList<>();
        String pythonCmd = resolvePython(pythonOverride);

        if (!Files.exists(apiDir)) {
            issues.add("API directory not found: " + apiDir);
        }

        if (pythonCmd == null) {
            issues.add("Python not found on PATH");
            commands.add("python --version");
            commands.add("py --version");
        }

        Path venvPython = venvPythonPath();
        if (!Files.exists(venvPython)) {
            issues.add("Virtual environment not found at " + venvPython);
            if (pythonCmd != null) {
                commands.add(pythonCmd + " -m venv api/venv (from extension root)");
            }
        } else if (!canImport(venvPython, "fastapi", "uvicorn", "playwright")) {
            issues.add("Missing required Python packages in venv");
            commands.add(venvPython + " -m pip install fastapi uvicorn playwright");
            commands.add("PLAYWRIGHT_BROWSERS_PATH=api/browsers " + venvPython + " -m playwright install firefox");
        }
        Path browsersDir = apiDir.resolve("browsers");
        List<Path> firefoxExecutables = findFirefoxExecutables(browsersDir);
        if (firefoxExecutables.isEmpty()) {
            issues.add("Playwright Firefox not found. Expected: " + browsersDir
                    + "\\firefox-*\\firefox\\firefox.exe");
            if (venvPython != null) {
                commands.add("PLAYWRIGHT_BROWSERS_PATH=api/browsers " + venvPython + " -m playwright install firefox");
            }
        }

        if (issues.isEmpty()) {
            return new VerificationResult(true, "API environment looks OK", commands);
        }
        return new VerificationResult(false, String.join("; ", issues), commands);
    }

    public synchronized void install(String pythonOverride, String installProxy)
            throws IOException, InterruptedException {
        if (!Files.exists(apiDir)) {
            throw new IOException("API directory not found: " + apiDir);
        }
        String pythonCmd = resolvePython(pythonOverride);
        if (pythonCmd == null) {
            throw new IOException("Python not found on PATH");
        }
        Path venvPython = venvPythonPath();

        Map<String, String> installEnv = buildInstallEnv(installProxy);

        if (!Files.exists(venvPython)) {
            logging.logToOutput("Creating virtual environment...");
            runCommandWithEnv(installEnv, pythonCmd, "-m", "venv", apiDir.resolve("venv").toString());
        }

        logging.logToOutput("Installing Python dependencies...");
        runPipCommandWithProxySupport(installEnv, venvPython.toString(), installProxy, "install", "--upgrade", "pip");
        runPipCommandWithProxySupport(installEnv, venvPython.toString(), installProxy, "install", "fastapi", "uvicorn",
                "playwright");
        logging.logToOutput("Installing Playwright browsers...");
        Map<String, String> playwrightEnv = new HashMap<>(installEnv);
        playwrightEnv.put("PLAYWRIGHT_BROWSERS_PATH", apiDir.resolve("browsers").toString());
        runCommandWithEnv(playwrightEnv,
                venvPython.toString(), "-m", "playwright", "install", "firefox");
        logging.logToOutput("API install complete");
    }

    public synchronized void start(String pythonOverride) throws IOException {
        logging.logToOutput("Starting token service...");
        if (process != null && process.isAlive()) {
            logging.logToOutput("Token service already running");
            return;
        }
        if (!Files.exists(apiDir)) {
            throw new IOException("API directory not found: " + apiDir);
        }

        Path venvPython = venvPythonPath();
        String pythonCmd = Files.exists(venvPython) ? venvPython.toString() : resolvePython(pythonOverride);
        if (pythonCmd == null) {
            throw new IOException("Python not found on PATH");
        }

        ProcessBuilder pb = new ProcessBuilder(
                pythonCmd,
                "-m",
                "uvicorn",
                "token_service:app",
                "--host",
                "127.0.0.1",
                "--port",
                "7575");
        pb.directory(apiDir.toFile());
        pb.environment().put("PYTHONUNBUFFERED", "1");
        pb.environment().put("PLAYWRIGHT_BROWSERS_PATH", apiDir.resolve("browsers").toString());
        pb.redirectErrorStream(true);
        process = pb.start();

        Thread reader = new Thread(() -> streamToLog(process.getInputStream()), "token-service-stdout");
        reader.setDaemon(true);
        reader.start();

        if (waitForRunning(true, 3000)) {
            logging.logToOutput("Token service started");
        } else {
            logging.logToError("Token service failed to start");
            try {
                process.destroyForcibly();
                process.waitFor();
            } catch (Exception ignored) {
            } finally {
                process = null;
            }
            throw new IOException("Token service failed to start");
        }
    }

    public synchronized void stop() {
        if (process == null) {
            return;
        }
        try {
            process.destroy();
            process.waitFor();
            if (process.isAlive()) {
                process.destroyForcibly();
                process.waitFor();
            }
        } catch (Exception ignored) {
        } finally {
            if (waitForRunning(false, 1000)) {
                logging.logToOutput("Token service stopped");
            } else {
                logging.logToError("Token service did not stop");
            }
            process = null;
        }
    }

    public synchronized boolean isRunning() {
        return process != null && process.isAlive() && isHealthy();
    }

    private String resolvePython(String override) {
        if (override != null && !override.isBlank()) {
            return override.trim();
        }
        if (commandOk("python", "--version")) {
            return "python";
        }
        if (commandOk("python3", "--version")) {
            return "python3";
        }
        if (commandOk("py", "--version")) {
            return "py";
        }
        return null;
    }

    private boolean commandOk(String... command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(apiDir.toFile());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
            return p.exitValue() == 0;
        } catch (Exception ex) {
            return false;
        }
    }

    private boolean canImport(Path python, String... modules) {
        String joined = String.join(",", modules);
        String code = "import " + joined;
        try {
            ProcessBuilder pb = new ProcessBuilder(python.toString(), "-c", code);
            pb.directory(apiDir.toFile());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
            return p.exitValue() == 0;
        } catch (Exception ex) {
            return false;
        }
    }

    private void runCommand(String... command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(apiDir.toFile());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        streamToLog(p.getInputStream());
        int exit = p.waitFor();
        if (exit != 0) {
            logging.logToError("Command failed: " + String.join(" ", command));
            throw new IOException("Command failed: " + String.join(" ", command));
        }
    }

    private Map<String, String> buildInstallEnv(String installProxy) {
        if (installProxy == null || installProxy.isBlank()) {
            return Map.of();
        }
        String proxy = installProxy.trim();
        Map<String, String> env = new HashMap<>();
        env.put("HTTP_PROXY", proxy);
        env.put("HTTPS_PROXY", proxy);
        return env;
    }

    private void runPipCommandWithProxySupport(
            Map<String, String> env,
            String pythonExe,
            String installProxy,
            String... pipArgs) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add(pythonExe);
        cmd.add("-m");
        cmd.add("pip");
        for (String arg : pipArgs) {
            cmd.add(arg);
        }

        if (installProxy != null && !installProxy.isBlank()) {
            // Common fix for corporate/intercepting proxies that re-sign TLS.
            cmd.add("--trusted-host");
            cmd.add("pypi.org");
            cmd.add("--trusted-host");
            cmd.add("files.pythonhosted.org");
            cmd.add("--trusted-host");
            cmd.add("pypi.python.org");
        }

        runCommandWithEnv(env, cmd.toArray(new String[0]));
    }

    private void runCommandWithEnv(Map<String, String> env, String... command)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(apiDir.toFile());
        if (env != null && !env.isEmpty()) {
            pb.environment().putAll(env);
        }
        pb.redirectErrorStream(true);
        Process p = pb.start();
        streamToLog(p.getInputStream());
        int exit = p.waitFor();
        if (exit != 0) {
            logging.logToError("Command failed: " + String.join(" ", command));
            throw new IOException("Command failed: " + String.join(" ", command));
        }
    }

    private void streamToLog(java.io.InputStream stream) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                logging.logToOutput(line);
            }
        } catch (IOException ex) {
            logging.logToError("Failed to read process output: " + ex.getMessage());
        }
    }

    private boolean isHealthy() {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL("http://127.0.0.1:7575/health").openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(1000);
            conn.setReadTimeout(1000);
            int code = conn.getResponseCode();
            return code >= 200 && code < 300;
        } catch (Exception ignored) {
            return false;
        }
    }

    private Path venvPythonPath() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            return apiDir.resolve("venv").resolve("Scripts").resolve("python.exe");
        }
        return apiDir.resolve("venv").resolve("bin").resolve("python");
    }

    private boolean browserInstalled(Path browsersDir) {
        return !findFirefoxExecutables(browsersDir).isEmpty();
    }

    private List<Path> findFirefoxExecutables(Path browsersDir) {
        try {
            if (!Files.isDirectory(browsersDir)) {
                return List.of();
            }
            try (var stream = Files.list(browsersDir)) {
                return stream
                        .filter(path -> path.getFileName().toString().startsWith("firefox-"))
                        .map(path -> path.resolve("firefox").resolve("firefox.exe"))
                        .filter(Files::exists)
                        .collect(Collectors.toList());
            }
        } catch (IOException ex) {
            return List.of();
        }
    }

    public static final class VerificationResult {
        public final boolean ok;
        public final String message;
        public final List<String> commands;

        VerificationResult(boolean ok, String message, List<String> commands) {
            this.ok = ok;
            this.message = message;
            this.commands = commands;
        }
    }

    // Poll process state until it matches the expected running value or timeout is reached.
    private boolean waitForRunning(boolean running, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (isRunning() == running) {
                return true;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return isRunning() == running;
    }
}

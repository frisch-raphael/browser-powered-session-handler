package lab.auth;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Existing private VM helpers are the only transfer/guest-execution boundary. */
public final class LabHostVmTransport {
    @FunctionalInterface interface Runner { void run(List<String> arguments, Duration timeout) throws IOException, InterruptedException; }
    public static final class Failure extends IOException {
        private final String code;
        Failure(String code) { super(code); this.code = code; }
        public String code() { return code; }
    }
    private final Runner runner;
    public LabHostVmTransport() { this(LabHostVmTransport::runPrivate); }
    LabHostVmTransport(Runner runner) { this.runner = Objects.requireNonNull(runner); }

    public void put(LabHostInputs.Vm vm, Path source, String target, Duration timeout) throws IOException, InterruptedException {
        invoke(vm, List.of("put",source.toAbsolutePath().toString(),target),timeout);
    }
    public void get(LabHostInputs.Vm vm, String source, Path target, Duration timeout) throws IOException, InterruptedException {
        invoke(vm, List.of("get",source,target.toAbsolutePath().toString()),timeout);
    }
    public void script(LabHostInputs.Vm vm, String script, Duration timeout) throws IOException, InterruptedException {
        script(vm,script,timeout,false);
    }
    public void interactiveScript(LabHostInputs.Vm vm,String script,Duration timeout) throws IOException,InterruptedException {
        script(vm,script,timeout,true);
    }
    private void script(LabHostInputs.Vm vm,String script,Duration timeout,boolean interactive) throws IOException,InterruptedException {
        if (vm.platform().equals("windows")) {
            String encoded = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_16LE));
            var args=new ArrayList<String>();args.add("run");if(interactive)args.add("-interactive");
            args.addAll(List.of("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-NoProfile","-WindowStyle","Hidden","-EncodedCommand",encoded));
            invoke(vm,args,timeout);
        } else {
            // Avoid Windows argv stripping embedded JSON/Python quotes before the SSH helper receives them.
            String encoded=Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_8));
            invoke(vm,List.of("run","printf %s "+encoded+" | base64 --decode | /bin/bash"),timeout);
        }
    }
    private void invoke(LabHostInputs.Vm vm, List<String> arguments, Duration timeout) throws IOException, InterruptedException {
        long maximum=arguments.getFirst().equals("put")?600:60;
        LabJson.require(timeout.isPositive() && timeout.compareTo(Duration.ofSeconds(maximum)) <= 0,"VM_TIMEOUT_BUDGET");
        var command = new ArrayList<>(List.of("python",vm.helper().toString())); command.addAll(arguments);
        try { runner.run(List.copyOf(command),timeout); }
        catch (Failure failure) { throw failure; }
        catch (IOException | RuntimeException failure) { throw new Failure("VM_OPERATION_FAILED"); }
    }
    static void runPrivate(List<String> arguments, Duration timeout) throws IOException, InterruptedException {
        Process process;
        try {
            process = new ProcessBuilder(arguments).redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        } catch (IOException | RuntimeException failure) { throw new Failure("VM_HELPER_START_FAILED"); }
        try {
            process.getOutputStream().close();
            if (!process.waitFor(timeout.toMillis(),TimeUnit.MILLISECONDS)) {
                stopOwned(process); throw new Failure("VM_OPERATION_TIMEOUT");
            }
            if (process.exitValue() != 0) throw new Failure("VM_OPERATION_FAILED");
        } catch (InterruptedException interrupted) { stopOwned(process); throw interrupted; }
        catch (IOException failure) {
            if (process.isAlive()) stopOwned(process);
            throw failure instanceof Failure fixed ? fixed : new Failure("VM_OPERATION_FAILED");
        }
    }
    private static void stopOwned(Process process) {
        var children = process.descendants().map(p -> Map.entry(p,p.info().startInstant())).toList().reversed();
        for (var child : children) if (child.getValue().isPresent() && child.getKey().info().startInstant().equals(child.getValue()))
            child.getKey().destroyForcibly();
        if (process.isAlive()) process.destroyForcibly();
    }
    public static String shellQuote(String value) { return "'" + value.replace("'","'\"'\"'") + "'"; }
    public static String powershellQuote(String value) { return "'" + value.replace("'","''") + "'"; }
    static String joinGuest(String root, String relative, String platform) {
        LabJson.relative(new com.google.gson.JsonPrimitive(relative));
        String separator = platform.equals("windows") ? "\\" : "/";
        return root.replaceAll("[\\\\/]+$", "") + separator + relative.replace("/",separator);
    }
}

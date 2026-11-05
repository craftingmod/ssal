package dev.ssal.probe;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.NoSuchFileException;
import java.util.concurrent.TimeUnit;

/** No Framework services: the controller observes this process before releasing it. */
public final class ForkProbe {
    private static String readAll(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int count;
        while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
        return new String(output.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String run(String... command) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
        builder.environment().remove("LD_PRELOAD");
        Process process = builder.start();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            process.waitFor();
            throw new IllegalStateException("child command timed out: " + command[0]);
        }
        String output = readAll(process.getInputStream());
        if (process.exitValue() != 0) {
            throw new IllegalStateException(command[0] + " failed: " + output);
        }
        return output.trim();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("no probe arguments expected");
        Path session = Paths.get("/run/ssal/fork-probe");
        for (String name : new String[] {"stat", "status", "cgroup", "attr/current"}) {
            Files.write(session.resolve(name.replace('/', '-')),
                    Files.readAllBytes(Paths.get("/proc/self/" + name)));
        }
        StringBuilder namespaces = new StringBuilder();
        for (String name : new String[] {"mnt", "net", "pid", "user", "uts", "ipc", "cgroup"}) {
            namespaces.append(name).append('=');
            try {
                namespaces.append(Files.readSymbolicLink(Paths.get("/proc/self/ns/" + name)));
            } catch (NoSuchFileException absent) {
                namespaces.append("unavailable");
            }
            namespaces.append('\n');
        }
        Files.write(session.resolve("namespaces"), namespaces.toString().getBytes(StandardCharsets.UTF_8));
        if ("1".equals(System.getenv("SSAL_PHASE7I_PROPERTIES"))) {
            String sdk = run("/system/bin/getprop", "ro.build.version.sdk");
            String persist = run("/system/bin/getprop", "persist.ssal_probe");
            if (!"36".equals(sdk) || !"7".equals(persist)) {
                throw new IllegalStateException("Guest properties differ: sdk=" + sdk + " persist=" + persist);
            }
            Files.write(session.resolve("properties.txt"),
                    ("sdk=" + sdk + "\npersist.ssal_probe=" + persist + "\n").getBytes(StandardCharsets.UTF_8));
            String binder = run("/run/ssal/phase3-ipc", "client");
            if (!binder.contains("\"event\":\"ipc_passed\"")) {
                throw new IllegalStateException("Guest Private Binder call failed: " + binder);
            }
            Files.write(session.resolve("binder.txt"), binder.getBytes(StandardCharsets.UTF_8));
            Path dataFile = Paths.get(new String(Files.readAllBytes(session.resolve("data-probe-path")),
                    StandardCharsets.UTF_8).trim());
            if (!"guest-userdata-v1".equals(new String(Files.readAllBytes(dataFile), StandardCharsets.UTF_8))) {
                throw new IllegalStateException("Guest userdata marker mismatch");
            }
            Files.write(dataFile.getParent().resolve("java-child"),
                    "Java child reached Guest userdata\n".getBytes(StandardCharsets.UTF_8));
            Files.write(session.resolve("integration"),
                    "property=PASS private_binder=PASS userdata_read_write=PASS\n".getBytes(StandardCharsets.UTF_8));
        }
        Files.write(session.resolve("ready"), "SSAL_FORK_PROBE_READY\n".getBytes(StandardCharsets.UTF_8));
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (!new File("/run/ssal/fork-probe/release").exists()) {
            if (System.nanoTime() >= deadline) throw new IllegalStateException("controller timeout");
            Thread.sleep(20);
        }
        Files.write(session.resolve("completed"), "SSAL_FORK_PROBE_EXIT=0\n".getBytes(StandardCharsets.UTF_8));
        System.exit(0);
    }
}

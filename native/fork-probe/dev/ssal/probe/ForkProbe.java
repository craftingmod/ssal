package dev.ssal.probe;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.NoSuchFileException;

/** No Framework services: the controller observes this process before releasing it. */
public final class ForkProbe {
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

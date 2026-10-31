import { mkdir, rename, stat } from "node:fs/promises"
import { createReadStream } from "node:fs"
import { createHash, randomUUID } from "node:crypto"
import { resolve, relative, join } from "node:path"
import { parseArgs } from "node:util"

const { values } = parseArgs({
  args: Bun.argv.slice(2),
  options: { profile: { type: "string", default: "profile1" }, serial: { type: "string" }, help: { type: "boolean" } },
  strict: true,
})
if (values.help) {
  console.log("bun run selinux:check [--profile profile1] [--serial ADB_SERIAL]\nQueries only; requires adb root via su and the running ssal-dev container.\nCaches a hash-verified copy of the registered raw ext4 image; writes out/selinux-check/<run>/report.json.")
  process.exit(0)
}
const profile = values.profile!
if (!/^[A-Za-z0-9_-]{1,64}$/.test(profile)) throw new Error("Invalid profile name")
const workspace = resolve(import.meta.dir, "..")
process.chdir(workspace)
const runId = new Date().toISOString().replace(/[:.]/g, "-") + "-" + randomUUID().slice(0, 8)
const folder = join(workspace, "out", "selinux-check", runId)
await mkdir(folder, { recursive: true })
const linuxPath = (path: string) => {
  const local = relative(workspace, path)
  if (local.startsWith("..") || resolve(workspace, local) !== resolve(path)) throw new Error("Path outside workspace")
  return "/src/" + local.replaceAll("\\", "/")
}
const adb = ["adb", ...(values.serial ? ["-s", values.serial] : [])]
const logs: object[] = []
const quote = (s: string) => "'" + s.replaceAll("'", "'\"'\"'") + "'"
async function command(argv: string[], outputFile?: string, required = true) {
  const process = Bun.spawn(argv, { cwd: workspace, stdin: "ignore", stdout: outputFile ? Bun.file(outputFile) : "pipe", stderr: "pipe" })
  const stderrPromise = new Response(process.stderr).text()
  const stdoutPromise = outputFile ? Promise.resolve("") : new Response(process.stdout as ReadableStream<Uint8Array>).text()
  const [exitCode, stdout, stderr] = await Promise.all([process.exited, stdoutPromise, stderrPromise])
  const result = { command: argv, exit_code: exitCode, stdout, stderr }
  logs.push({ ...result, output_file: outputFile })
  if (required && exitCode) throw new Error(`${argv[0]} exited ${exitCode}: ${stderr || stdout}`)
  return result
}
// Use shell-v2 exit status for text commands. Windows adb shell can translate
// newlines, so binary exports use exec-out and are checked by hashes/parsers.
const root = (text: string, output?: string, required = true) => command(
  [...adb, ...(output ? ["exec-out"] : ["shell", "-T"]), "su -c " + quote(text)], output, required)
const container = (...args: string[]) => command(["wslc", "exec", "ssal-dev", ...args])
async function sha256(path: string) {
  const hash = createHash("sha256")
  for await (const chunk of createReadStream(path)) hash.update(chunk)
  return hash.digest("hex")
}
async function observe(suffix: string) {
  const [processes, resources] = await Promise.all([
    root("ps -A -o PID,NAME,LABEL"),
    root("sha256sum /proc/1/mountinfo /data/adb/modules/ssal/sepolicy.rule"),
  ])
  const names = new Set(["init", "servicemanager", "zygote64", "zygote_next", "system_server", "surfaceflinger", "vold", "installd", "artd"])
  const selected = processes.stdout.split(/\r?\n/).map(s => s.trim()).filter(line => names.has(line.split(/\s+/)[1] ?? "")).sort()
  if (!selected.some(line => line.split(/\s+/)[1] === "init")) throw new Error("Cannot observe Host init")
  if (!/^[a-f0-9]{64}\s/m.test(resources.stdout)) throw new Error("Cannot observe Host resource hashes")
  await Bun.write(join(folder, `host-observation-${suffix}.txt`), JSON.stringify({ processes: selected, resources: resources.stdout.trim() }, null, 2) + "\n")
}

const scratch = "/data/local/tmp/ssal-selinux-check-" + runId
let scratchCreated = false
try {
  console.log(`Checking SELinux tools and registered image...\nArtifacts: ${folder}`)
  const tools = await container("dpkg-query", "-W", "secilc", "checkpolicy", "setools", "m4")
  await Bun.write(join(folder, "tools.txt"), tools.stdout)
  const profileInfo = JSON.parse((await root(`cat /data/local/ssal/guests/${profile}/profile.json`)).stdout)
  const imageId = profileInfo.image_id
  if (typeof imageId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(imageId)) throw new Error("Invalid image ID in profile")
  const manifestText = (await root(`cat /data/local/ssal/images/${imageId}/manifest.json`)).stdout
  const manifest = JSON.parse(manifestText)
  if (manifest.format !== "raw-ext4" || !/^[a-f0-9]{64}$/.test(manifest.sha256) || !Number.isSafeInteger(manifest.size) || manifest.size <= 0) throw new Error("Unsupported image manifest")
  await Bun.write(join(folder, "image-manifest.json"), manifestText)
  const cache = join(workspace, ".cache", "selinux-images")
  await mkdir(cache, { recursive: true })
  const image = join(cache, manifest.sha256 + ".img")
  const imageStat = await stat(image).catch(() => null)
  if (!imageStat || imageStat.size !== manifest.size) {
    console.log(`Copying registered system image (${manifest.size} bytes) to local cache...`)
    const partial = image + "." + runId + ".partial"
    await root(`cat /data/local/ssal/images/${imageId}/system.img`, partial)
    if ((await stat(partial)).size !== manifest.size || await sha256(partial) !== manifest.sha256) throw new Error("Copied image does not match manifest")
    await rename(partial, image)
  } else if (await sha256(image) !== manifest.sha256) {
    throw new Error("Cached image hash mismatch; remove the cache file and retry")
  }
  console.log("Exporting Host policy files and analyzing Guest CIL without mounting the image...")
  await observe("before")
  await root("tar -cf - -C / system/etc/selinux system_ext/etc/selinux product/etc/selinux vendor/etc/selinux odm/etc/selinux", join(folder, "host-selinux.tar"))
  const offline = await container("python3", "scripts/check-selinux.py", "prepare", linuxPath(folder), "--image", linuxPath(image))
  console.log(offline.stdout.trim())
  const helper = join(folder, "selinux-query")
  await container("/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang", "-std=c11", "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIE", "-pie", "native/selinux-query/main.c", "-o", linuxPath(helper))
  await command([...adb, "shell", `mkdir -m 700 ${scratch}`])
  scratchCreated = true
  try {
    await command([...adb, "push", helper, scratch + "/query"])
    await command([...adb, "push", join(folder, "queries.tsv"), scratch + "/queries.tsv"])
    await command([...adb, "shell", `chmod 700 ${scratch}/query`])
    const fallback = join(folder, "device-compile-inputs.tar")
    if (await Bun.file(fallback).exists()) {
      console.log("Comparing with the device's Android CIL compiler in temporary scratch; generated policies are never loaded...")
      await command([...adb, "push", fallback, scratch + "/inputs.tar"])
      await root(`cd ${scratch} && tar -xf inputs.tar && /system/bin/sh compile.sh`)
      await root(`cat ${scratch}/results.tar`, join(folder, "device-compile-results.tar"))
      const compiler = await root("sha256sum /system/bin/secilc")
      await Bun.write(join(folder, "android-compiler.txt"), compiler.stdout)
    }
    console.log("Querying current kernel contexts and AV decisions; no services or policy patches...")
    await root(`${scratch}/query ${scratch}/queries.tsv`, join(folder, "live.jsonl"))
  } finally {
    const cleanup = await command([...adb, "shell", `rm -f ${scratch}/query ${scratch}/queries.tsv ${scratch}/inputs.tar ${scratch}/compile.sh ${scratch}/input-*.cil ${scratch}/*.policy ${scratch}/*.log ${scratch}/*.rc ${scratch}/results.tar && rmdir ${scratch} && test ! -e ${scratch}`], undefined, false)
    await Bun.write(join(folder, "cleanup.json"), JSON.stringify({ scratch_removed: cleanup.exit_code === 0, stderr: cleanup.stderr }, null, 2))
    if (cleanup.exit_code) throw new Error(`Scratch cleanup failed: ${scratch}`)
    scratchCreated = false
  }
  await observe("after")
  const summary = await container("python3", "scripts/check-selinux.py", "finish", linuxPath(folder))
  const reportPath = join(folder, "report.json")
  const report = await Bun.file(reportPath).json()
  report.run = {
    time_utc: new Date().toISOString(), profile, tools: tools.stdout.trim(),
    helper_sha256: await sha256(helper), helper_source_sha256: await sha256(join(workspace, "native/selinux-query/main.c")),
    controller_source_sha256: await sha256(join(workspace, "scripts/check-selinux.ts")),
    analyzer_source_sha256: await sha256(join(workspace, "scripts/check-selinux.py")),
    android_compiler: await Bun.file(join(folder, "android-compiler.txt")).exists() ? (await Bun.file(join(folder, "android-compiler.txt")).text()).trim() : null,
    image_sha256_verified: manifest.sha256,
  }
  await Bun.write(reportPath, JSON.stringify(report, null, 2) + "\n")
  const plan = await container("python3", "scripts/plan-selinux.py", linuxPath(reportPath))
  console.log(plan.stdout.trim())
  await Bun.write(join(workspace, "out", "selinux-check", "latest.json"), JSON.stringify({ report: relative(workspace, reportPath).replaceAll("\\", "/"), overall: report.overall }, null, 2) + "\n")
  console.log(summary.stdout.trim())
  console.log(`Report: ${reportPath}\nA completed query does not certify Android service startup.`)
} finally {
  await Bun.write(join(folder, "commands.json"), JSON.stringify(logs, null, 2) + "\n")
  if (scratchCreated) console.error(`Device scratch may remain: ${scratch}`)
}

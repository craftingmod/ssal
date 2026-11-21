import { existsSync } from "node:fs"
import { spawnSync } from "node:child_process"

const zipPath = "out/ssal-module.zip"
const remoteZip = "/data/local/tmp/ssal-module.zip"
const moduleDir = "/data/adb/modules/ssal"

if (!existsSync(zipPath)) {
  console.error(`Missing ${zipPath}; run "bun run build" or "bun run package" first.`)
  process.exit(1)
}

function run(cmd: string, args: string[]): void {
  const res = spawnSync(cmd, args, { stdio: "inherit" })
  if (res.status !== 0) {
    process.exit(res.status ?? 1)
  }
}

run("adb", ["push", zipPath, remoteZip])

const remoteScript = [
  "set -e",
  `[ -d ${moduleDir} ] || { echo 'Module directory not found: ${moduleDir}' >&2; exit 1; }`,
  `if [ -x ${moduleDir}/bin/ssal ] && ${moduleDir}/bin/ssal status >/dev/null 2>&1; then`,
  `  ${moduleDir}/bin/ssal stop-for-restart`,
  "  i=0",
  "  while [ \"$i\" -lt 50 ] && pidof ssald >/dev/null 2>&1; do sleep 0.1; i=$((i + 1)); done",
  "  if pidof ssald >/dev/null 2>&1; then echo 'ssald did not stop' >&2; exit 1; fi",
  "fi",
  `unzip -oq ${remoteZip} -d ${moduleDir}`,
  `rm -f ${remoteZip}`,
  `chmod 0755 ${moduleDir}/*.sh ${moduleDir}/bin/*`,
  `sh ${moduleDir}/restart.sh`,
  `${moduleDir}/bin/ssal status`,
].join("\n")

run("adb", ["shell", "su", "-c", remoteScript])

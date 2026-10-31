import { resolve, relative } from "node:path"
import { parseArgs } from "node:util"

const { values } = parseArgs({ args: Bun.argv.slice(2), options: {
  report: { type: "string" }, help: { type: "boolean" },
} })
if (values.help) {
  console.log("bun run selinux:plan [--report out/selinux-check/<run>/report.json]\nUses the latest saved report by default. No adb/device access or policy application.")
  process.exit(0)
}
const root = resolve(import.meta.dir, "..")
process.chdir(root)
const report = resolve(root, values.report ?? (await Bun.file("out/selinux-check/latest.json").json()).report)
const local = relative(root, report)
if (local.startsWith("..") || local.startsWith("\\") || /^[A-Za-z]:/.test(local)) throw new Error("Report must be inside the workspace")
if (!await Bun.file(report).exists()) throw new Error("Saved report not found")
const child = Bun.spawn(["wslc", "exec", "ssal-dev", "python3", "scripts/plan-selinux.py", "/src/" + local.replaceAll("\\", "/")], {
  cwd: root, stdin: "ignore", stdout: "inherit", stderr: "inherit",
})
const code = await child.exited
if (code) throw new Error(`SELinux plan generation failed: ${code}`)

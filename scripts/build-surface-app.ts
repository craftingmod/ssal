import { fileURLToPath } from "node:url"

const cwd = fileURLToPath(new URL("../android-surface", import.meta.url))
const args = process.argv.slice(2)
const tasks = args.length > 0 ? args : [":app:assembleDebug"]
const command =
  process.platform === "win32"
    ? ["cmd.exe", "/c", "gradlew.bat", ...tasks]
    : ["./gradlew", ...tasks]

const child = Bun.spawn(command, {
  cwd,
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
})
process.exit(await child.exited)

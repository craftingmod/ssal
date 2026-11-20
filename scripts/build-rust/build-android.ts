import { fileURLToPath } from "node:url"
import { buildCommand } from "./common"

if (import.meta.main) {
  const target = process.argv.slice(2).join(" ")
  if (!["src", "services", "native", "clean"].includes(target)) {
    throw new Error("Usage: bun scripts/build-rust/build-android.ts <src|services|native|clean>")
  }
  const args = ["bash", "scripts/build-rust/build-android.sh", target]
  if (process.env.SSAL_GUEST_LIB_DIR) args.unshift("env", `SSAL_GUEST_LIB_DIR=${process.env.SSAL_GUEST_LIB_DIR}`)
  const command = buildCommand(process.platform, args)
  const child = Bun.spawn(command, {
    cwd: fileURLToPath(new URL("../../", import.meta.url)),
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  })
  process.exit(await child.exited)
}

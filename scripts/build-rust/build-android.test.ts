import { expect, test } from "bun:test"
import { fileURLToPath } from "node:url"
import { buildCommand } from "./common"

for (const target of ["src", "services", "native", "clean"]) {
  test(`${target}: Windows uses WSLc, Linux uses native bash`, () => {
    const command = ["bash", "scripts/build-rust/build-android.sh", target]
    expect(buildCommand("win32", command)).toEqual([
      "wslc", "exec", "--workdir", "/src", "ssal-dev", ...command,
    ])
    expect(buildCommand("linux", command)).toEqual(command)
  })
}

test("reject unsupported platforms and build targets", () => {
  expect(() => buildCommand("darwin", ["cargo", "build"])).toThrow("Unsupported build platform")
  for (const target of ["", "all", "src services", "invalid"]) {
    const child = Bun.spawnSync([process.execPath, fileURLToPath(new URL("./build-android.ts", import.meta.url)), target])
    expect(child.exitCode).not.toBe(0)
    expect(child.stderr.toString()).toContain("Usage:")
  }
})

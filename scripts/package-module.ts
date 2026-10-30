import { readFile, readdir, writeFile, rename } from "node:fs/promises"
import { join } from "node:path"
import AdmZip from "adm-zip"
import { existsSync } from "node:fs"
import { createHash } from "node:crypto"

// Keep ZIP metadata deterministic, including the Unix executable permissions.
const entries: { name: string; path: string; mode: number }[] = [
  ...[
    "module.prop",
    "sepolicy.rule",
    "skip_mount",
    "service.sh",
    "post-fs-data.sh",
    "customize.sh",
    "uninstall.sh",
    "restart.sh",
    "profiles/mounts/initial.json",
    "profiles/services/initial.json",
  ].map((name) => ({
    name,
    path: `module/${name}`,
    mode: name.endsWith(".sh") ? 0o100755 : 0o100644,
  })),
  ...["ssal", "ssald", "ssal-selinux-identity"].map((name) => ({
    name: `bin/${name}`,
    path: `out/bin/${name}`,
    mode: 0o100755,
  })),
]
if (existsSync("out/bin/ssal-binder-probe") || existsSync("out/bin/ssal-binder-probe.json")) {
  const manifest = JSON.parse(await readFile("out/bin/ssal-binder-probe.json", "utf8"))
  for (const [key, path] of [
    ["helper_sha256", "out/bin/ssal-binder-probe"],
    ["source_sha256", "native/binder-probe/main.cpp"],
    ["build_script_sha256", "scripts/build-binder-probe.sh"],
  ] as const) {
    const digest = createHash("sha256").update(await readFile(path)).digest("hex")
    if (manifest[key] !== digest) throw new Error(`Stale Binder helper: ${path}; rebuild before packaging`)
  }
  if (manifest.header_revision !== "android-16.0.0_r2") throw new Error("Unsupported Binder helper header revision")
  entries.push(
    { name: "bin/ssal-binder-probe", path: "out/bin/ssal-binder-probe", mode: 0o100755 },
    { name: "bin/ssal-binder-probe.json", path: "out/bin/ssal-binder-probe.json", mode: 0o100644 },
    { name: "NOTICE.binder-probe", path: "native/binder-probe/NOTICE", mode: 0o100644 },
    { name: "LICENSE.binder-probe", path: "native/binder-probe/LICENSE.apache-2.0", mode: 0o100644 },
  )
}
async function addWeb(dir: string, prefix = "webroot"): Promise<void> {
  for (const entry of (await readdir(dir, { withFileTypes: true })).sort(
    (a, b) => a.name.localeCompare(b.name),
  )) {
    const name = `${prefix}/${entry.name}`
    if (entry.isDirectory()) await addWeb(join(dir, entry.name), name)
    else if (entry.isFile())
      entries.push({ name, path: join(dir, entry.name), mode: 0o100644 })
    else throw new Error(`Unsupported webroot entry: ${name}`)
  }
}
await addWeb("out/webroot")
if (!entries.some((entry) => entry.name === "webroot/index.html"))
  throw new Error("Missing webroot/index.html")
const zip = new AdmZip()
for (const entry of entries) {
  const member = zip.addFile(
    entry.name,
    await readFile(entry.path),
    "",
    entry.mode,
  )
  member.header.made = 0x0314
  member.header.time = new Date(2020, 0, 1)
}
await writeFile("out/ssal-module.tmp", zip.toBuffer())
await rename("out/ssal-module.tmp", "out/ssal-module.zip")
console.log("out/ssal-module.zip")

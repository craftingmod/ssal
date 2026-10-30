import { readFile, readdir, writeFile, rename } from "node:fs/promises"
import { join } from "node:path"
import AdmZip from "adm-zip"

// Keep ZIP metadata deterministic, including the Unix executable permissions.
const entries: { name: string; path: string; mode: number }[] = [
  ...[
    "module.prop",
    "skip_mount",
    "service.sh",
    "post-fs-data.sh",
    "customize.sh",
    "uninstall.sh",
    "restart.sh",
  ].map((name) => ({
    name,
    path: `module/${name}`,
    mode: name.endsWith(".sh") ? 0o100755 : 0o100644,
  })),
  ...["ssal", "ssald"].map((name) => ({
    name: `bin/${name}`,
    path: `out/bin/${name}`,
    mode: 0o100755,
  })),
]
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

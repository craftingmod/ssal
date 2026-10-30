import { cp, mkdir, rm } from "node:fs/promises"

await rm("out/webroot", { recursive: true, force: true })
await mkdir("out/webroot", { recursive: true })
const result = await Bun.build({
  entrypoints: ["frontend/main.ts"],
  outdir: "out/webroot",
  minify: true,
  target: "browser",
})
if (!result.success) throw new AggregateError(result.logs, "WebUI build failed")
await cp("frontend/index.html", "out/webroot/index.html")
await cp("frontend/style.css", "out/webroot/style.css")

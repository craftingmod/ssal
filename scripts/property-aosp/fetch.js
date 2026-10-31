import {readFileSync,existsSync,mkdirSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';import {dirname} from 'node:path';
const manifest=JSON.parse(readFileSync('scripts/property-aosp/sources.json','utf8'));const root='out/guest-property-validation-v2/aosp/';
for(const [path,hash] of Object.entries(manifest)){const dest=root+path;if(!existsSync(dest)){const r=await fetch('https://raw.githubusercontent.com/aosp-mirror/platform_system_core/android-16.0.0_r2/'+path);if(!r.ok)throw Error(`fetch ${path}: ${r.status}`);mkdirSync(dirname(dest),{recursive:true});writeFileSync(dest,Buffer.from(await r.arrayBuffer()));}const got=createHash('sha256').update(readFileSync(dest)).digest('hex');if(got!==hash)throw Error(`source hash mismatch ${path}`);}
console.log(`Verified ${Object.keys(manifest).length} pinned AOSP sources`);

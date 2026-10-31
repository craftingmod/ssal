import {mkdirSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const files = {
 'libc/system_properties/prop_area.cpp':'43de5c91c78398d3c5f7f22695ac771509cd3993a8d418f05b9260bc01017959',
 'libc/system_properties/prop_info.cpp':'50b283367065b44370a992d10930b6cf3147b378577d97a85bfff7927f965aba',
 'libc/system_properties/include/system_properties/prop_area.h':'07da2d23f543533d840f96b4ed6c37ab3a9ec1e5149358767b822bfd158b6101',
 'libc/system_properties/include/system_properties/prop_info.h':'5055c2f07cf3c211d3722371a1bf2d1128ef6c66f461fd276f20f631ca6689f0',
};
const dir='out/property-area-prototype/source'; mkdirSync(dir,{recursive:true});
for (const [path, hash] of Object.entries(files)) {
 const file=dir+'/'+path.split('/').pop();
 const r=await fetch('https://raw.githubusercontent.com/aosp-mirror/platform_bionic/android-16.0.0_r2/'+path);
 if (!r.ok) throw Error(`fetch ${path}: ${r.status}`);
 const data=Buffer.from(await r.arrayBuffer());
 if(createHash('sha256').update(data).digest('hex')!==hash) throw Error(`hash mismatch: ${path}`);
 writeFileSync(file,data);
}
console.log('Verified four Android 16 r2 Bionic sources');

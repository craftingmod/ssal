import {run,parseContexts,lookup} from './validate-guest-properties.js';
import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const j=run(), input=['plat','system_ext','vendor','product','odm'].map(k=>j.inputs[k]).filter(x=>x.status==='available').map(x=>x.path);
const entries=input.flatMap(p=>parseContexts(readFileSync(p,'utf8'),p).entries);
const names=[...new Set([...j.properties.candidates.map(x=>x.name),...entries.map(e=>e.name+(e.match==='prefix'?'ssal_probe':'')), 'ssal.unmatched'])];
writeFileSync('out/guest-property-validation-v2/queries.txt',names.join('\n')+'\n');
const proc=spawnSync('out/guest-property-validation-v2/aosp-harness.exe',['out/guest-property-validation-v2/queries.txt',...input],{encoding:'utf8',maxBuffer:20*1024*1024});if(proc.status!==0)throw Error(proc.stderr);
writeFileSync('out/guest-property-validation-v2/aosp-output.tsv',proc.stdout);
const rows=proc.stdout.split(/\r?\n/).map(x=>x.split('\t'));
const aospEntries=rows.filter(x=>x[0]==='ENTRY'); const contexts=rows.filter(x=>x[0]==='CONTEXT').map(x=>x[1]);
const diffs=rows.filter(x=>x[0]==='LOOKUP').flatMap(x=>{let js=lookup(entries,x[1]);let jstype=js.type||'string';return js.context===x[2]&&jstype===x[3]?[]:[{name:x[1],js:{context:js.context,type:jstype},aosp:{context:x[2],type:x[3]}}]});
const parsed=entries.map(e=>[e.name,e.context,e.match,e.type].join('\t'));
const entryDiff=aospEntries.map(x=>x.slice(1).join('\t')).filter((x,i)=>x!==parsed[i]);
j.aosp_comparison={status:'completed',source:'android-16.0.0_r2',scope:'in-memory serializer, text parser and serialized-trie lookup; Windows shim; no property area',build:rows.find(x=>x[0].startsWith('BUILD_')),aosp_entry_count:aospEntries.length,js_entry_count:entries.length,entry_difference_count:entryDiff.length+Math.abs(aospEntries.length-parsed.length),lookup_count:names.length,lookup_differences:diffs,serialized_context_count:contexts.length,parse_errors:rows.filter(x=>x[0]==='ERROR')};
j.provenance={host_connection:'no_adb_device',host_snapshot:'out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef',firmware_fingerprint:'samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys',fingerprint_source:'profile1 configuration in snapshot commands.json; correspondence to current device unknown',device_model:'SM-S937N',firmware_image_sha256:'unknown',guest_image_sha256:'7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff',guest_hash_source:'previous record, not reverified',aosp_source_hashes:JSON.parse(readFileSync('scripts/property-aosp/sources.json','utf8'))};
const inventoryPath='out/guest-property-validation-v2/host/input-inventory.json';
if(existsSync(inventoryPath)){const device=JSON.parse(readFileSync(inventoryPath,'utf8'));j.provenance.host_connection=device.adb.transport;j.provenance.fingerprint_source='current read-only ADB getprop; prior profile fingerprint matches';j.provenance.firmware_fingerprint=device.device.ro_build_fingerprint;j.provenance.device_model=device.device.model;j.provenance.host_inventory=inventoryPath;j.provenance.vendor_build_fingerprint=device.device.ro_vendor_build_fingerprint;j.provenance.odm_build_fingerprint=device.device.ro_odm_build_fingerprint;}
j.contract={context_inputs:'platform, system_ext, vendor, product, odm in this order; do not serialize duplicate match/name',selinux:'12 previous EINVAL labels are serialized in this partial AOSP trie; revalidate each in actual guest service context and filesystem',boot:'deny direct host DT/cmdline/bootconfig by default; explicit reviewed values before first ro write',build:'use guest build inputs with source-specific permission/type checks and AOSP precedence; host vendor/odm inputs require explicit decisions',persist:'guest-owned userdata and property store; do not import host persisted values',control:'ctl.* and sys.powerctl must never forward to host; guest-only controller or reject',area_socket:'guest-owned area and sockets, no inherited host handles; actual isolation not_run',minimal_values:'unknown; property candidates are not an approved allowlist'};
for(let x of j.context.invalid_12){x.serialized=contexts.includes(x.label);x.serialized_status=contexts.includes(x.label)?'observed_in_local_aosp_trie':'not_observed_in_local_aosp_trie';}
writeFileSync('out/guest-property-validation-v2/result.json',JSON.stringify(j,null,2)+'\n');console.log(JSON.stringify({...j.aosp_comparison,lookup_differences:diffs.slice(0,10)},null,2));

if (entryDiff.length || aospEntries.length!==parsed.length || diffs.length || !j.aosp_comparison.build || j.aosp_comparison.build[0]!=='BUILD_OK') process.exitCode=1;


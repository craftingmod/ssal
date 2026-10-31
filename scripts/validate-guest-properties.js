import {readFileSync, existsSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

export function parseContexts(text, source) {
  const entries=[], errors=[];
  text.split(/\r?\n/).forEach((raw,i)=>{
    const line=raw.trim(); if(!line || line.startsWith('#')) return;
    const [name,context,op,...types]=line.split(/\s+/); const type=types.join(' ');
    const validType=!types.length || (types[0]==='enum' ? types.length>1 : types.length===1 && ['string','bool','int','uint','double','size'].includes(types[0]));
    if(!context || (op && !['exact','prefix'].includes(op)) || !validType) { errors.push({source,line:i+1,text:line}); return; }
    entries.push({name,context,match:op==='exact'?'exact':'prefix',type,source,line:i+1});
  }); return {entries,errors};
}
export function duplicates(entries) {
  const seen=new Map(), result=[];
  for(const e of entries) { const key=e.match+'\0'+e.name; const prev=seen.get(key); if(prev) result.push({name:e.name,match:e.match,kind:prev.context===e.context && prev.type===e.type?'duplicate':'conflict',first:prev,second:e}); else seen.set(key,e); }
  return result;
}
export function lookup(entries,name) {
  let context='u:object_r:default_prop:s0', type='string', matched=null;
  const parts=name.split('.'); let node='';
  for(let i=0;i<parts.length;i++) {
    if(node) { const dotted=entries.find(e=>e.match==='prefix' && e.name===node); if(dotted){if(dotted.context){context=dotted.context;matched=dotted;} if(dotted.type)type=dotted.type;} }
    const remainder=parts.slice(i).join('.');
    const prefixes=entries.filter(e=>e.match==='prefix' && !e.name.endsWith('.') && e.name.startsWith(node) && !e.name.slice(node.length).includes('.') && remainder.startsWith(e.name.slice(node.length))).sort((a,b)=>b.name.length-a.name.length);
    if(prefixes.length){const e=prefixes[0];if(e.context){context=e.context;matched=e;}if(e.type)type=e.type;}
    const child=node+parts[i]+'.';
    if(i===parts.length-1 || !entries.some(e=>e.name.startsWith(child))) {
      const exact=entries.find(e=>e.match==='exact' && e.name===name);
      if(exact){if(exact.context){context=exact.context;matched=exact;}if(exact.type)type=exact.type;}
      break;
    }
    node=child;
  }
  return {...(matched || {source:'AOSP default',match:'default'}),context,type};
}
export function mergeProps(files, initial={}) {
  const map={}, changes=[], ignored=[], imports=[];
  for(const file of files) file.text.split(/\n/).forEach((raw,i)=>{
    const s=raw.trim(); if(!s || s.startsWith('#')) return;
    if(s.startsWith('import ')){imports.push({source:file.source,line:i+1,text:s,status:'unknown'});return;}
    const pos=s.indexOf('='); if(pos<0)return;
    const name=s.slice(0,pos).trim(), value=s.slice(pos+1).trim();
    if(name.startsWith('ctl.') || ['sys.powerctl','selinux.restorecon_recursive'].includes(name)) {ignored.push({name,source:file.source,line:i+1});return;}
    const entry={name,value,source:file.source,line:i+1};
    if(map[name]) changes.push({name,previous:map[name],next:entry,kind:map[name].value===value?'duplicate':'override'});
    map[name]=entry;
  });
  const applied={}, rejected=[];
  for(const [name,e] of Object.entries(map)) {if(name.startsWith('ro.') && Object.hasOwn(initial,name)) rejected.push({name,existing:initial[name],candidate:e,reason:'write_once'}); else applied[name]=e;}
  return {map,changes,ignored,imports,applied,rejected};
}
export function checkRequired(names, map, complete) { return names.map(name=>({name,status:map[name]?'candidate_present':complete?'missing':'unknown_inputs_incomplete'})); }
export function classifyLabel(label, invalid) { if(!/^u:object_r:[A-Za-z0-9_]+:s0$/.test(label)) return 'invalid_syntax'; return invalid.includes(label)?'previously_invalid':'unknown'; }
const ROOT='out/init-preflight-extract/system';
const SNAP='out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef';
const HOST='out/guest-property-validation-v2/host';
const paths={plat:`${ROOT}/etc/selinux/plat_property_contexts`,system_ext:`${ROOT}/system_ext/etc/selinux/system_ext_property_contexts`,vendor:existsSync(`${HOST}/vendor/etc/selinux/vendor_property_contexts`)?`${HOST}/vendor/etc/selinux/vendor_property_contexts`:`${SNAP}/host/vendor/etc/selinux/vendor_property_contexts`,product:`${SNAP}/guest/product/etc/selinux/product_property_contexts`,odm:`${HOST}/odm/etc/selinux/odm_property_contexts`,system_prop:`${ROOT}/build.prop`,system_ext_prop:`${ROOT}/system_ext/etc/build.prop`,vendor_default:`${HOST}/vendor/default.prop`,vendor_prop:`${HOST}/vendor/build.prop`,vendor_dlkm_prop:`${HOST}/vendor_dlkm/etc/build.prop`,odm_dlkm_prop:`${HOST}/odm_dlkm/etc/build.prop`,system_dlkm_prop:`${HOST}/system_dlkm/etc/build.prop`,odm_prop:`${HOST}/odm/etc/build.prop`,product_prop:`${ROOT}/product/etc/build.prop`,invalid:'docs/selinux-check-device-20261031.json'};
const targets=['custom_version_prop','legal_url_prop','native_binder_stats_prop','odm_cast_prop','persist_sysui_builder_extras_prop','persist_sysui_ranking_update_prop','recovery_update_prop','sf_hs_mode_prop','usb_uvc_config_prop','vendor_hwc_prop','vendor_persist_nfc_prop','xtra_control_prop'];
export function run() {
 const inputs={}; for(const [k,p] of Object.entries(paths)) inputs[k]=existsSync(p)?{path:p,status:'available',sha256:createHash('sha256').update(readFileSync(p)).digest('hex')}:{path:p,status:'unknown_not_collected'};
 const inventoryPath=`${HOST}/input-inventory.json`;
 const inventory=existsSync(inventoryPath)?JSON.parse(readFileSync(inventoryPath,'utf8')):null;
 const devicePaths={vendor:'/vendor/etc/selinux/vendor_property_contexts',odm:'/odm/etc/selinux/odm_property_contexts',vendor_default:'/vendor/default.prop',vendor_prop:'/vendor/build.prop',vendor_dlkm_prop:'/vendor_dlkm/etc/build.prop',odm_dlkm_prop:'/odm_dlkm/etc/build.prop',system_dlkm_prop:'/system_dlkm/etc/build.prop',odm_prop:'/odm/etc/build.prop'};
 for(const [key,devicePath] of Object.entries(devicePaths)){const evidence=inventory?.inputs.find(x=>x.device_path===devicePath);if(evidence){inputs[key].device_observation=evidence;if(!existsSync(paths[key])) inputs[key].status=evidence.status;}}
 const entries=[],parse_errors=[]; for(const k of ['plat','system_ext','vendor','product','odm']) if(existsSync(paths[k])) {const r=parseContexts(readFileSync(paths[k],'utf8'),paths[k]);entries.push(...r.entries);parse_errors.push(...r.errors);}
 const files=['system_prop','system_ext_prop','system_dlkm_prop','vendor_default','vendor_prop','vendor_dlkm_prop','odm_dlkm_prop','odm_prop','product_prop'].filter(k=>existsSync(paths[k])).map(k=>({source:paths[k],text:readFileSync(paths[k],'utf8')}));
 const props=mergeProps(files); const dup=duplicates(entries);
 const inv=JSON.parse(readFileSync(paths.invalid,'utf8')).invalid_contexts.filter(x=>x.valid===false).map(x=>x.label);
 const labels=entries.map(e=>({label:e.context,status:classifyLabel(e.context,inv)})).filter((e,i,a)=>a.findIndex(x=>x.label===e.label)===i);
 const invalid=targets.map(type=>{const label=`u:object_r:${type}:s0`;const occurrences=entries.filter(e=>e.context===label);return {type,label,previous_live_einval:inv.includes(label),occurrences,area_initialization:'conditional_blocker_if_serialized_and_fsetxattr_fails',functional_necessity:'unknown'};});
 const candidates=Object.values(props.map).map(e=>({...e,context:lookup(entries,e.name),permission:'unknown',effective_value:'unknown'}));
 return {schema:1,model:'Android 16 r2 input analysis; conditional on complete inputs and permissions',inputs,context:{entry_count:entries.length,parse_errors,duplicates:dup,serialization:dup.length?'would_fail_on_first_duplicate_if_all_files_present_and_parsed':'unknown_missing_inputs',invalid_12:invalid,labels,other_context_validity:'unknown_except_previously_observed_invalid_labels'},properties:{candidates,overrides:props.changes,ignored:props.ignored,imports:props.imports,minimal_candidates:checkRequired(['ro.build.version.sdk','ro.build.version.release','ro.build.fingerprint','ro.product.cpu.abilist','ro.property_service.version','servicemanager.ready'],props.map,false),initial_boot_inputs:'unknown',permission_checks:'not_run',derived_properties:'not_run',write_once_rejections:props.rejected,warning:'Candidates are not effective values. Android checks SELinux and value types before merging; boot properties may already occupy ro.*.'},missing_inputs:['second_stage_resources','debug_ramdisk','host bootconfig/cmdline/device_tree',...['system_dlkm_prop','vendor_default','vendor_prop','vendor_dlkm_prop','odm_dlkm_prop','odm_prop','odm'].filter(k=>!existsSync(paths[k]))],not_run:['guest_property_area_creation','selinux_label_application','guest_init','servicemanager','authentication_HAL'],host_leak_risks:['device_tree','kernel_cmdline','bootconfig','host property area and inherited descriptors','vendor/odm build properties','host persistent properties','control and power properties']};
}
if(import.meta.main){const result=run();const out=process.argv[2]||'docs/guest-property-input-validation-20261031.json';writeFileSync(out,JSON.stringify(result,null,2)+'\n');console.log(`Wrote ${out}: ${result.context.entry_count} contexts, ${result.context.duplicates.length} duplicate keys, ${result.properties.candidates.length} property candidates`);}




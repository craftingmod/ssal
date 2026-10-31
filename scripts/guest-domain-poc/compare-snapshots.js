// Offline only: compares caller-collected evidence, never connects to a device.
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const required=['init','servicemanager','zygote64','system_server','surfaceflinger'];
export function compare(before, after, phase) {
  if (!['apply','probe','cleanup'].includes(phase)) throw Error('phase must be apply, probe, or cleanup');
  const errors=[], changes=[];
  for (const [name,s] of [['before',before],['after',after]]) {
    if (!s || typeof s!=='object' || !s.boot_id || !s.fingerprint || !s.captured_at || !s.processes || typeof s.processes!=='object') { errors.push(`${name}: incomplete snapshot`); continue; }
    if (s.enforce!==1) errors.push(`${name}: Enforcing not confirmed`);
    if (!Number.isInteger(s.av_sequence)) errors.push(`${name}: AV sequence missing`);
    if (!s.host_av || typeof s.host_av!=='object' || !Object.keys(s.host_av).length || Object.values(s.host_av).some(v=>typeof v!=='boolean')) errors.push(`${name}: Host AV observations missing or invalid`);
    for(const p of required) { const x=s.processes[p]; if(!x || !Number.isInteger(x.pid) || !x.start_time || !x.context || !x.executable) errors.push(`${name}: ${p} identity missing`); }
  }
  if(errors.length) return {ok:false,errors,changes};
  for(const key of ['boot_id','fingerprint']) if(before[key]!==after[key]) changes.push(key);
  for(const p of required) for(const key of ['pid','start_time','context','executable']) if(before.processes[p][key]!==after.processes[p][key]) changes.push(`${p}.${key}`);
  for(const key of new Set([...Object.keys(before.host_av),...Object.keys(after.host_av)])) if(before.host_av[key]!==after.host_av[key]) changes.push(`host_av.${key}`);
  if(phase==='probe' && before.av_sequence!==after.av_sequence) changes.push('av_sequence');
  const policy_hash=before.policy_sha256 && after.policy_sha256 ? (before.policy_sha256===after.policy_sha256?'equal':'changed') : 'unknown';
  if(phase==='probe' && policy_hash==='changed') changes.push('policy_sha256');
  return {ok:changes.length===0,errors,changes,phase,av_sequence:{before:before.av_sequence,after:after.av_sequence},policy_hash,scope:'listed process identities and supplied Host AV decisions only'};
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try { const [phase,a,b,...extra]=process.argv.slice(2); if(!phase||!a||!b||extra.length) throw Error('usage: bun compare-snapshots.js apply|probe|cleanup BEFORE.json AFTER.json'); const r=compare(JSON.parse(readFileSync(a,'utf8')),JSON.parse(readFileSync(b,'utf8')),phase); console.log(JSON.stringify(r,null,2)); if(!r.ok) process.exitCode=1; }
  catch(e) { console.error(String(e)); process.exitCode=2; }
}

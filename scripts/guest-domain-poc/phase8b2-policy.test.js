import {expect, test} from 'bun:test';
import {readFileSync} from 'node:fs';

const policy=readFileSync('scripts/guest-domain-poc/phase8b2-domain-transition.rule','utf8')
  .split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!line.startsWith('#'));
const gsiPatch=readFileSync('scripts/guest-domain-poc/phase8b2-guest-gsi.patch','utf8');

test('transition delta limits permissive mode to the two Guest targets',()=>{
  expect(policy).toEqual([
    'type ssal_guest_system_server_startup domain',
    'typeattribute ssal_guest_system_server_startup coredomain',
    'type ssal_guest_system_server domain',
    'typeattribute ssal_guest_system_server coredomain',
    'permissive ssal_guest_system_server_startup',
    'permissive ssal_guest_system_server',
    'allow ssal_guest_probe self process setcurrent',
    'allow ssal_guest_probe ssal_guest_system_server_startup process dyntransition',
    'allow ssal_guest_system_server_startup self process setcurrent',
    'allow ssal_guest_system_server_startup ssal_guest_system_server process dyntransition',
    'allow ssal_guest_system_server_startup ssal_guest_probe process sigchld',
    'allow ssal_guest_system_server ssal_guest_probe process sigchld',
  ]);
  expect(policy.filter(line=>line.startsWith('permissive '))).toEqual([
    'permissive ssal_guest_system_server_startup',
    'permissive ssal_guest_system_server',
  ]);
  expect(policy.some(line=>/^allow (?:zygote|system_server)\b/.test(line))).toBe(false);
});

test('Guest source patch changes only the two system-server SID selectors',()=>{
  expect(gsiPatch).toContain('isSystemServer=true domain=ssal_guest_system_server_startup');
  expect(gsiPatch).toContain('u:r:ssal_guest_system_server:s0');
  expect(gsiPatch).not.toContain('--start-system-server');
  expect(gsiPatch).not.toContain('SystemServer.main()');
});

test('the existing launcher still does not request system_server startup',()=>{
  const launcher=readFileSync('src/guest_launcher.rs','utf8');
  expect(launcher).toContain('start_system_server=false');
  expect(launcher).not.toContain('"--start-system-server"');
  expect(launcher).not.toContain('SystemServer.main()');
});

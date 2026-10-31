import {test, expect} from 'bun:test';
import {readFileSync} from 'node:fs';

test('candidate contains only the dedicated types and narrow transition and entrypoint rules', () => {
  const lines=readFileSync('scripts/guest-domain-poc/policy-candidate.txt','utf8').split(/\r?\n/).map(x=>x.trim()).filter(x=>x&&!x.startsWith('#'));
  expect(lines).toEqual([
    'type ssal_guest_probe domain',
    'type ssal_guest_probe_exec file_type',
    'allow ksu ssal_guest_probe process transition',
    'allow ssal_guest_probe ssal_guest_probe_exec file entrypoint',
  ]);
});

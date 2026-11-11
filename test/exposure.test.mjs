import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseV4, parseV6, formatV4, formatV6, cidr, box, subtractBox, volumeBox, volume, setFromBoxes, union, intersection, difference,
  subset, isEmpty, contains, allowedSet, evalPacket, endpoints, byClass, reviewChange, saferAlternative, ruleHealth, deadRuleHint,
  replay, mergeRanges, fmtPorts,
} from '../src/exposure.js';
import { generate, mulberry32, SEED } from '../scripts/generate.mjs';
import { headline } from '../scripts/report.mjs';

const data = JSON.parse(readFileSync(new URL('../data/account.json', import.meta.url)));
const results = JSON.parse(readFileSync(new URL('../data/results.json', import.meta.url)));
const acct = () => ({ ...data.account, rules: [], linkAll: false });
const T = (id) => data.account.tunnels.find((t) => t.id === id);

test('address parsing, formatting and CIDR ranges', () => {
  assert.equal(formatV4(parseV4('10.20.44.8')), '10.20.44.8');
  assert.equal(formatV6(parseV6('2001:db8:d0c:44::8')), '2001:db8:d0c:44::8');
  assert.equal(parseV6('::'), 0n);
  const c = cidr('10.0.0.0/8');
  assert.equal(c.hi - c.lo + 1n, 1n << 24n);
  const v6 = cidr('::/0');
  assert.equal(v6.hi, (1n << 128n) - 1n);
  assert.equal(cidr('2001:db8::1/128').lo, cidr('2001:db8::1/128').hi);
});

test('box subtraction is exact: pieces are disjoint and add up to |a| - |a and b|', () => {
  const rng = mulberry32(5);
  const R = (n) => Math.floor(rng() * n);
  for (let k = 0; k < 300; k++) {
    const mk = () => { const s = R(50), d = R(50); return box(R(2), s, s + R(30), R(3), 2, d, d + R(30), 0, R(65535)); };
    const a = mk(), b = mk();
    const pieces = subtractBox(a, b);
    const inter = intersection([a], [b]);
    assert.equal(volume(pieces) + volume(inter), volumeBox(a));
    for (let i = 0; i < pieces.length; i++) for (let j = i + 1; j < pieces.length; j++) assert.equal(intersection([pieces[i]], [pieces[j]]).length, 0);
  }
});

test('randomized: the symbolic allowed set agrees with brute-force packet evaluation', () => {
  const rng = mulberry32(11);
  const pick = (a) => a[Math.floor(rng() * a.length)];
  const eps = endpoints(data.account);
  for (let trial = 0; trial < 40; trial++) {
    const a = acct();
    a.linkAll = rng() < 0.3;
    const rules = [];
    for (let k = 0; k < 6; k++) {
      const t = pick(data.account.tunnels);
      const v6 = rng() < 0.5;
      const src = v6 ? pick(['::/0', T('macbook').v6 + '/128', '2001:db8:beef::/48']) : pick(['0.0.0.0/0', '10.0.0.0/8', T('macbook').v4 + '/32', '203.0.113.0/24']);
      const dst = v6 ? t.v6 : (t.dedicatedV4 && rng() < 0.5 ? t.dedicatedV4 : t.v4);
      const proto = pick(['TCP', 'UDP', 'ICMP', 'ALL']);
      const port = pick(['22', '443', '3000-3010', '', '6379']);
      rules.push({ tunnel: t.id, protocol: proto, src_ip: src, dst_ip: dst, dst_port: proto === 'ICMP' ? '' : port });
    }
    a.rules = rules;
    const S = allowedSet(a);
    for (let q = 0; q < 250; q++) {
      const ep = pick(eps);
      const srcPool = ep.fam === 6 ? [parseV6(T('macbook').v6), parseV6('2001:db8:beef::5'), parseV6('2001:db8:ffff::1'), 0n]
        : [parseV4(T('macbook').v4), parseV4('10.99.1.1'), parseV4('203.0.113.7'), parseV4(T('office').v4)];
      const pkt = { e: BigInt(ep.id), src: pick(srcPool), proto: BigInt(Math.floor(rng() * 3)), dport: BigInt(pick([22, 443, 3000, 3005, 3011, 6379, 8080, 0, 65535])), sport: BigInt(Math.floor(rng() * 65536)) };
      assert.equal(contains(S, pkt), evalPacket(a, pkt), `trial ${trial} packet ${JSON.stringify(pkt, (k, v) => typeof v === 'bigint' ? v.toString() : v)}`);
    }
  }
});

test('set algebra identities hold: |A u B| = |A| + |B| - |A n B|, subset and emptiness', () => {
  const a = setFromBoxes([box(0, 0, 100, 0, 0, 20, 30), box(0, 50, 150, 0, 1, 25, 40)]);
  const b = setFromBoxes([box(0, 80, 200, 0, 2, 0, 65535)]);
  assert.equal(volume(union(a, b)), volume(a) + volume(b) - volume(intersection(a, b)));
  assert.ok(subset(intersection(a, b), a) && subset(intersection(a, b), b));
  assert.ok(isEmpty(difference(a, union(a, b))));
  assert.ok(!subset(a, b));
});

test('IPv6 allowances are public; internal IPv4 allowances only reach doxx.net users', () => {
  const a = acct();
  a.rules = [{ tunnel: 'nas', protocol: 'TCP', src_ip: '::/0', dst_ip: T('nas').v6, dst_port: '22' }];
  const c6 = byClass(a, allowedSet(a));
  assert.ok(!isEmpty(c6.internet));
  a.rules = [{ tunnel: 'nas', protocol: 'TCP', src_ip: '0.0.0.0/0', dst_ip: T('nas').v4, dst_port: '22' }];
  const c4 = byClass(a, allowedSet(a));
  assert.ok(isEmpty(c4.internet));
  assert.ok(!isEmpty(c4.doxx));
  assert.equal(volume(c4.own) + volume(c4.doxx), (1n << 24n) * 65536n); // exactly the doxx.net tunnel space on TCP/22, any source port
});

test('dead rules: a public source pinned to an internal address can never match, with a hint', () => {
  const a = acct();
  const r = { tunnel: 'vps', protocol: 'TCP', src_ip: '198.51.100.77/32', dst_ip: T('vps').v4, dst_port: '8080' };
  const rv = reviewChange(a, { op: 'add', rule: r }, data.policy);
  assert.equal(rv.decision, 'dead');
  assert.equal(deadRuleHint(a, r).dst_ip, T('vps').dedicatedV4);
  const h = ruleHealth(data.account);
  assert.ok(h.some((x) => x.kind === 'dead' && x.index === 3));
  assert.ok(h.some((x) => x.kind === 'redundant' && x.index === 5));
});

test('public SSH is held with a witness packet inside the forbidden region; webhooks on 443 are not', () => {
  const a = acct();
  const rv = reviewChange(a, { op: 'add', rule: { tunnel: 'nas', protocol: 'TCP', src_ip: '::/0', dst_ip: T('nas').v6, dst_port: '22' } }, data.policy);
  assert.equal(rv.decision, 'hold');
  assert.equal(rv.witness.dport, 22n);
  assert.ok(contains(rv.violation, rv.witness) && contains(rv.opened, rv.witness));
  const ok = reviewChange(a, { op: 'add', rule: { tunnel: 'vps', protocol: 'TCP', src_ip: '::/0', dst_ip: T('vps').v6, dst_port: '443' } }, data.policy);
  assert.equal(ok.decision, 'auto');
});

test('Link All only opens traffic between the account\'s own devices', () => {
  const rv = reviewChange(acct(), { op: 'link_all', enabled: true }, data.policy);
  assert.equal(rv.decision, 'auto');
  assert.ok(isEmpty(rv.openedBy.internet) && isEmpty(rv.openedBy.doxx));
  assert.ok(!isEmpty(rv.openedBy.own));
});

test('safer alternative is verified to cover the intent and open nothing forbidden', () => {
  const a = acct();
  const ch = { op: 'add', rule: { tunnel: 'k8s', protocol: 'TCP', src_ip: '0.0.0.0/0', dst_ip: T('k8s').v4, dst_port: '5432' } };
  assert.equal(reviewChange(a, ch, data.policy).decision, 'hold');
  const alt = saferAlternative(a, ch, { from: ['vps'] }, data.policy);
  assert.ok(alt.safe && alt.coversIntent);
  assert.equal(alt.rules[0].src_ip, T('vps').v4 + '/32');
  assert.equal(reviewChange(a, { op: 'add', rule: alt.rules[0] }, data.policy).decision, 'auto');
});

test('deleting a rule closes exactly what only that rule allowed', () => {
  const a = { ...data.account };
  const rv = reviewChange(a, { op: 'delete', rule: data.account.rules[0] }, data.policy);
  assert.ok(!isEmpty(rv.closed) && isEmpty(rv.opened));
});

test('replay: applied as-is the month leaves sensitive exposures; with the check it leaves none', () => {
  const imm = replay(data, 'immediate'), chk = replay(data, 'checked');
  assert.ok(imm.exposures.length > 0);
  assert.equal(chk.exposures.length, 0);
  assert.ok(imm.exposures.some((x) => x.audience === 'internet' && x.fam === 6));
  // approving a held change re-creates its exposure, applying the verified safer rule does not
  const held = chk.log.find((l) => l.decision === 'hold' && l.alt && l.alt.safe);
  assert.ok(replay(data, 'checked', { [held.change.id]: 'approve' }).exposures.length > 0);
  assert.equal(replay(data, 'checked', { [held.change.id]: 'safer' }).exposures.length, 0);
});

test('headline numbers in data/results.json are reproduced from the data', () => {
  assert.deepEqual(headline(data), results);
  assert.ok(results.immediate.sensitiveExposures > 0 && results.checked.sensitiveExposures === 0);
});

test('generator is deterministic and matches the committed data', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(generate(SEED))), data);
});

test('port range helpers', () => {
  assert.deepEqual(mergeRanges([[80, 80], [443, 443], [81, 90], [444, 500]]), [[80, 90], [443, 500]]);
  assert.equal(fmtPorts([[0, 65535]]), 'all ports');
  assert.equal(fmtPorts([[22, 22], [27015, 27030]]), '22, 27015-27030');
});

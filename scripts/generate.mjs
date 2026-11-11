// Seeded generator: one doxx.net account (6 tunnels, 3 AI agents with net-admin tokens) and 30 days
// of agent-proposed firewall changes, each with the plain-language intent the agent was given.
// node scripts/generate.mjs -> data/account.json
// Addresses use documentation ranges (RFC 5737 IPv4, RFC 3849 IPv6) so nothing points at a real host.
import { writeFileSync } from 'node:fs';

export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
export const SEED = 20261111;
export const START = '2026-10-11';
export const DAYS = 30;

export const TUNNELS = [
  { id: 'macbook', name: 'MacBook Pro', kind: 'Desktop', server: 'mia1', v4: '10.13.7.21', v6: '2001:db8:d0c:21::15' },
  { id: 'iphone', name: 'iPhone', kind: 'Mobile', server: 'mia1', v4: '10.13.7.22', v6: '2001:db8:d0c:21::16' },
  { id: 'nas', name: 'homelab-nas', kind: 'Server', server: 'atl2', v4: '10.20.44.8', v6: '2001:db8:d0c:44::8' },
  { id: 'k8s', name: 'k8s-node-1', kind: 'Server', server: 'atl2', v4: '10.20.44.9', v6: '2001:db8:d0c:44::9' },
  { id: 'vps', name: 'agent-vps', kind: 'Server', server: 'fra1', v4: '10.31.2.40', v6: '2001:db8:d0c:31::40', dedicatedV4: '198.51.100.40' },
  { id: 'office', name: 'office-desktop', kind: 'Desktop', server: 'nyc1', v4: '10.14.9.3', v6: '2001:db8:d0c:14::3' },
];

export const AGENTS = [
  { id: 'coding', name: 'Coding Agent', host: 'vps', token: 'net-admin, expires Dec 31' },
  { id: 'research', name: 'Research Agent', host: 'macbook', token: 'net-admin, expires Nov 30' },
  { id: 'home', name: 'Home Assistant', host: 'nas', token: 'net-admin, no expiry' },
];

// Services the default guardrail treats as sensitive (commonly attacked admin and data services).
export const SENSITIVE = [
  { port: 21, service: 'FTP' }, { port: 22, service: 'SSH' }, { port: 23, service: 'Telnet' }, { port: 445, service: 'SMB' },
  { port: 1433, service: 'MS SQL Server', database: true }, { port: 2375, service: 'Docker API' }, { port: 3000, service: 'Grafana / dev server' },
  { port: 3306, service: 'MySQL', database: true }, { port: 3389, service: 'RDP' }, { port: 5432, service: 'PostgreSQL', database: true },
  { port: 5900, service: 'VNC' }, { port: 6379, service: 'Redis', database: true }, { port: 6443, service: 'Kubernetes API' },
  { port: 8080, service: 'Jenkins / admin HTTP' }, { port: 9200, service: 'Elasticsearch', database: true }, { port: 11211, service: 'Memcached', database: true },
  { port: 27017, service: 'MongoDB', database: true },
];

const T = (id) => TUNNELS.find((t) => t.id === id);
// Change templates: what the agent was asked, what it actually proposed, and who the intent needs to reach the service.
const TEMPLATES = [
  { w: 9, agent: 'coding', ask: 'Let me open the dev server on agent-vps from my laptop', mk: (r) => ({ op: 'add', rule: { tunnel: 'vps', protocol: 'TCP', src_ip: '::/0', dst_ip: T('vps').v6, dst_port: r.pick(['3000', '8080', '5173']) } }), from: ['macbook'] },
  { w: 8, agent: 'home', ask: 'I want to SSH into the NAS from my laptop', mk: (r) => ({ op: 'add', rule: { tunnel: 'nas', protocol: 'TCP', src_ip: r.pick(['0.0.0.0/0', '::/0']), dst_ip: r.p() < 0.5 ? T('nas').v4 : T('nas').v6, dst_port: '22' } }), from: ['macbook'], fix: (c) => { if (c.rule.src_ip === '::/0') c.rule.dst_ip = T('nas').v6; else c.rule.dst_ip = T('nas').v4; } },
  { w: 7, agent: 'coding', ask: 'agent-vps needs to reach Postgres on k8s-node-1', mk: (r) => ({ op: 'add', rule: { tunnel: 'k8s', protocol: 'TCP', src_ip: r.pick(['0.0.0.0/0', '10.0.0.0/8']), dst_ip: T('k8s').v4, dst_port: '5432' } }), from: ['vps'] },
  { w: 5, agent: 'home', ask: 'Let Home Assistant on my phone read Redis on the NAS', mk: () => ({ op: 'add', rule: { tunnel: 'nas', protocol: 'TCP', src_ip: '::/0', dst_ip: T('nas').v6, dst_port: '6379' } }), from: ['iphone'] },
  { w: 10, agent: 'coding', ask: 'Receive GitHub webhooks on agent-vps', mk: (r) => ({ op: 'add', rule: { tunnel: 'vps', protocol: 'TCP', src_ip: r.pick(['::/0', '0.0.0.0/0']), dst_ip: r.p() < 0.5 ? T('vps').v6 : T('vps').dedicatedV4, dst_port: '443' } }), from: null, fix: (c) => { if (c.rule.src_ip === '::/0') c.rule.dst_ip = T('vps').v6; else c.rule.dst_ip = T('vps').dedicatedV4; } },
  { w: 8, agent: 'research', ask: 'Make sure I can ping all my servers', mk: (r) => ({ op: 'add', rule: { tunnel: r.pick(['nas', 'k8s', 'vps']), protocol: 'ICMP', src_ip: '::/0', dst_ip: '', dst_port: '' } }), from: null, fix: (c) => { c.rule.dst_ip = T(c.rule.tunnel).v6; } },
  { w: 3, agent: 'research', ask: 'Connect all my devices together', mk: () => ({ op: 'link_all', enabled: true }), from: null },
  { w: 6, agent: 'research', ask: 'Allow the k8s API from my laptop', mk: () => ({ op: 'add', rule: { tunnel: 'k8s', protocol: 'TCP', src_ip: T('macbook').v6 + '/128', dst_ip: T('k8s').v6, dst_port: '6443' } }), from: ['macbook'] },
  { w: 6, agent: 'coding', ask: 'Let the CI runner (198.51.100.77) reach Jenkins on agent-vps', mk: () => ({ op: 'add', rule: { tunnel: 'vps', protocol: 'TCP', src_ip: '198.51.100.77/32', dst_ip: T('vps').v4, dst_port: '8080' } }), from: null },
  { w: 4, agent: 'home', ask: 'Only my laptop should reach the NAS file share', mk: () => ({ op: 'add', rule: { tunnel: 'nas', protocol: 'TCP', src_ip: T('macbook').v4 + '/32', dst_ip: T('nas').v4, dst_port: '445' } }), from: ['macbook'] },
  { w: 5, agent: 'coding', ask: 'Open a port range for the game server test', mk: () => ({ op: 'add', rule: { tunnel: 'vps', protocol: 'UDP', src_ip: '::/0', dst_ip: T('vps').v6, dst_port: '27015-27030' } }), from: null },
  { w: 4, agent: 'research', ask: 'Let the office desktop reach the NAS over RDP', mk: () => ({ op: 'add', rule: { tunnel: 'nas', protocol: 'TCP', src_ip: '0.0.0.0/0', dst_ip: T('nas').v4, dst_port: '3389' } }), from: ['office'] },
  { w: 5, agent: 'coding', ask: 'Clean up the old webhook rule', mk: () => ({ op: 'delete' }), from: null },
  { w: 3, agent: 'home', ask: 'Share the Grafana dashboard with my contractor (2001:db8:beef::9)', mk: () => ({ op: 'add', rule: { tunnel: 'nas', protocol: 'TCP', src_ip: '2001:db8:beef::9/128', dst_ip: T('nas').v6, dst_port: '3000' } }), from: null, external: '2001:db8:beef::9' },
  { w: 2, agent: 'coding', ask: 'Open SSH on agent-vps so the demo audience can try it', mk: () => ({ op: 'add', rule: { tunnel: 'vps', protocol: 'TCP', src_ip: '0.0.0.0/0', dst_ip: T('vps').dedicatedV4, dst_port: '22' } }), from: null, external: 'anyone' },
];

export function generate(seed = SEED) {
  const rng = mulberry32(seed);
  const r = { p: rng, pick: (a) => a[Math.floor(rng() * a.length)] };
  const rules = [
    { tunnel: 'vps', protocol: 'TCP', src_ip: '::/0', dst_ip: T('vps').v6, dst_port: '443' },
    { tunnel: 'nas', protocol: 'TCP', src_ip: T('macbook').v4 + '/32', dst_ip: T('nas').v4, dst_port: '22' },
    { tunnel: 'nas', protocol: 'TCP', src_ip: '0.0.0.0/0', dst_ip: T('nas').v4, dst_port: '8123' },
    // stale: pinned to a home ISP address, but the destination is the internal doxx IPv4 (can never match)
    { tunnel: 'k8s', protocol: 'TCP', src_ip: '203.0.113.58/32', dst_ip: T('k8s').v4, dst_port: '22' },
    { tunnel: 'vps', protocol: 'ICMP', src_ip: '::/0', dst_ip: T('vps').v6, dst_port: '' },
    // redundant: 443 is already open to everyone on this address
    { tunnel: 'vps', protocol: 'TCP', src_ip: '2001:db8:d0c:21::15/128', dst_ip: T('vps').v6, dst_port: '443' },
  ];
  const tw = TEMPLATES.reduce((a, t) => a + t.w, 0);
  const changes = [];
  const start = Date.parse(START + 'T00:00:00Z');
  for (let day = 0; day < DAYS; day++) {
    const n = 4 + Math.floor(rng() * 6);
    for (let k = 0; k < n; k++) {
      let x = rng() * tw, t = TEMPLATES[0];
      for (const c of TEMPLATES) { x -= c.w; if (x <= 0) { t = c; break; } }
      const ch = t.mk(r);
      if (t.fix) t.fix(ch);
      if (ch.op === 'delete') ch.rule = { tunnel: 'vps', protocol: 'TCP', src_ip: '::/0', dst_ip: T('vps').v6, dst_port: '443' };
      const minute = 7 * 60 + Math.floor(rng() * 15 * 60);
      changes.push({ id: 0, at: new Date(start + day * 864e5 + minute * 6e4).toISOString(), agent: t.agent, ask: t.ask, intentFrom: t.from, intentExternal: t.external || null, ...ch });
    }
  }
  changes.sort((a, b) => a.at.localeCompare(b.at));
  changes.forEach((c, i) => { c.id = 1001 + i; });
  return {
    meta: { generator: 'scripts/generate.mjs', seed, note: 'Synthetic account. Addresses are documentation ranges (RFC 5737, RFC 3849).' },
    account: { name: 'r.moreno', plan: 'Pro', doxxV4Space: '10.0.0.0/8', linkAll: false, tunnels: TUNNELS, rules, agents: AGENTS },
    policy: { noPublicSensitive: true, noDoxxWideSensitive: true, sensitive: SENSITIVE },
    startDate: START, days: DAYS, changes,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const d = generate();
  writeFileSync(new URL('../data/account.json', import.meta.url), JSON.stringify(d, null, 1) + '\n');
  console.log('changes', d.changes.length);
}

// Exposure Check: exact reachability diffs for doxx.net firewall changes. No dependencies.
//
// doxx.net firewall model (from config.doxx.net and the Firewall help page):
//  * per-tunnel inbound ALLOW rules on a default-deny firewall: protocol (ALL|TCP|UDP|ICMP),
//    src_ip (CIDR), dst_ip (one of the tunnel's own addresses), optional src_port / dst_port;
//  * a tunnel's IPv4 address is internal to doxx.net (10.x), its IPv6 address is public, and a leased
//    dedicated IPv4 is public; so the same "allow port 22" means very different exposure per family;
//  * Link All (full mesh) allows all traffic between the account's own tunnels;
//  * changes take effect immediately (no dry run), and AI agents holding net-admin tokens can make them.
//
// Every allowed packet is a point in a 5-dimensional space:
//   e     destination endpoint (tunnel x address family), an index
//   src   source address, an integer inside the endpoint's family (IPv4 32-bit, IPv6 128-bit)
//   proto 0 = TCP, 1 = UDP, 2 = ICMP
//   dport destination port 0..65535 (ICMP rules cover the full range)
//   sport source port 0..65535
// A rule is an axis-aligned box. A rule set is a union of boxes. We keep sets as lists of pairwise
// disjoint boxes, so union, intersection, difference, emptiness, subset and exact counting are all
// exact (no sampling, no false positives or negatives) for this rule language. This is the same idea
// as header space analysis (Kazemian et al., NSDI 2012) and AWS Zelkova, specialised to doxx.net.

export const PROTO = { TCP: 0, UDP: 1, ICMP: 2 };
export const PROTO_NAME = ['TCP', 'UDP', 'ICMP'];
const DIMS = ['e', 'src', 'proto', 'dport', 'sport'];
const MAX = { 4: (1n << 32n) - 1n, 6: (1n << 128n) - 1n };

// ---------- addresses ----------
export function parseV4(s) {
  const p = s.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) throw new Error('bad IPv4 ' + s);
  return BigInt(((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]);
}
export function parseV6(s) {
  let [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : null;
  let groups;
  if (t === null) groups = h; else groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  if (groups.length !== 8) throw new Error('bad IPv6 ' + s);
  return groups.reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g || '0', 16)), 0n);
}
export const familyOf = (addr) => (addr.includes(':') ? 6 : 4);
/** CIDR -> [lo, hi] as BigInt plus family. */
export function cidr(s) {
  const [a, l] = s.split('/');
  const fam = familyOf(a);
  const bits = fam === 4 ? 32 : 128;
  const len = l === undefined ? bits : Number(l);
  const base = fam === 4 ? parseV4(a) : parseV6(a);
  const host = (1n << BigInt(bits - len)) - 1n;
  const lo = base & ~host & MAX[fam];
  return { fam, lo, hi: lo | host, len };
}
export function formatV4(n) { return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join('.'); }
export function formatV6(n) {
  const g = []; for (let i = 7; i >= 0; i--) g.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // compress the longest zero run
  let best = [-1, 0], cur = [-1, 0];
  g.forEach((x, i) => { if (x === '0') { if (cur[0] < 0) cur = [i, 0]; cur[1]++; if (cur[1] > best[1]) best = [...cur]; } else cur = [-1, 0]; });
  if (best[1] < 2) return g.join(':');
  const left = g.slice(0, best[0]).join(':'), right = g.slice(best[0] + best[1]).join(':');
  return `${left}::${right}`;
}
export const formatAddr = (fam, n) => (fam === 4 ? formatV4(n) : formatV6(n));

// ---------- boxes ----------
// box: { e:[lo,hi], src:[lo,hi], proto:[lo,hi], dport:[lo,hi], sport:[lo,hi] } with BigInt bounds
const B = (x) => BigInt(x);
export function box(e, srcLo, srcHi, pLo, pHi, dLo, dHi, sLo = 0, sHi = 65535) {
  return { e: [B(e), B(e)], src: [B(srcLo), B(srcHi)], proto: [B(pLo), B(pHi)], dport: [B(dLo), B(dHi)], sport: [B(sLo), B(sHi)] };
}
const emptyBox = (b) => DIMS.some((d) => b[d][0] > b[d][1]);
export function intersectBox(a, b) {
  const o = {};
  for (const d of DIMS) o[d] = [a[d][0] > b[d][0] ? a[d][0] : b[d][0], a[d][1] < b[d][1] ? a[d][1] : b[d][1]];
  return emptyBox(o) ? null : o;
}
/** a \ b as a list of disjoint boxes (at most 2 per dimension). */
export function subtractBox(a, b) {
  const x = intersectBox(a, b);
  if (!x) return [a];
  const out = [];
  let rest = { ...a };
  for (const d of DIMS) {
    if (rest[d][0] < x[d][0]) out.push({ ...rest, [d]: [rest[d][0], x[d][0] - 1n] });
    if (rest[d][1] > x[d][1]) out.push({ ...rest, [d]: [x[d][1] + 1n, rest[d][1]] });
    rest = { ...rest, [d]: [x[d][0], x[d][1]] };
  }
  return out;
}
export const volumeBox = (b) => DIMS.reduce((acc, d) => acc * (b[d][1] - b[d][0] + 1n), 1n);
export const containsPoint = (b, p) => DIMS.every((d) => b[d][0] <= p[d] && p[d] <= b[d][1]);

// ---------- sets (lists of disjoint boxes) ----------
export function setFromBoxes(boxes) {
  let out = [];
  for (const b of boxes) {
    let pieces = [b];
    for (const o of out) pieces = pieces.flatMap((p) => subtractBox(p, o));
    out = out.concat(pieces);
  }
  return out;
}
export const union = (A, Bs) => setFromBoxes([...A, ...Bs]);
export function difference(A, Bs) {
  let out = A;
  for (const b of Bs) out = out.flatMap((a) => subtractBox(a, b));
  return out;
}
export function intersection(A, Bs) {
  const out = [];
  for (const a of A) for (const b of Bs) { const x = intersectBox(a, b); if (x) out.push(x); }
  return out; // pairwise disjoint because A and B are disjoint lists
}
export const isEmpty = (A) => A.length === 0;
export const volume = (A) => A.reduce((s, b) => s + volumeBox(b), 0n);
export const contains = (A, p) => A.some((b) => containsPoint(b, p));
export const subset = (A, Bs) => isEmpty(difference(A, Bs));
/** A concrete witness packet inside a non-empty set. Prefers a recognisable outside address
 * (documentation ranges) and a typical ephemeral source port when the set allows them. */
const PROBES = [parseV6Probe('2001:db8:ffff::1'), 0xcb007107n /* 203.0.113.7 */, 0x0a630107n /* 10.99.1.7, another doxx.net user */];
function parseV6Probe(s) { const [h, t] = s.split('::'); const hg = h.split(':'); const tg = t ? t.split(':') : []; const g = [...hg, ...Array(8 - hg.length - tg.length).fill('0'), ...tg]; return g.reduce((a, x) => (a << 16n) + BigInt(parseInt(x || '0', 16)), 0n); }
export function witness(A) {
  if (!A.length) return null;
  const b = A.find((x) => PROBES.some((p) => x.src[0] <= p && p <= x.src[1])) || A[0];
  const src = PROBES.find((p) => b.src[0] <= p && p <= b.src[1]) ?? b.src[0];
  const sport = b.sport[0] <= 51514n && 51514n <= b.sport[1] ? 51514n : b.sport[0];
  return { e: b.e[0], src, proto: b.proto[0], dport: b.dport[0], sport };
}

// ---------- the doxx.net account model ----------
/**
 * endpoints(account): one endpoint per (tunnel, address family) with how it can be reached.
 * scope: 'doxx' = internal IPv4 (only other doxx.net tunnels can send to it),
 *        'public' = public IPv6 or a leased dedicated IPv4 (any address on the internet).
 */
export function endpoints(account) {
  const out = [];
  account.tunnels.forEach((t) => {
    out.push({ id: out.length, tunnel: t.id, fam: 4, addr: t.v4, scope: 'doxx' });
    if (t.v6) out.push({ id: out.length, tunnel: t.id, fam: 6, addr: t.v6, scope: 'public' });
    if (t.dedicatedV4) out.push({ id: out.length, tunnel: t.id, fam: 4, addr: t.dedicatedV4, scope: 'public' });
  });
  return out;
}
const protoRange = (p) => (p === 'ALL' ? [0, 2] : [PROTO[p], PROTO[p]]);
function portRange(v) {
  if (v === undefined || v === null || v === '' || v === 'any') return [0, 65535];
  const s = String(v);
  if (s.includes('-')) { const [a, b] = s.split('-').map(Number); return [a, b]; }
  return [Number(s), Number(s)];
}
/** A rule as boxes (one per endpoint it targets). Rules on an address the tunnel does not own match nothing. */
export function ruleBoxes(rule, eps) {
  const src = cidr(rule.src_ip);
  const dst = rule.dst_ip.split('/')[0];
  const targets = eps.filter((ep) => ep.tunnel === rule.tunnel && ep.addr === dst && ep.fam === src.fam);
  const [pLo, pHi] = protoRange(rule.protocol);
  const [dLo, dHi] = rule.protocol === 'ICMP' ? [0, 65535] : portRange(rule.dst_port);
  const [sLo, sHi] = rule.protocol === 'ICMP' ? [0, 65535] : portRange(rule.src_port);
  return targets.map((ep) => box(ep.id, src.lo, src.hi, pLo, pHi, dLo, dHi, sLo, sHi));
}
/** Sources that can actually send to an endpoint: all of IPv6 / IPv4 for public endpoints, doxx tunnel space for internal ones. */
export function reachableSources(ep, account) {
  if (ep.scope === 'public') return [{ lo: 0n, hi: MAX[ep.fam] }];
  const net = cidr(account.doxxV4Space || '10.0.0.0/8');
  return [{ lo: net.lo, hi: net.hi }];
}
/** The exact set of packets that can arrive and be accepted. */
const ruleKey = (r) => [r.tunnel, r.protocol, r.src_ip, r.dst_ip, r.dst_port ?? '', r.src_port ?? ''].join('|');
const SET_CACHE = new Map();
export function allowedSet(account, rules = account.rules, linkAll = account.linkAll) {
  const keys = [...new Set(rules.map(ruleKey))].sort();
  const ck = account.tunnels.map((t) => t.v4 + t.v6 + (t.dedicatedV4 || '')).join(',') + '#' + linkAll + '#' + keys.join(';');
  if (SET_CACHE.has(ck)) return SET_CACHE.get(ck);
  const uniq = keys.map((k) => rules.find((r) => ruleKey(r) === k));
  const eps = endpoints(account);
  const boxes = [];
  for (const r of uniq) for (const b of ruleBoxes(r, eps)) {
    // clip to what can physically arrive at the endpoint
    for (const s of reachableSources(eps[Number(b.e[0])], account)) {
      const c = intersectBox(b, { ...b, src: [s.lo, s.hi] });
      if (c) boxes.push(c);
    }
  }
  if (linkAll) {
    // full mesh: every own tunnel may reach every other own tunnel on its internal IPv4, any proto/port
    const own = account.tunnels.map((t) => cidr(t.v4));
    for (const ep of eps.filter((x) => x.scope === 'doxx')) for (const o of own) if (o.lo !== cidr(ep.addr).lo) boxes.push(box(ep.id, o.lo, o.hi, 0, 2, 0, 65535));
  }
  const out = setFromBoxes(boxes);
  if (SET_CACHE.size > 5000) SET_CACHE.clear();
  SET_CACHE.set(ck, out);
  return out;
}

// ---------- source classes ----------
/** Partition a source range of an endpoint into who is behind it: own devices, other doxx.net users, the public internet. */
export function sourceClasses(account, ep) {
  const own = account.tunnels.flatMap((t) => [t.v4, t.v6, t.dedicatedV4].filter(Boolean)).map(cidr).filter((c) => c.fam === ep.fam);
  const classes = own.map((c) => ({ cls: 'own', lo: c.lo, hi: c.hi }));
  if (ep.fam === 4 && ep.scope === 'doxx') { const n = cidr(account.doxxV4Space || '10.0.0.0/8'); classes.push({ cls: 'doxx', lo: n.lo, hi: n.hi }); }
  classes.push({ cls: 'internet', lo: 0n, hi: MAX[ep.fam] });
  return classes; // earlier entries take precedence
}
/** Split a set into per-class parts for an endpoint list. */
export function byClass(account, S) {
  const eps = endpoints(account);
  const out = { own: [], doxx: [], internet: [] };
  for (const b of S) {
    const ep = eps[Number(b.e[0])];
    let rest = [b];
    for (const c of sourceClasses(account, ep)) {
      const sel = { ...b, src: [c.lo, c.hi] };
      const hit = rest.map((r) => intersectBox(r, sel)).filter(Boolean);
      out[c.cls].push(...hit);
      rest = rest.flatMap((r) => subtractBox(r, sel));
    }
  }
  return out;
}

// ---------- policy ----------
/**
 * Guardrails as forbidden regions. Default policy: agents may not make sensitive services reachable
 * from the public internet, or from every doxx.net user, without a person approving it. The account's
 * own devices are always allowed.
 */
const FORB_CACHE = new WeakMap();
export function forbiddenSet(account, policy) {
  const k = account.tunnels.map((t) => t.v4 + t.v6 + (t.dedicatedV4 || '')).join(',');
  const c = FORB_CACHE.get(policy); if (c && c.k === k) return c.v;
  const eps = endpoints(account);
  const boxes = [];
  for (const ep of eps) {
    const classes = sourceClasses(account, ep);
    const internet = { lo: 0n, hi: MAX[ep.fam] };
    for (const svc of policy.sensitive) {
      const p = PROTO[svc.proto || 'TCP'];
      if (policy.noPublicSensitive && ep.scope === 'public') {
        // internet minus own addresses
        let parts = [box(ep.id, internet.lo, internet.hi, p, p, svc.port, svc.port)];
        for (const c of classes.filter((c) => c.cls === 'own')) parts = parts.flatMap((x) => subtractBox(x, { ...x, src: [c.lo, c.hi] }));
        boxes.push(...parts);
      }
      if (policy.noDoxxWideSensitive && ep.scope === 'doxx') {
        const n = cidr(account.doxxV4Space || '10.0.0.0/8');
        let parts = [box(ep.id, n.lo, n.hi, p, p, svc.port, svc.port)];
        for (const c of classes.filter((c) => c.cls === 'own')) parts = parts.flatMap((x) => subtractBox(x, { ...x, src: [c.lo, c.hi] }));
        boxes.push(...parts);
      }
    }
  }
  // boxes are pairwise disjoint already (distinct endpoint/port, and subtraction pieces are disjoint)
  FORB_CACHE.set(policy, { k, v: boxes });
  return boxes;
}

// ---------- change review ----------
/**
 * Evaluate a proposed change against the current state.
 * change: { op: 'add'|'delete'|'link_all', rule?, enabled? }
 */
export function reviewChange(account, change, policy) {
  const before = allowedSet(account);
  let rules = account.rules, linkAll = account.linkAll;
  if (change.op === 'add') rules = [...rules, change.rule];
  else if (change.op === 'delete') rules = rules.filter((r) => !sameRule(r, change.rule));
  else if (change.op === 'link_all') linkAll = !!change.enabled;
  const after = allowedSet(account, rules, linkAll);
  const opened = difference(after, before);
  const closed = difference(before, after);
  const forb = forbiddenSet(account, policy);
  const violation = intersection(opened, forb);
  const openedBy = byClass(account, opened);
  const deadRule = change.op === 'add' && isEmpty(allowedSet(account, [change.rule], false));
  let decision;
  if (deadRule) decision = 'dead';
  else if (!isEmpty(violation)) decision = 'hold';
  else decision = 'auto';
  return { before, after, opened, closed, violation, openedBy, decision, deadRule, witness: witness(violation.length ? violation : opened), newRules: rules, linkAll };
}
export const sameRule = (a, b) => a.tunnel === b.tunnel && a.protocol === b.protocol && a.src_ip === b.src_ip && a.dst_ip === b.dst_ip && String(a.dst_port ?? '') === String(b.dst_port ?? '') && String(a.src_port ?? '') === String(b.src_port ?? '');

/**
 * Safer alternative: rules that still let the intended sources in (intent.from: tunnel ids of the
 * account's own devices) but open nothing in the forbidden region. Uses the destination tunnel's
 * internal IPv4 and the source devices' internal IPv4 /32s, which never touch the public internet.
 * Verified exactly: returns { rules, coversIntent, safe }.
 */
export function saferAlternative(account, change, intent, policy) {
  if (change.op !== 'add' || !intent || !intent.from || !intent.from.length) return null;
  const r = change.rule;
  const dst = account.tunnels.find((t) => t.id === r.tunnel);
  const rules = intent.from.map((tid) => {
    const src = account.tunnels.find((t) => t.id === tid);
    return { tunnel: r.tunnel, protocol: r.protocol, src_ip: src.v4.split('/')[0] + '/32', dst_ip: dst.v4.split('/')[0], dst_port: r.dst_port };
  });
  const eps = endpoints(account);
  const want = setFromBoxes(intent.from.flatMap((tid) => {
    const src = cidr(account.tunnels.find((t) => t.id === tid).v4);
    const ep = eps.find((e) => e.tunnel === r.tunnel && e.scope === 'doxx');
    const [pLo, pHi] = protoRange(r.protocol); const [dLo, dHi] = portRange(r.dst_port);
    return [box(ep.id, src.lo, src.hi, pLo, pHi, dLo, dHi)];
  }));
  const proposed = allowedSet(account, [...account.rules, ...rules], account.linkAll);
  const opened = difference(proposed, allowedSet(account));
  const safe = isEmpty(intersection(opened, forbiddenSet(account, policy)));
  const coversIntent = subset(want, proposed);
  return { rules, safe, coversIntent };
}

// ---------- rule health ----------
/** For a rule that can never match: the most likely intended rule (same source, the tunnel's public address). */
export function deadRuleHint(account, rule) {
  const src = cidr(rule.src_ip), t = account.tunnels.find((x) => x.id === rule.tunnel);
  if (src.fam === 4 && t.dedicatedV4 && rule.dst_ip.split('/')[0] === t.v4.split('/')[0]) return { ...rule, dst_ip: t.dedicatedV4 };
  return null;
}

/** Rules that can never match (dead) or are fully covered by the other rules (redundant). */
export function ruleHealth(account) {
  const out = [];
  account.rules.forEach((r, i) => {
    const own = allowedSet(account, [r], false);
    if (isEmpty(own)) {
      const src = cidr(r.src_ip), t = account.tunnels.find((x) => x.id === r.tunnel);
      const pub = !inRange(src, account.doxxV4Space || '10.0.0.0/8') && src.fam === 4;
      out.push({ index: i, rule: r, kind: 'dead', reason: pub && r.dst_ip === t.v4.split('/')[0] ? 'Source is a public IPv4 but the destination is the tunnel\'s internal doxx.net IPv4, so no packet from that source can ever arrive.' : 'The rule targets an address this tunnel does not have.' });
      return;
    }
    const others = allowedSet(account, account.rules.filter((_, j) => j !== i), account.linkAll);
    if (subset(own, others)) out.push({ index: i, rule: r, kind: 'redundant', reason: account.linkAll ? 'Already allowed by Link All or another rule.' : 'Fully covered by another rule.' });
  });
  return out;
}
function inRange(c, space) { const s = cidr(space); return c.fam === s.fam && c.lo >= s.lo && c.hi <= s.hi; }

// ---------- reporting helpers ----------
/** Human summary of a set restricted to one class: [{endpoint, proto, ports:[[lo,hi]], sources}] */
export function describe(account, S) {
  const eps = endpoints(account);
  const groups = new Map();
  for (const b of S) {
    const ep = eps[Number(b.e[0])];
    for (let p = Number(b.proto[0]); p <= Number(b.proto[1]); p++) {
      const key = `${ep.id}|${p}`;
      const g = groups.get(key) || { endpoint: ep, proto: PROTO_NAME[p], ports: [], sources: 0n };
      g.ports.push([Number(b.dport[0]), Number(b.dport[1])]);
      g.sources += b.src[1] - b.src[0] + 1n;
      groups.set(key, g);
    }
  }
  for (const g of groups.values()) g.ports = mergeRanges(g.ports);
  return [...groups.values()];
}
export function mergeRanges(rs) {
  const s = rs.slice().sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const r of s) { const l = out[out.length - 1]; if (l && r[0] <= l[1] + 1) l[1] = Math.max(l[1], r[1]); else out.push([...r]); }
  return out;
}
export const fmtPorts = (rs) => rs.map(([a, b]) => (a === 0 && b === 65535 ? 'all ports' : a === b ? String(a) : `${a}-${b}`)).join(', ');
/** log2 of a BigInt count (for "2^96 sources" style summaries). */
export const log2 = (n) => (n <= 0n ? 0 : n.toString(2).length - 1);

/** Evaluate a packet by brute force against raw rules (reference semantics for tests). */
export function evalPacket(account, pkt, rules = account.rules, linkAll = account.linkAll) {
  const eps = endpoints(account);
  const ep = eps[Number(pkt.e)];
  const reach = reachableSources(ep, account).some((s) => s.lo <= pkt.src && pkt.src <= s.hi);
  if (!reach) return false;
  if (linkAll && ep.scope === 'doxx') {
    const own = account.tunnels.map((t) => cidr(t.v4)).filter((o) => o.lo !== cidr(ep.addr).lo);
    if (own.some((o) => o.lo <= pkt.src && pkt.src <= o.hi)) return true;
  }
  return rules.some((r) => {
    if (r.tunnel !== ep.tunnel || r.dst_ip.split('/')[0] !== ep.addr) return false;
    const s = cidr(r.src_ip); if (s.fam !== ep.fam || pkt.src < s.lo || pkt.src > s.hi) return false;
    const [pl, ph] = protoRange(r.protocol); if (pkt.proto < BigInt(pl) || pkt.proto > BigInt(ph)) return false;
    if (r.protocol === 'ICMP') return true;
    const [dl, dh] = portRange(r.dst_port); if (pkt.dport < BigInt(dl) || pkt.dport > BigInt(dh)) return false;
    const [sl, sh] = portRange(r.src_port); return pkt.sport >= BigInt(sl) && pkt.sport <= BigInt(sh);
  });
}

// ---------- replay ----------
/**
 * Replay an agent change log.
 *  mode 'immediate': today's behaviour, every change applies at once.
 *  mode 'checked'  : each change is reviewed; 'auto' applies, 'hold' and 'dead' wait for a person.
 * decisions: { [changeId]: 'approve' | 'reject' | 'safer' } for held changes (checked mode only).
 */
export function replay(data, mode = 'checked', decisions = {}) {
  const acc = { ...data.account, rules: data.account.rules.slice(), linkAll: data.account.linkAll };
  const log = [];
  for (const ch of data.changes) {
    const rv = reviewChange(acc, ch, data.policy);
    let applied = false, via = null;
    const alt = rv.decision === 'hold' ? saferAlternative(acc, ch, ch.intentFrom ? { from: ch.intentFrom } : null, data.policy) : null;
    if (mode === 'immediate' || rv.decision === 'auto') { applied = true; via = mode === 'immediate' ? 'immediate' : 'auto'; }
    else if (decisions[ch.id] === 'approve') { applied = true; via = 'approved'; }
    else if (decisions[ch.id] === 'safer' && alt && alt.safe && alt.coversIntent) {
      acc.rules = [...acc.rules, ...alt.rules.filter((r) => !acc.rules.some((x) => sameRule(x, r)))]; via = 'safer';
    }
    if (applied) { acc.rules = rv.newRules.filter((r, i, a) => a.findIndex((x) => sameRule(x, r)) === i); acc.linkAll = rv.linkAll; }
    log.push({ change: ch, decision: rv.decision, applied, via, alt, opened: rv.opened, violation: rv.violation, openedBy: rv.openedBy, witness: rv.witness, closed: rv.closed });
  }
  const finalSet = allowedSet(acc);
  const exposed = intersection(finalSet, forbiddenSet(acc, data.policy));
  return { account: acc, log, finalSet, exposed, exposures: describeExposures(acc, exposed, data.policy) };
}

/** Distinct (tunnel, service, audience) exposures inside a forbidden-region intersection. */
export function describeExposures(account, S, policy) {
  const eps = endpoints(account);
  const cls = byClass(account, S);
  const out = [];
  for (const audience of ['internet', 'doxx']) {
    for (const g of describe(account, cls[audience])) {
      for (const [lo, hi] of g.ports) for (const svc of policy.sensitive) if (svc.port >= lo && svc.port <= hi && g.proto === 'TCP') {
        out.push({ tunnel: g.endpoint.tunnel, addr: g.endpoint.addr, fam: g.endpoint.fam, scope: g.endpoint.scope, port: svc.port, service: svc.service, audience, sourcesLog2: log2(g.sources) });
      }
    }
  }
  // de-duplicate per tunnel/port/audience
  const seen = new Set();
  return out.filter((x) => { const k = `${x.tunnel}|${x.port}|${x.audience}|${x.addr}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

/** Headline numbers for the results file and the page. */
export function summarize(data) {
  const imm = replay(data, 'immediate');
  const chk = replay(data, 'checked');
  const held = chk.log.filter((l) => l.decision === 'hold');
  const dead = chk.log.filter((l) => l.decision === 'dead');
  const auto = chk.log.filter((l) => l.decision === 'auto');
  const withAlt = held.filter((l) => l.alt && l.alt.safe && l.alt.coversIntent);
  const internetImm = imm.exposures.filter((x) => x.audience === 'internet');
  const doxxImm = imm.exposures.filter((x) => x.audience === 'doxx');
  return {
    changes: data.changes.length,
    autoApplied: auto.length,
    held: held.length,
    deadRulesCaught: dead.length,
    saferAlternativeVerified: withAlt.length,
    needsPerson: held.filter((l) => !(l.alt && l.alt.safe && l.alt.coversIntent)).length,
    immediate: { sensitiveExposures: imm.exposures.length, toInternet: internetImm.length, toAllDoxxUsers: doxxImm.length, services: [...new Set(imm.exposures.map((x) => x.service))] },
    checked: { sensitiveExposures: chk.exposures.length },
    initialRuleHealth: ruleHealth(data.account).map((h) => ({ index: h.index, kind: h.kind })),
  };
}

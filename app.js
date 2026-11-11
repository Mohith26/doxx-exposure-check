// doxx.net portal > My Network > Exposure (concept). Every number is computed in the browser from
// data/account.json by src/exposure.js (exact set algebra; nothing on the page is hard-coded).
import { replay, ruleHealth, reviewChange, saferAlternative, deadRuleHint, byClass, describe, fmtPorts, log2, formatAddr, endpoints, intersection, forbiddenSet, isEmpty, sameRule, PROTO_NAME, allowedSet } from './src/exposure.js';

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const LS = 'doxx-exposure-check-v1';
const state = { data: null, kev: null, decisions: {}, manual: [], removed: [], mode: 'checked', tab: 'held', q: '', sel: -1 };

function load() { try { const s = JSON.parse(localStorage.getItem(LS)) || {}; state.decisions = s.decisions || {}; state.manual = s.manual || []; state.removed = s.removed || []; } catch { /* private mode */ } }
function save() { try { localStorage.setItem(LS, JSON.stringify({ decisions: state.decisions, manual: state.manual, removed: state.removed })); } catch { /* ignore */ } }

function dataNow() {
  const a = state.data.account;
  const rules = [...a.rules, ...state.manual].filter((r) => !state.removed.some((x) => sameRule(x, r)));
  return { ...state.data, account: { ...a, rules } };
}
function compute() {
  const d = dataNow();
  const t0 = performance.now();
  state.checked = replay(d, 'checked', state.decisions);
  state.immediate = replay(d, 'immediate');
  state.ms = performance.now() - t0;
}

const tun = (id) => state.data.account.tunnels.find((t) => t.id === id);
const agent = (id) => state.data.account.agents.find((a) => a.id === id);
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const when = (iso) => { const d = new Date(iso); return `${MON[d.getUTCMonth()]} ${d.getUTCDate()}, ${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`; };
const srcLabel = (s) => (s === '0.0.0.0/0' || s === '::/0' ? `Anywhere (${s.includes(':') ? 'IPv6' : 'IPv4'})` : s);
const srcShort = (s) => (s === '0.0.0.0/0' ? 'any IPv4' : s === '::/0' ? 'any IPv6' : s.replace(/\/(32|128)$/, ''));
const bigCount = (n) => { const x = Number(n); return x < 1e4 ? x.toLocaleString() : x < 1e9 ? (x / 1e6).toFixed(1) + 'M' : '2^' + log2(n); };
const svcName = (port) => (state.data.policy.sensitive.find((x) => x.port === Number(port)) || {}).service;
const kevFor = (port) => (state.kev?.services || []).find((s) => s.port === Number(port));

function changeText(ch) {
  if (ch.op === 'link_all') return `<span class="proto">Link All</span> ${ch.enabled ? 'on' : 'off'} <span class="faint">· full mesh between your devices</span>`;
  const r = ch.rule, t = tun(r.tunnel);
  const sign = ch.op === 'delete' ? '−' : '+';
  const port = r.protocol === 'ICMP' ? '' : ` ${esc(r.dst_port || 'all')}`;
  return `${sign} <span class="proto">${esc(r.protocol)}</span>${port} <span class="faint">from</span> ${esc(srcShort(r.src_ip))} <span class="faint">→</span> ${esc(t.name)} <span class="faint mono">${r.dst_ip.includes(':') ? 'v6' : r.dst_ip === t.dedicatedV4 ? 'pub v4' : 'v4'}</span>`;
}
function audiencePill(l) {
  if (l.decision === 'dead') return '<span class="pill p-purple">Never matches</span>';
  if (l.change.op === 'delete') return '<span class="pill p-dim">Closes access</span>';
  const o = l.openedBy;
  if (!isEmpty(o.internet)) return `<span class="pill ${isEmpty(l.violation) ? 'p-yellow' : 'p-red'}">Public internet</span>`;
  if (!isEmpty(o.doxx)) return `<span class="pill ${isEmpty(l.violation) ? 'p-yellow' : 'p-red'}">All doxx.net users</span>`;
  if (!isEmpty(o.own)) return '<span class="pill p-blue">Your devices only</span>';
  return '<span class="pill p-dim">No change</span>';
}
function decisionPill(l) {
  const d = state.decisions[l.change.id];
  if (l.decision === 'auto') return '<span class="pill p-teal"><span class="d"></span>Applied</span>';
  if (l.decision === 'dead') return '<span class="pill p-purple">Not applied</span>';
  if (d === 'approve') return '<span class="pill p-dim">Approved</span>';
  if (d === 'safer') return '<span class="pill p-teal">Safer rule applied</span>';
  if (d === 'reject') return '<span class="pill p-dim">Rejected</span>';
  return '<span class="pill p-yellow"><span class="d"></span>Held for you</span>';
}

// ---------- routing ----------
function route() { const h = (location.hash || '#/ops/tunnels/exposure').slice(1); const [p, qs] = h.split('?'); return { parts: p.split('/').filter(Boolean), params: new URLSearchParams(qs || '') }; }
window.addEventListener('hashchange', () => { state.sel = -1; render(); });
function setParam(k, v) { const r = route(); if (v == null) r.params.delete(k); else r.params.set(k, v); const qs = r.params.toString(); history.replaceState(null, '', '#/' + r.parts.join('/') + (qs ? '?' + qs : '')); }

// ---------- top nav ----------
function renderNav(sub) {
  const total = state.checked.log.length;
  $('#topnav').innerHTML = `
    <div class="topnav-row">
      <a class="logo" href="#/ops/tunnels" aria-label="doxx.net home"><img src="assets/logotype_white.svg" alt="doxx.net" width="98" height="18" /></a>
      <nav class="capsule" aria-label="Main">
        <a href="#/ops/tunnels" aria-current="page">My Network</a><a href="#/ops/security">Security</a><a href="#/ops/chatnet">ChatNET</a><a href="#/ops/dns">DNS &amp; PKI</a><a href="#/ops/account">Account</a>
        <span class="sep"></span><button class="logout" type="button">Logout</button>
      </nav>
      <div class="counter" aria-label="Agent changes reviewed"><div class="n">${total.toLocaleString()}</div><div class="l">agent changes checked</div></div>
    </div>
    <nav class="capsule subnav" aria-label="My Network">
      <a href="#/ops/tunnels" ${sub === 'list' ? 'aria-current="page"' : ''}>Tunnel List</a><a href="#/ops/tunnels/topology" ${sub === 'topology' ? 'aria-current="page"' : ''}>Topology</a><a href="#/ops/tunnels/saved-connections" ${sub === 'saved' ? 'aria-current="page"' : ''}>Saved Connections</a><a href="#/ops/tunnels/exposure" ${sub === 'exposure' ? 'aria-current="page"' : ''}>Exposure <span class="newtag">new</span></a>
    </nav>`;
  $('#topnav .logout').onclick = () => toast('Logout is disabled in this concept demo');
}

// ---------- exposure view ----------
function exposureView() {
  const C = state.checked, I = state.immediate, R = state.data;
  const held = C.log.filter((l) => l.decision === 'hold');
  const pending = held.filter((l) => !state.decisions[l.change.id]);
  const withAlt = held.filter((l) => l.alt && l.alt.safe && l.alt.coversIntent);
  const dead = C.log.filter((l) => l.decision === 'dead');
  const auto = C.log.filter((l) => l.decision === 'auto');
  const cur = state.mode === 'checked' ? C : I;
  const tabs = [['held', 'Held for you', held.length], ['auto', 'Applied', auto.length], ['dead', 'Never matches', dead.length], ['all', 'All', C.log.length]];
  let rows = C.log.filter((l) => state.tab === 'all' || l.decision === (state.tab === 'held' ? 'hold' : state.tab));
  const q = state.q.trim().toLowerCase();
  if (q) rows = rows.filter((l) => `${agent(l.change.agent).name} ${l.change.ask} ${l.change.rule ? tun(l.change.rule.tunnel).name + ' ' + l.change.rule.dst_port + ' ' + l.change.rule.protocol : 'link all'}`.toLowerCase().includes(q));
  rows = rows.slice().reverse();
  state.rows = rows.map((l) => l.change.id);
  const health = ruleHealth(C.account);
  return `
  <div class="head"><div class="grow">
    <p class="eyebrow">Agentic Defined Networking</p>
    <h1 class="page-title">Exposure Check</h1>
    <p class="page-desc">Every firewall change an agent makes through the API or MCP is checked before it takes effect. Exposure Check computes exactly which packets the change would newly let in, and from whom: the public internet, any doxx.net user, or only your devices. Changes that open a sensitive service to strangers wait for you, with a safer rule that still does the job.</p>
  </div>
  <div class="seg" role="group" aria-label="Compare">
    <button type="button" data-mode="checked" aria-pressed="${state.mode === 'checked'}">With Exposure Check</button><button type="button" data-mode="immediate" aria-pressed="${state.mode === 'immediate'}">Applied as-is (today)</button>
  </div></div>
  <div class="tiles">
    <div class="tile"><div class="lab">Sensitive services exposed</div><div class="val ${C.exposures.length ? 'red' : 'teal'}">${C.exposures.length}<small>vs ${I.exposures.length} if applied as-is</small></div><div class="note">${I.exposures.filter((x) => x.audience === 'internet').length} of those ${I.exposures.length} would be reachable from the public internet</div></div>
    <div class="tile"><div class="lab">Agent changes, 30 days</div><div class="val">${C.log.length}</div><div class="note">${auto.length} applied automatically: nothing sensitive opened to strangers</div></div>
    <div class="tile"><div class="lab">Held for you</div><div class="val ${pending.length ? '' : 'teal'}">${pending.length}<small>of ${held.length}</small></div><div class="note">${withAlt.length} came with a verified safer rule that still meets the request</div></div>
    <div class="tile"><div class="lab">Rules that could never match</div><div class="val">${dead.length}</div><div class="note">Caught before they failed silently, plus ${health.filter((h) => h.kind === 'dead').length} already on the account</div></div>
  </div>
  <div class="cols">
    <section class="card" aria-labelledby="h-changes">
      <h2 class="card-title" id="h-changes">Agent changes</h2>
      <p class="card-sub">From ${R.account.agents.map((a) => a.name).join(', ')} (net-admin tokens). Click a change to see exactly what it opens.</p>
      <div class="tabs" role="tablist">${tabs.map(([k, l, n]) => `<button class="tab" role="tab" data-tab="${k}" aria-selected="${state.tab === k}">${l}${n ? `<span class="badge">${n}</span>` : ''}</button>`).join('')}</div>
      <div class="filter"><input id="q" type="search" placeholder="Filter changes" aria-label="Filter changes" value="${esc(state.q)}" autocomplete="off" /></div>
      ${rows.length ? `<div class="rt"><div class="rt-h"><span class="c-time">Time</span><span class="c-agent">Agent</span><span class="c-change">Change</span><span class="c-aud">Opens to</span><span class="c-dec">Status</span></div>
      ${rows.slice(0, 60).map((l, k) => `<button class="row" type="button" data-change="${l.change.id}" data-selected="${state.sel === k}"><span class="c-time">${when(l.change.at)}</span><span class="c-agent">${esc(agent(l.change.agent).name)}</span><span class="c-change">${changeText(l.change)}</span><span class="c-aud">${audiencePill(l)}</span><span class="c-dec">${decisionPill(l)}</span></button>`).join('')}
      </div>${rows.length > 60 ? `<div class="empty">Showing the latest 60 of ${rows.length}. Refine the filter to see more.</div>` : ''}` : `<div class="empty">${state.q ? 'No results match your filter.' : 'Nothing here.'}</div>`}
    </section>
    <div class="stack">
      <section class="card" aria-labelledby="h-expo">
        <h2 class="card-title" id="h-expo">${state.mode === 'checked' ? 'Exposure now' : 'Exposure if applied as-is'}</h2>
        <p class="card-sub">Who can reach each device, computed exactly from the rules${cur.account.linkAll ? ' and Link All' : ''}. Red ports are sensitive services.</p>
        ${exposureMap(cur)}
      </section>
      <section class="card" aria-labelledby="h-health">
        <h2 class="card-title" id="h-health">Rule health</h2>
        <p class="card-sub">Rules that can never match or are fully covered by other rules.</p>
        ${health.length ? health.map((h) => `<div class="health-row"><span class="pill ${h.kind === 'dead' ? 'p-purple' : 'p-dim'}">${h.kind === 'dead' ? 'Never matches' : 'Redundant'}</span><div style="flex:1;min-width:0"><div><span class="proto">${esc(h.rule.protocol)}</span> ${esc(h.rule.dst_port || '')} <span class="faint">from</span> ${esc(srcLabel(h.rule.src_ip))} <span class="faint">→</span> ${esc(tun(h.rule.tunnel).name)}</div><div class="faint" style="margin-top:2px">${esc(h.reason)}</div></div><button class="linkbtn" data-remove="${h.index}">Remove</button></div>`).join('') : '<div class="empty">All rules are live and distinct.</div>'}
      </section>
      <div style="display:flex;gap:8px;justify-content:flex-end"><button class="btn btn-ghost-glass btn-sm" data-act="export-json">Export report</button><button class="btn btn-ghost-glass btn-sm" data-act="export-csv">Export CSV</button>${Object.keys(state.decisions).length || state.manual.length || state.removed.length ? '<button class="btn btn-ghost-glass btn-sm" data-act="reset">Reset demo</button>' : ''}</div>
    </div>
  </div>
  <p class="faint" style="font-size:11px;margin-top:16px">Exact set algebra over (destination, source address, protocol, port) boxes; computed in ${state.ms.toFixed(0)} ms in your browser. Sensitive-service evidence from the CISA Known Exploited Vulnerabilities catalog ${esc(state.kev?.catalogVersion || '')}.</p>`;
}

function exposureMap(res) {
  const acct = res.account;
  const cls = byClass(acct, res.finalSet);
  const forb = forbiddenSet(acct, state.data.policy);
  const rows = acct.tunnels.map((t) => {
    const line = (aud, label) => {
      const groups = describe(acct, cls[aud]).filter((g) => g.endpoint.tunnel === t.id);
      if (!groups.length) return '';
      const chips = groups.flatMap((g) => g.proto === 'ICMP' ? ['<span class="port">ping</span>'] : g.ports.map(([lo, hi]) => {
        const bad = aud !== 'own' && state.data.policy.sensitive.some((s) => s.port >= lo && s.port <= hi && g.proto === 'TCP');
        return `<span class="port ${bad ? 'bad' : ''}" title="${g.proto} ${fmtPorts([[lo, hi]])}${bad ? ' · sensitive' : ''}">${g.proto === 'UDP' ? 'udp ' : ''}${fmtPorts([[lo, hi]])}</span>`;
      }));
      return `<div class="aud-line"><span class="who">${label}</span>${chips.slice(0, 8).join('')}${chips.length > 8 ? `<span class="faint">+${chips.length - 8}</span>` : ''}</div>`;
    };
    const lines = line('internet', 'Public internet') + line('doxx', 'All doxx.net users') + line('own', 'Your devices');
    return `<div class="expo-t"><div class="nm"><span class="online"></span>${esc(t.name)} <span class="ad mono">${esc(t.v4)}</span></div>${lines || '<div class="aud-line"><span class="who faint">Nothing reachable</span></div>'}</div>`;
  });
  return rows.join('');
}

// ---------- review panel ----------
function openReview(id) {
  const C = state.checked;
  const l = C.log.find((x) => x.change.id === id);
  if (!l) return;
  setParam('change', id);
  const ch = l.change, a = agent(ch.agent);
  const t = ch.rule ? tun(ch.rule.tunnel) : null;
  const acct = C.account;
  const audLabel = { internet: 'Public internet', doxx: 'All doxx.net users', own: 'Your devices' };
  const opened = ['internet', 'doxx', 'own'].flatMap((aud) => describe(acct, l.openedBy[aud]).map((g) => {
    const fam = g.endpoint.fam, full = fam === 6 ? 128 : 32;
    const lg = log2(g.sources);
    const who = aud === 'internet' ? (lg >= full - 1 ? `any ${fam === 6 ? 'IPv6' : 'IPv4'} address` : `${bigCount(g.sources)} internet addresses`) : aud === 'doxx' ? `any doxx.net tunnel (${bigCount(g.sources)} addresses)` : 'your own devices';
    return `<div>${audLabel[aud]}</div><div><span class="proto">${g.proto}</span> ${g.proto === 'ICMP' ? '' : esc(fmtPorts(g.ports))} <span class="faint">on ${esc(tun(g.endpoint.tunnel).name)} ${esc(g.endpoint.addr)} · from ${who}</span></div>`;
  })).join('');
  const w = l.witness;
  const eps = endpoints(acct);
  const wtext = w ? (() => { const ep = eps[Number(w.e)]; const pr = PROTO_NAME[Number(w.proto)]; const src = formatAddr(ep.fam, w.src); return `${pr}  ${ep.fam === 6 ? '[' + src + ']' : src}:${w.sport}  →  ${ep.fam === 6 ? '[' + ep.addr + ']' : ep.addr}:${pr === 'ICMP' ? '-' : w.dport}\nbefore: dropped (default deny)    after: accepted`; })() : '';
  const port = ch.rule?.dst_port, svc = svcName(port), kev = kevFor(port);
  const dec = state.decisions[id];
  let verdict = '';
  if (l.decision === 'hold') verdict = `<div class="verdict red">${shieldSvg('#ff4d6a')}<div><b>Held: opens ${esc(svc || 'a sensitive service')} (TCP ${esc(port)}) to ${!isEmpty(l.openedBy.internet) ? 'the public internet' : 'every doxx.net user'}.</b> Your guardrail says agents may not do this without you.${kev && kev.kev ? ` CISA lists ${kev.kev} actively exploited ${esc(kev.service)} vulnerabilities${kev.ransomware ? `, ${kev.ransomware} used in ransomware` : ''}.` : ''}${ch.rule && ch.rule.dst_ip.includes(':') ? ' The tunnel\'s IPv6 address is public, so an IPv6 allowance reaches the whole internet.' : ''}</div></div>`;
  else if (l.decision === 'dead') { const hint = deadRuleHint(acct, ch.rule); verdict = `<div class="verdict yellow">${shieldSvg('#f5c122')}<div><b>Not applied: this rule could never match.</b> ${ch.rule.dst_ip === t.v4 ? `The source ${esc(ch.rule.src_ip)} is a public address, but ${esc(t.v4)} is ${esc(t.name)}'s internal doxx.net IPv4, which only other doxx.net tunnels can send to.` : `The source and destination are different address families (${esc(ch.rule.src_ip)} vs ${esc(ch.rule.dst_ip)}).`} Applied as-is it would fail silently.${hint ? ` Did the agent mean the dedicated IPv4 <span class="mono">${esc(hint.dst_ip)}</span>? That version would be checked as its own change.` : ''}</div></div>`; }
  else verdict = `<div class="verdict teal">${shieldSvg('#1bc1bc')}<div><b>Applied automatically.</b> ${ch.op === 'delete' ? 'Removing a rule only closes access.' : !isEmpty(l.openedBy.internet) || !isEmpty(l.openedBy.doxx) ? 'It opens a non-sensitive service, which your guardrail allows.' : 'It only opens traffic between your own devices.'}</div></div>`;
  const alt = l.alt;
  const altHtml = l.decision === 'hold' ? (alt && alt.safe && alt.coversIntent ? `<div class="sect">Safer alternative</div>
      <div class="codebox">${alt.rules.map((r) => `${r.protocol} ${r.dst_port}  from ${r.src_ip}  →  ${tun(r.tunnel).name} ${r.dst_ip}`).join('\n')}</div>
      <div class="checks"><span class="pill p-teal">✓ Still lets ${esc(ch.intentFrom.map((x) => tun(x).name).join(', '))} reach it</span><span class="pill p-teal">✓ Opens nothing to the internet or other doxx.net users</span><span class="pill p-dim">verified exactly, not sampled</span></div>`
    : `<div class="sect">Safer alternative</div><div class="empty" style="text-align:left">None: the request itself needs access from outside your devices (${esc(ch.intentExternal || 'outside sources')}). Approve it only if you mean it.</div>`) : '';
  const done = dec ? `<p class="faint" style="font-size:12px;margin:14px 0 0">Decision: ${dec === 'safer' ? 'safer rule applied' : dec === 'approve' ? 'approved as proposed' : 'rejected'}. <button class="linkbtn" data-undo="${id}">Undo</button></p>` : '';
  $('#overlay-root').innerHTML = `<div class="overlay" data-close><div class="glass panel" role="dialog" aria-modal="true" aria-labelledby="rv-t">
    <div class="panel-top"><div class="panel-h">${shieldSvg('#1bc1bc')}<h2 id="rv-t">Change #${id}</h2><button class="closebtn" data-close aria-label="Close">${xSvg()}</button></div>
      <div class="panel-sub">${esc(a.name)} · ${t ? `${esc(t.name)}: ${esc(t.v4)} / ${esc(t.v6)}` : 'all tunnels'}</div>
      <div class="panel-desc">“${esc(ch.ask)}” · ${when(ch.at)} · token ${esc(a.token)}</div></div>
    ${verdict}
    <div class="sect">Proposed</div>
    <div class="rt"><div class="rt-h"><span style="width:64px">Proto</span><span style="width:70px;text-align:right">Port</span><span style="flex:1">Source IP</span><span style="width:250px">Destination</span></div>
      ${ch.op === 'link_all' ? `<div class="row" style="cursor:default"><span style="width:64px" class="proto">ALL</span><span style="width:70px;text-align:right" class="dim">all</span><span style="flex:1">Your tunnels</span><span style="width:250px" class="dim">Your tunnels (full mesh)</span></div>` : `<div class="row" style="cursor:default"><span style="width:64px" class="proto">${esc(ch.rule.protocol)}</span><span style="width:70px;text-align:right" class="dim">${esc(ch.rule.dst_port || (ch.rule.protocol === 'ICMP' ? '-' : 'all'))}</span><span style="flex:1">${esc(srcLabel(ch.rule.src_ip))}</span><span style="width:250px" class="dim mono">${esc(ch.rule.dst_ip)}</span></div>`}</div>
    ${opened ? `<div class="sect">What it newly lets in (exact)</div><div class="opened">${opened}</div>` : ch.op === 'delete' ? '<div class="sect">What it closes</div><div class="dim" style="font-size:13px">Removes access that only this rule allowed.</div>' : ''}
    ${wtext && l.decision !== 'dead' ? `<div class="sect">Example packet</div><div class="codebox">${esc(wtext)}</div>` : ''}
    ${altHtml}${done}
    <div class="actions">${l.decision === 'hold' && !dec ? `<button class="btn btn-red btn-md" data-decide="reject">Reject</button><button class="btn btn-ghost-glass btn-md" data-decide="approve">Approve as proposed</button>${alt && alt.safe && alt.coversIntent ? '<button class="btn btn-teal btn-md" data-decide="safer">Apply safer rule</button>' : ''}` : '<button class="btn btn-ghost-glass btn-md" data-close>Close</button>'}</div>
  </div></div>`;
  const root = $('#overlay-root');
  root.querySelectorAll('[data-close]').forEach((el) => el.addEventListener('click', (e) => { if (e.target === el || el.tagName === 'BUTTON') closeOverlay(); }));
  root.querySelectorAll('[data-decide]').forEach((b) => b.addEventListener('click', () => decide(id, b.dataset.decide)));
  root.querySelectorAll('[data-undo]').forEach((b) => b.addEventListener('click', () => { delete state.decisions[id]; save(); compute(); render(); openReview(id); }));
  root.querySelector('.closebtn').focus();
}
function decide(id, d) {
  state.decisions[id] = d; save(); compute(); closeOverlay(); render();
  toast(d === 'safer' ? `Change #${id}: safer rule applied` : d === 'approve' ? `Change #${id} approved as proposed` : `Change #${id} rejected`);
}
function closeOverlay() { if (!$('#overlay-root').innerHTML) return false; $('#overlay-root').innerHTML = ''; setParam('change', null); setParam('fw', null); return true; }
const shieldSvg = (c) => `<svg viewBox="0 0 512 512" width="22" height="22" aria-hidden="true" style="flex:none"><g fill="none" stroke="${c}" stroke-width="28" stroke-linecap="round" stroke-linejoin="round"><path d="M256 56 L96 144 L96 272 C96 384 256 464 256 464 C256 464 416 384 416 272 L416 144 Z"/><polyline points="192,260 236,308 328,212"/></g></svg>`;
const xSvg = () => '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const fwSvg = () => '<svg viewBox="0 0 24 24" width="32" height="32" aria-hidden="true" style="color:#fff"><g fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></g></svg>';

// ---------- tunnel list + firewall configuration ----------
function tunnelsView() {
  const C = state.checked, acct = C.account, cls = byClass(acct, C.finalSet);
  return `<div class="head"><div class="grow"><p class="eyebrow">My Network</p><h1 class="page-title">Tunnel List</h1><p class="page-desc">${acct.tunnels.length} tunnels · Link All ${acct.linkAll ? 'on' : 'off'} · ${acct.rules.length} firewall rules</p></div></div>
  <div class="tunnels">${acct.tunnels.map((t) => {
    const pub = describe(acct, cls.internet).filter((g) => g.endpoint.tunnel === t.id).length;
    const dx = describe(acct, cls.doxx).filter((g) => g.endpoint.tunnel === t.id).length;
    return `<div class="tcard"><h3><span class="online"></span>${esc(t.name)}</h3><div class="meta">${esc(t.v4)} · ${esc(t.v6)}${t.dedicatedV4 ? ' · ' + esc(t.dedicatedV4) : ''}</div>
      <div class="dim" style="font-size:12px;margin-top:8px">${esc(t.kind)} · ${esc(t.server)}.doxx.net · ${acct.rules.filter((r) => r.tunnel === t.id).length} rules</div>
      <div class="checks">${pub ? '<span class="pill p-yellow">Reachable from internet</span>' : ''}${dx ? '<span class="pill p-yellow">Open to doxx.net users</span>' : ''}${!pub && !dx ? '<span class="pill p-blue">Your devices only</span>' : ''}</div>
      <div style="margin-top:12px"><a class="btn btn-ghost-glass btn-sm" href="#/ops/tunnels?fw=${t.id}" style="text-decoration:none">Firewall</a></div></div>`;
  }).join('')}</div>`;
}
function openFirewall(tid) {
  const C = state.checked, acct = C.account, t = tun(tid);
  setParam('fw', tid);
  const rules = acct.rules.filter((r) => r.tunnel === tid);
  const fs = state.fw || (state.fw = { open: false, addr: t.v6, proto: 'TCP', port: '22', src: '::/0', tab: 'custom' });
  if (fs.tid !== tid) Object.assign(fs, { tid, open: false, addr: t.v6, proto: 'TCP', port: '22', src: '::/0' });
  const preview = () => {
    if (!fs.open) return '';
    const rule = { tunnel: tid, protocol: fs.proto, src_ip: fs.src.trim() || '::/0', dst_ip: fs.addr, dst_port: fs.proto === 'ICMP' ? '' : fs.port.trim() };
    let rv; try { rv = reviewChange(acct, { op: 'add', rule }, state.data.policy); } catch { return '<div class="verdict yellow"><div>Enter a valid source IP or CIDR.</div></div>'; }
    fs.last = { rule, rv };
    if (rv.decision === 'dead') return `<div class="verdict yellow">${shieldSvg('#f5c122')}<div><b>This rule could never match.</b> The source and destination can't reach each other (internal IPv4 only receives from doxx.net tunnels; families must match).</div></div>`;
    if (rv.decision === 'hold') return `<div class="verdict red">${shieldSvg('#ff4d6a')}<div><b>Opens ${esc(svcName(rule.dst_port) || 'a sensitive service')} to ${!isEmpty(rv.openedBy.internet) ? 'the public internet' : 'every doxx.net user'}.</b> Agents can't do this without approval. Narrow the source to one of your devices, or add it anyway.</div></div>`;
    const aud = !isEmpty(rv.openedBy.internet) ? 'the public internet' : !isEmpty(rv.openedBy.doxx) ? 'all doxx.net users' : !isEmpty(rv.openedBy.own) ? 'your devices only' : 'nothing new';
    return `<div class="verdict teal">${shieldSvg('#1bc1bc')}<div><b>Opens to ${aud}.</b> Within your guardrail.</div></div>`;
  };
  const presetOn = (p) => rules.some((r) => (p === 'icmp' ? r.protocol === 'ICMP' : r.protocol === 'TCP' && (p === 'ssh' ? r.dst_port === '22' : r.dst_port === '80' || r.dst_port === '443')));
  const draw = () => {
    $('#overlay-root').innerHTML = `<div class="overlay" data-close><div class="glass panel" role="dialog" aria-modal="true" aria-labelledby="fw-t">
      <div class="panel-top"><div class="panel-h">${fwSvg()}<h2 id="fw-t">Firewall Configuration</h2><button class="closebtn" data-close aria-label="Close">${xSvg()}</button></div>
        <div class="panel-sub">${esc(t.name)}: ${esc(t.v4)} / ${esc(t.v6)}</div><div class="panel-desc">Control traffic filtering between tunnels and external destinations by protocol, port, and IP.</div></div>
      <div class="toggle-card"><div class="toggle-row">Enable Firewall Protection<button class="sw" role="switch" aria-checked="true" aria-label="Enable Firewall Protection"></button></div><div class="note">ⓘ ${t.dedicatedV4 ? 'Dedicated IPv4 ' + esc(t.dedicatedV4) + ' is public.' : 'Private tunnel: rules apply within the doxx network only.'} IPv6 ${esc(t.v6)} is public.</div></div>
      <div class="card" style="margin-top:20px"><h3 class="card-title" style="margin-bottom:12px">Inbound Allows</h3>
        <div class="presets"><button class="chip" aria-pressed="${presetOn('ssh')}" data-preset="22">SSH (22)</button><button class="chip" aria-pressed="${presetOn('web')}" data-preset="443">Web (80/443)</button><button class="chip" aria-pressed="${presetOn('icmp')}" data-preset="icmp">ICMP (Ping)</button>${fs.open ? '' : '<button class="btn btn-teal btn-md" data-act="open" style="margin-left:auto">+ Add Custom Rule</button>'}</div>
        ${fs.open ? `<div class="form-row">
          <div class="fld" style="max-width:190px"><label for="f-addr">Address</label><select id="f-addr">${[[t.v4, 'IPv4 (doxx.net only)'], [t.v6, 'IPv6 (public)'], ...(t.dedicatedV4 ? [[t.dedicatedV4, 'Dedicated IPv4 (public)']] : [])].map(([v, l]) => `<option value="${esc(v)}" ${fs.addr === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
          <div class="fld" style="max-width:110px"><label for="f-proto">Protocol</label><select id="f-proto">${['TCP', 'UDP', 'ICMP', 'ALL'].map((p) => `<option ${fs.proto === p ? 'selected' : ''}>${p}</option>`).join('')}</select></div>
          <div class="fld" style="max-width:120px"><label for="f-port">Port(s)</label><input id="f-port" value="${esc(fs.port)}" ${fs.proto === 'ICMP' ? 'disabled' : ''} /></div>
          <div class="fld"><label for="f-src">Source IP</label><input id="f-src" value="${esc(fs.src)}" placeholder="::/0 or 10.13.7.21/32" /></div></div>
          <div id="fw-preview">${preview()}</div>
          <div class="actions" style="margin-top:12px"><button class="btn btn-ghost-glass btn-md" data-act="cancel">Cancel</button><button class="btn btn-teal btn-md" data-act="add">${fs.last && fs.last.rv.decision === 'hold' ? 'Add anyway' : 'Add'}</button></div>` : ''}
        <div class="tabs" style="margin-top:18px" role="tablist"><button class="tab" role="tab" aria-selected="true">Custom Rules<span class="badge">${rules.length}</span></button>${acct.linkAll ? `<button class="tab" role="tab" aria-selected="false">Tunnel Links<span class="badge">${acct.tunnels.length - 1}</span></button>` : ''}</div>
        ${rules.length ? `<div class="rt"><div class="rt-h"><span style="width:64px">Proto</span><span style="width:56px;text-align:right">Port</span><span style="flex:1">Source IP</span><span style="width:36px"></span></div>${rules.map((r, k) => `<div class="row" style="cursor:default"><span style="width:64px" class="proto">${esc(r.protocol)}</span><span style="width:56px;text-align:right" class="dim">${esc(r.dst_port || '-')}</span><span style="flex:1">${esc(srcLabel(r.src_ip))} <span class="faint mono">→ ${esc(r.dst_ip)}</span></span><button class="linkbtn" data-del="${k}" aria-label="Delete rule" style="width:36px">✕</button></div>`).join('')}</div>` : '<p class="empty">No custom rules yet.</p>'}
      </div></div></div>`;
    const root = $('#overlay-root');
    root.querySelectorAll('[data-close]').forEach((el) => el.addEventListener('click', (e) => { if (e.target === el || el.tagName === 'BUTTON') closeOverlay(); }));
    const rd = () => { const p = $('#fw-preview'); if (p) { p.innerHTML = preview(); const add = root.querySelector('[data-act="add"]'); if (add) add.textContent = fs.last && fs.last.rv.decision === 'hold' ? 'Add anyway' : 'Add'; } };
    root.querySelector('[data-act="open"]')?.addEventListener('click', () => { fs.open = true; draw(); });
    root.querySelector('[data-act="cancel"]')?.addEventListener('click', () => { fs.open = false; draw(); });
    root.querySelector('#f-addr')?.addEventListener('change', (e) => { fs.addr = e.target.value; fs.src = fs.addr.includes(':') ? '::/0' : '0.0.0.0/0'; draw(); });
    root.querySelector('#f-proto')?.addEventListener('change', (e) => { fs.proto = e.target.value; draw(); });
    root.querySelector('#f-port')?.addEventListener('input', (e) => { fs.port = e.target.value; rd(); });
    root.querySelector('#f-src')?.addEventListener('input', (e) => { fs.src = e.target.value; rd(); });
    root.querySelector('[data-act="add"]')?.addEventListener('click', () => { if (!fs.last) return; state.manual.push(fs.last.rule); save(); compute(); fs.open = false; draw(); render(true); toast(fs.last.rv.decision === 'hold' ? 'Rule added with your approval' : 'Rule added'); });
    root.querySelectorAll('[data-preset]').forEach((b) => b.addEventListener('click', () => { fs.open = true; fs.proto = b.dataset.preset === 'icmp' ? 'ICMP' : 'TCP'; fs.port = b.dataset.preset === 'icmp' ? '' : b.dataset.preset; fs.addr = t.v6; fs.src = '::/0'; draw(); }));
    root.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', () => { state.removed.push(rules[+b.dataset.del]); save(); compute(); draw(); render(true); toast('Rule deleted'); }));
  };
  draw();
}

function placeholder(name) {
  return `<div class="head"><div class="grow"><p class="eyebrow">doxx.net</p><h1 class="page-title">${esc(name)}</h1><p class="page-desc">Not part of this concept demo. <a href="#/ops/tunnels/exposure">Open Exposure Check</a></p></div></div>`;
}

// ---------- render ----------
function render(keepOverlay = false) {
  if (!state.data) return;
  const { parts, params } = route();
  if (params.get('tab') && ['held', 'auto', 'dead', 'all'].includes(params.get('tab'))) state.tab = params.get('tab');
  const sec = parts[1] || 'tunnels';
  let sub = 'exposure', html;
  if (sec === 'tunnels') {
    if (parts[2] === 'exposure') { sub = 'exposure'; html = exposureView(); }
    else if (!parts[2]) { sub = 'list'; html = tunnelsView(); }
    else { sub = parts[2] === 'topology' ? 'topology' : 'saved'; html = placeholder(sub === 'topology' ? 'Topology' : 'Saved Connections'); }
  } else html = placeholder({ security: 'Security', chatnet: 'ChatNET', dns: 'DNS & PKI', account: 'Account' }[sec] || 'Not found');
  renderNav(sub);
  $('#main').innerHTML = html;
  document.title = `${sub === 'exposure' ? 'Exposure Check' : sub === 'list' ? 'Tunnel List' : 'doxx.net'} · doxx.net`;
  wire();
  if (!keepOverlay) {
    if (params.has('change')) openReview(Number(params.get('change')));
    else if (params.has('fw') && tun(params.get('fw'))) openFirewall(params.get('fw'));
  }
}
function wire() {
  const m = $('#main');
  m.querySelectorAll('[data-mode]').forEach((b) => b.addEventListener('click', () => { state.mode = b.dataset.mode; render(); }));
  m.querySelectorAll('[data-tab]').forEach((b) => b.addEventListener('click', () => { state.tab = b.dataset.tab; state.sel = -1; setParam('tab', state.tab); render(); }));
  m.querySelectorAll('[data-change]').forEach((b) => b.addEventListener('click', () => openReview(Number(b.dataset.change))));
  m.querySelectorAll('[data-remove]').forEach((b) => b.addEventListener('click', () => { const h = ruleHealth(state.checked.account).find((x) => String(x.index) === b.dataset.remove); if (h) { state.removed.push(h.rule); save(); compute(); render(); toast('Rule removed'); } }));
  const q = $('#q'); if (q) q.addEventListener('input', () => { state.q = q.value; const p = q.selectionStart; render(); const n = $('#q'); n.focus(); n.setSelectionRange(p, p); });
  m.querySelector('[data-act="export-json"]')?.addEventListener('click', exportJson);
  m.querySelector('[data-act="export-csv"]')?.addEventListener('click', exportCsv);
  m.querySelector('[data-act="reset"]')?.addEventListener('click', () => { state.decisions = {}; state.manual = []; state.removed = []; save(); compute(); render(); toast('Demo reset'); });
  m.querySelectorAll('a[href*="?fw="]').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); openFirewall(new URLSearchParams(a.getAttribute('href').split('?')[1]).get('fw')); }));
}
function exportCsv() {
  const head = ['change_id', 'time', 'agent', 'request', 'operation', 'tunnel', 'protocol', 'port', 'source', 'destination', 'opens_to', 'check_result', 'your_decision', 'safer_rule'];
  const rows = state.checked.log.map((l) => { const c = l.change, r = c.rule || {}; const o = !isEmpty(l.openedBy.internet) ? 'internet' : !isEmpty(l.openedBy.doxx) ? 'all-doxx-users' : !isEmpty(l.openedBy.own) ? 'own-devices' : 'none'; return [c.id, c.at, agent(c.agent).name, c.ask, c.op, r.tunnel || '', r.protocol || '', r.dst_port || '', r.src_ip || '', r.dst_ip || '', o, l.decision, state.decisions[c.id] || '', l.alt && l.alt.safe ? l.alt.rules.map((x) => `${x.protocol} ${x.dst_port} from ${x.src_ip}`).join('; ') : '']; });
  const e = (v) => { const s = String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  dl('doxx-exposure-check.csv', [head, ...rows].map((r) => r.map(e).join(',')).join('\n') + '\n', 'text/csv');
}
function exportJson() {
  const C = state.checked, I = state.immediate;
  dl('doxx-exposure-report.json', JSON.stringify({ generatedAt: new Date().toISOString(), method: 'exact set algebra over (endpoint, source address, protocol, dst port, src port) boxes', exposuresWithCheck: C.exposures, exposuresAppliedAsIs: I.exposures, changes: C.log.map((l) => ({ id: l.change.id, at: l.change.at, agent: l.change.agent, request: l.change.ask, result: l.decision, decision: state.decisions[l.change.id] || null })), ruleHealth: ruleHealth(C.account).map((h) => ({ kind: h.kind, rule: h.rule, reason: h.reason })) }, null, 2), 'application/json');
}
function dl(name, text, type) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0); toast('Exported ' + name); }
function toast(msg) { const t = document.createElement('div'); t.className = 'toast'; t.setAttribute('role', 'status'); t.textContent = msg; document.body.appendChild(t); setTimeout(() => t.remove(), 2800); }

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { if (closeOverlay()) return; if (document.activeElement?.id === 'q') document.activeElement.blur(); return; }
  if (/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName) || $('#overlay-root').innerHTML || e.metaKey || e.ctrlKey) return;
  const rows = [...document.querySelectorAll('#main [data-change]')];
  if ((e.key === 'j' || e.key === 'k') && rows.length) { e.preventDefault(); state.sel = Math.max(0, Math.min(rows.length - 1, state.sel + (e.key === 'j' ? 1 : -1))); rows.forEach((r, i) => r.dataset.selected = String(i === state.sel)); rows[state.sel].scrollIntoView({ block: 'nearest' }); rows[state.sel].focus(); }
  else if (e.key === 'Enter' && state.sel >= 0 && rows[state.sel]) rows[state.sel].click();
  else if (e.key === '/') { const q = $('#q'); if (q) { e.preventDefault(); q.focus(); } }
  else if (e.key === 'e') exportJson();
});

async function boot() {
  try {
    const [d, kev] = await Promise.all([
      fetch('data/account.json').then((r) => { if (!r.ok) throw new Error('data/account.json ' + r.status); return r.json(); }),
      fetch('data/kev_ports.json').then((r) => (r.ok ? r.json() : null)).catch(() => null),
    ]);
    state.data = d; state.kev = kev;
    load();
    const p = route().params; if (p.get('tab')) state.tab = p.get('tab');
    compute();
    if (!location.hash) history.replaceState(null, '', '#/ops/tunnels/exposure');
    render();
  } catch (err) {
    console.error(err);
    $('#main').innerHTML = `<div class="card" role="alert" style="max-width:420px;margin:80px auto;text-align:center"><h2 class="card-title" style="justify-content:center">Failed to load</h2><p class="card-sub">${esc(err.message)}</p><button class="btn btn-teal btn-md" onclick="location.reload()">Retry</button></div>`;
  }
}
boot();

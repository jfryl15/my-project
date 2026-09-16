/* ===========================================================
   StanNG — dashboard controller (v1.5.3)
   Fully compatible with plain‑text subscription links
   (Info Configs + TLS), no Non‑TLS, no Clean IP.
   =========================================================== */
(() => {
  let currentInbounds = [];
  let lastHourly = [];
  let lastBuckets = null;
  let statusFilter = 'all';
  let currentPage = 1;
  const PAGE_SIZE = 10;

  // ---- status classifier (MUST mirror core/users.py priority) ----
  function classifyIb(ib, warnDays = 3) {
    const now = Date.now() / 1000;
    const used = (ib.used_up || 0) + (ib.used_down || 0);
    const quota = (ib.quota_gb || 0) * 1024 ** 3;
    if (ib.expire_at && now >= ib.expire_at) return 'expired';
    if (quota > 0 && used >= quota) return 'quota_reached';
    if (!ib.enabled) return 'disabled';
    if ((ib.max_requests || 0) > 0 && (ib.request_count || 0) >= ib.max_requests) return 'disabled';
    if (ib.expire_at && (ib.expire_at - now) / 86400 <= warnDays) return 'near_expiry';
    return 'active';
  }

  function remainingTxt(ib) {
    const used = (ib.used_up || 0) + (ib.used_down || 0);
    const quota = (ib.quota_gb || 0) * 1024 ** 3;
    if (!(ib.quota_gb > 0)) return STANNG.t('unlimited');
    return STANNG.fmtBytes(Math.max(0, quota - used));
  }

  function fmtDate(ts) {
    if (!ts) return '—';
    try {
      return new Date(ts * 1000).toLocaleDateString(STANNG.getLang() === 'fa' ? 'fa-IR' : 'en-US');
    } catch (e) { return '—'; }
  }

  // ---------------- guard: must be logged in ----------------
  STANNG.api('/api/me').then(me => {
    if (!me.logged_in) { window.location.href = '/login'; return; }
    document.getElementById('appVersion').textContent = me.app_version || '';
    const foot = document.getElementById('appVersionFoot');
    if (foot) foot.textContent = me.app_version || '';
    const mb = document.getElementById('maintBanner');
    if (mb) mb.style.display = me.maintenance ? '' : 'none';
    document.getElementById('otaCurrent').textContent = (me.settings && me.settings.app_version) || me.app_version;
    if (me.settings) {
      document.getElementById('settingPublicDomain').value = me.settings.public_domain || '';
      document.getElementById('settingKeepAlive').checked = me.settings.keep_alive !== false;
      document.getElementById('settingFingerprint').value = me.settings.default_fingerprint || 'chrome';
      document.getElementById('settingAlpn').value = me.settings.default_alpn || 'http/1.1';
      document.getElementById('settingSniOverride').value = me.settings.sni_override || '';
      document.getElementById('settingFragmentEnabled').checked = me.settings.fragment_enabled !== false;
      document.getElementById('settingFragmentPackets').value = me.settings.fragment_packets || 'tlshello';
      document.getElementById('settingFragmentLength').value = me.settings.fragment_length || '10-30';
      document.getElementById('settingFragmentInterval').value = me.settings.fragment_interval || '10-20';
      const _p = document.getElementById('settingPrefix'); if (_p) _p.value = me.settings.sub_remark_prefix || 'SsPanel';
      const _m = document.getElementById('settingMaint'); if (_m) _m.checked = !!me.settings.maintenance_enabled;
      const _mm = document.getElementById('settingMaintMsg'); if (_mm) _mm.value = me.settings.maintenance_message || '';
      const _a = document.getElementById('settingAutoDisable'); if (_a) _a.checked = me.settings.auto_disable_exhausted !== false;
      const _w = document.getElementById('settingWarnPct'); if (_w) _w.value = me.settings.quota_warn_percent || 80;
      const _d = document.getElementById('settingWarnDays'); if (_d) _d.value = me.settings.expiry_warn_days || 3;
    }
  }).catch(() => { window.location.href = '/login'; });

  document.getElementById('settingSound').checked = STANNG.isSoundEnabled();

  // ---------------- nav / view switching ----------------
  const views = document.querySelectorAll('.view');
  const navItems = document.querySelectorAll('.nav-item[data-view]');
  const viewTitle = document.getElementById('viewTitle');
  const titleKeys = { dashboard: 'nav_dashboard', inbounds: 'nav_inbounds', traffic: 'nav_traffic', plans: 'nav_plans', servers: 'nav_servers', monitoring: 'nav_monitoring', map: 'nav_map', compare: 'nav_compare', alerts: 'nav_alerts', events: 'nav_events', analytics: 'nav_analytics', live: 'nav_live', notifications: 'nav_notifications', shop: 'nav_shop', ai: 'nav_ai', extensions: 'nav_extensions', diagnostics: 'nav_diagnostics', xray: 'nav_xray', telegram: 'nav_telegram', api: 'nav_api', backup: 'nav_backup', logs: 'nav_logs', security: 'nav_security', settings: 'nav_settings' };

  function showView(name) {
    views.forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
    navItems.forEach(n => n.classList.toggle('active', n.dataset.view === name));
    viewTitle.setAttribute('data-i18n', titleKeys[name] || 'nav_dashboard');
    viewTitle.textContent = STANNG.t(titleKeys[name] || 'nav_dashboard');
    if (name === 'inbounds') loadInbounds();
    if (name === 'traffic') loadInbounds();
    if (name === 'telegram' && window.PREMIUM) window.PREMIUM.loadTelegram();
    if (name === 'api' && window.PREMIUM) window.PREMIUM.loadTokens();
    if (name === 'logs' && window.PREMIUM) window.PREMIUM.loadAudit();
    if (name === 'plans' && window.PREMIUM) window.PREMIUM.loadPlans();
    if (name === 'servers' && window.PREMIUM) window.PREMIUM.loadServers();
    if (name === 'monitoring' && window.PREMIUM) window.PREMIUM.loadMonitoring();
    if (name === 'analytics' && window.PREMIUM) window.PREMIUM.loadAnalytics();
    if (name === 'live' && window.PREMIUM) window.PREMIUM.startLive();
    else if (window.PREMIUM) window.PREMIUM.stopLive();
    if (name === 'notifications' && window.PREMIUM) window.PREMIUM.loadNotifications();
    if (name === 'security' && window.PREMIUM) window.PREMIUM.loadSecurity();
    if (name === 'backup' && window.PREMIUM) window.PREMIUM.loadBackups();
    if (name === 'shop' && window.PREMIUM) window.PREMIUM.loadShop();
    if (name === 'ai' && window.PREMIUM) window.PREMIUM.loadAi();
    if (name === 'extensions' && window.PREMIUM) window.PREMIUM.loadExtensions();
    if (name === 'alerts' && window.PREMIUM) { window.PREMIUM.loadAlerts(); window.PREMIUM.loadThresholds(); }
    if (name === 'events' && window.PREMIUM) window.PREMIUM.loadEvents();
    if (name === 'map' && window.PREMIUM) window.PREMIUM.loadMap();
    if (name === 'compare' && window.PREMIUM) window.PREMIUM.loadCompare();
    if (name === 'dashboard' && window.PREMIUM) window.PREMIUM.loadMsStrip();
    if (name === 'xray' && window.PREMIUM) window.PREMIUM.loadXray();
    if (name === 'dashboard' && window.PREMIUM) window.PREMIUM.loadSystem();
    closeSidebarMobile();
    STANNG.playSfx('open', 0.3);
  }
  navItems.forEach(item => item.addEventListener('click', () => showView(item.dataset.view)));

  // Phase 4: re-render data-bound strings when language changes
  window.addEventListener('aloo-lang', () => {
    try {
      const s = document.getElementById('inboundSearch');
      renderInboundsTable(s ? s.value : '');
      renderTrafficTable();
    } catch (e) {}
    refreshStats();
    if (window.PREMIUM && window.PREMIUM.reloadActive) {
      try { window.PREMIUM.reloadActive(); } catch (e) {}
    }
  });

  // ---------------- mobile sidebar ----------------
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  document.getElementById('menuToggle').addEventListener('click', () => {
    const opening = !sidebar.classList.contains('open');
    sidebar.classList.toggle('open', opening);
    backdrop.classList.toggle('open', opening);
    document.body.classList.toggle('sidebar-locked', opening);
  });
  backdrop.addEventListener('click', closeSidebarMobile);
  function closeSidebarMobile() {
    sidebar.classList.remove('open');
    backdrop.classList.remove('open');
    document.body.classList.remove('sidebar-locked');
  }

  // ---------------- lang / theme ----------------
  document.querySelectorAll('.lang-toggle button').forEach(btn => {
    btn.addEventListener('click', () => {
      STANNG.setLang(btn.dataset.lang);
      viewTitle.textContent = STANNG.t(viewTitle.getAttribute('data-i18n'));
      STANNG.playSfx('toggle', 0.3);
    });
  });
  document.getElementById('themeToggle').addEventListener('click', () => {
    STANNG.setTheme(STANNG.getTheme() === 'dark' ? 'light' : 'dark');
    STANNG.playSfx('toggle', 0.3);
    renderTrafficChart(document.getElementById('trafficChart'), lastHourly);
  });
  document.getElementById('soundToggle').addEventListener('click', () => {
    const next = !STANNG.isSoundEnabled();
    STANNG.setSoundEnabled(next);
    document.getElementById('settingSound').checked = next;
    if (next) STANNG.playSfx('click');
  });

  // ---------------- logout ----------------
  document.getElementById('logoutBtn').addEventListener('click', async () => {
    await STANNG.api('/api/logout', { method: 'POST' });
    window.location.href = '/login';
  });

  // ---------------- modal helpers ----------------
  function openModal(id) {
    document.getElementById(id).classList.add('open');
    STANNG.playSfx('open', 0.4);
  }
  function closeModal(id) {
    document.getElementById(id).classList.remove('open');
    STANNG.playSfx('close', 0.4);
  }
  document.querySelectorAll('[data-close-modal]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
  });
  document.querySelectorAll('.modal-overlay').forEach(ov => {
    ov.addEventListener('click', (e) => { if (e.target === ov) closeModal(ov.id); });
  });

  // ---------------- dashboard stats polling ----------------
  async function refreshStats() {
    try {
      const s = await STANNG.api('/stats');
      document.getElementById('statCpu').textContent = s.cpu_percent.toFixed(1) + '%';
      document.getElementById('barCpu').style.width = Math.min(100, s.cpu_percent) + '%';
      document.getElementById('statMem').textContent = s.mem_percent.toFixed(1) + '%';
      document.getElementById('barMem').style.width = Math.min(100, s.mem_percent) + '%';
      document.getElementById('statUptime').textContent = STANNG.fmtDuration(s.uptime_seconds);
      const loc = s.location || {};
      document.getElementById('statLocation').textContent = `${loc.flag || ''} ${loc.city || '?'}`;
      document.getElementById('statTotalTraffic').textContent = STANNG.fmtBytes((s.total_up || 0) + (s.total_down || 0));
      document.getElementById('statUp').textContent = STANNG.fmtBytes(s.total_up || 0);
      document.getElementById('statDown').textContent = STANNG.fmtBytes(s.total_down || 0);
      document.getElementById('statActiveConn').textContent = s.active_connections || 0;
      document.getElementById('statInboundCount').textContent = s.inbounds_count || 0;
      document.getElementById('navInboundCount').textContent = s.inbounds_count || 0;
      document.getElementById('trafficUp').textContent = STANNG.fmtBytes(s.total_up || 0);
      document.getElementById('trafficDown').textContent = STANNG.fmtBytes(s.total_down || 0);
      lastHourly = s.hourly || [];
      renderTrafficChart(document.getElementById('trafficChart'), lastHourly);
      renderBuckets(s.users_by_status);
      renderServices(s.services);
      renderAlerts(s.alerts);
      renderActivity(s.recent_activity);
    } catch (e) { /* ignore transient errors */ }
  }
  refreshStats();
  setInterval(refreshStats, 8000);
  window.addEventListener('resize', () => renderTrafficChart(document.getElementById('trafficChart'), lastHourly));

  // ---------------- Phase 1 widgets: buckets / services / alerts / activity ----------------
  function renderBuckets(b) {
    if (!b) return;
    lastBuckets = b;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v || 0; };
    set('bucketActive', (b.active || 0) + (b.near_expiry || 0));
    set('bucketNear', b.near_expiry);
    set('bucketExpired', b.expired);
    set('bucketQuota', b.quota_reached);
    set('chipAll', b.total);
    set('chipActive', b.active);
    set('chipNear', b.near_expiry);
    set('chipExpired', b.expired);
    set('chipQuota', b.quota_reached);
    set('chipDisabled', b.disabled);
  }

  const ALERT_KEY = {
    users_expired: 'alert_users_expired', users_quota: 'alert_users_quota',
    users_near_expiry: 'alert_users_near_expiry', high_cpu: 'alert_high_cpu',
    high_mem: 'alert_high_mem', xray_offline: 'alert_xray_offline',
  };

  function renderAlerts(alerts) {
    const box = document.getElementById('alertsBox');
    const cnt = document.getElementById('alertsCount');
    if (!box) return;
    const list = alerts || [];
    if (cnt) cnt.textContent = list.length;
    if (!list.length) {
      box.innerHTML = `<div class="muted">${STANNG.t('alerts_empty')}</div>`;
      return;
    }
    box.innerHTML = list.map(a => {
      const dot = a.severity === 'error' ? 'dot-err' : 'dot-warn';
      const msg = `${a.count} ${STANNG.t(ALERT_KEY[a.code] || a.code)}`;
      return `<div class="alert-row"><span class="dot ${dot}"></span><span class="msg">${escapeHtml(msg)}</span></div>`;
    }).join('');
  }

  function renderServices(svc) {
    const box = document.getElementById('servicesBox');
    if (!box || !svc) return;
    const x = svc.xray || {};
    const xDot = x.status === 'online' ? 'dot-ok' : (x.status === 'mock' ? 'dot-warn' : 'dot-err');
    const xTxt = x.status === 'online' ? STANNG.t('svc_online') : (x.status === 'mock' ? STANNG.t('svc_mock') : STANNG.t('svc_offline'));
    const tg = svc.telegram || {};
    const tgDot = tg.enabled && tg.configured ? 'dot-ok' : (tg.configured ? 'dot-warn' : 'dot-mute');
    const tgTxt = tg.enabled && tg.configured ? STANNG.t('svc_on') : STANNG.t('svc_off');
    const db = svc.database || {};
    box.innerHTML = `
      <div class="svc-row"><span class="svc-name"><span class="dot ${xDot}"></span>${STANNG.t('svc_xray')}</span><span class="small muted">${xTxt}</span></div>
      <div class="svc-row"><span class="svc-name"><span class="dot dot-ok"></span>${STANNG.t('svc_db')}</span><b>${db.users || 0}</b></div>
      <div class="svc-row"><span class="svc-name"><span class="dot ${tgDot}"></span>${STANNG.t('svc_tg')}</span><span class="small muted">${tgTxt}</span></div>`;
  }

  function renderActivity(items) {
    const box = document.getElementById('activityBox');
    if (!box) return;
    const list = items || [];
    if (!list.length) {
      box.innerHTML = `<div class="muted">${STANNG.t('activity_empty')}</div>`;
      return;
    }
    box.innerHTML = list.slice(0, 8).map(l => {
      let time = '';
      try { time = new Date(l.ts * 1000).toLocaleString(STANNG.getLang() === 'fa' ? 'fa-IR' : 'en-US'); } catch (e) {}
      return `<div class="audit-item"><span class="audit-time">${time}</span><b>${escapeHtml(l.actor || '')}</b><span class="pill" style="font-size:.62rem;">${escapeHtml(window.ALOO_ACTION ? window.ALOO_ACTION(l.action) : (l.action || ''))}</span></div>`;
    }).join('');
  }

  document.querySelectorAll('.bucket-card').forEach(card => {
    card.addEventListener('click', () => {
      setStatusFilter(card.dataset.bucket === 'active' ? 'active' : card.dataset.bucket);
      document.querySelector('.nav-item[data-view="inbounds"]').click();
    });
  });

  document.querySelectorAll('#statusChips .chip').forEach(chip => {
    chip.addEventListener('click', () => setStatusFilter(chip.dataset.filter));
  });

  function setStatusFilter(f) {
    statusFilter = f;
    currentPage = 1;
    document.querySelectorAll('#statusChips .chip').forEach(c => c.classList.toggle('active', c.dataset.filter === f));
    document.querySelectorAll('.bucket-card').forEach(c => c.classList.toggle('selected', c.dataset.bucket === f));
    renderInboundsTable(document.getElementById('inboundSearch').value);
  }
  window.ALOO_SET_FILTER = setStatusFilter;

  // ---------------- OTA ----------------
  let otaLatestKnown = null;

  document.getElementById('otaCheckBtn').addEventListener('click', async () => {
    const btn = document.getElementById('otaCheckBtn');
    const updateBtn = document.getElementById('otaUpdateBtn');
    const hint = document.getElementById('otaUpdateHint');
    STANNG.setLoading(btn, true);
    try {
      const r = await STANNG.api('/api/ota/check');
      const el = document.getElementById('otaResult');
      if (r.update_available) {
        el.innerHTML = `<span style="color:var(--gold-300)">${STANNG.t('dash_ota_available')} <b>${r.latest}</b></span> — <a href="${r.url}" target="_blank" style="color:var(--azure); text-decoration:underline;">GitHub</a>`;
        STANNG.toast(STANNG.t('dash_ota_available') + ' ' + r.latest, 'info');
        otaLatestKnown = r.latest;
        updateBtn.style.display = '';
        hint.style.display = '';
      } else {
        el.innerHTML = `<span style="color:var(--emerald)">${STANNG.t('dash_ota_uptodate')}</span>`;
        STANNG.toast(STANNG.t('dash_ota_uptodate'), 'success');
        otaLatestKnown = null;
        updateBtn.style.display = 'none';
        hint.style.display = 'none';
      }
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
    } finally {
      STANNG.setLoading(btn, false);
    }
  });

  document.getElementById('otaUpdateBtn').addEventListener('click', async () => {
    const msg = STANNG.t('dash_ota_update_confirm').replace('{version}', otaLatestKnown || '');
    if (!confirm(msg)) return;

    const updateBtn = document.getElementById('otaUpdateBtn');
    const checkBtn = document.getElementById('otaCheckBtn');
    const el = document.getElementById('otaResult');
    STANNG.setLoading(updateBtn, true);
    checkBtn.disabled = true;

    try {
      const r = await STANNG.api('/api/ota/update', { method: 'POST' });
      if (r.ok) {
        el.innerHTML = `<span style="color:var(--gold-300)">${STANNG.t('dash_ota_updating')}</span>`;
        STANNG.toast(STANNG.t('dash_ota_updating'), 'info', 8000);
        waitForRestartThenReload();
      } else {
        el.innerHTML = `<span style="color:var(--emerald)">${STANNG.t('dash_ota_uptodate')}</span>`;
        STANNG.toast(STANNG.t('dash_ota_uptodate'), 'success');
        STANNG.setLoading(updateBtn, false);
        checkBtn.disabled = false;
      }
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
      STANNG.setLoading(updateBtn, false);
      checkBtn.disabled = false;
    }
  });

  function waitForRestartThenReload() {
    let attempts = 0;
    const poll = setInterval(async () => {
      attempts++;
      try {
        const res = await fetch('/health', { cache: 'no-store' });
        if (res.ok) {
          clearInterval(poll);
          STANNG.toast(STANNG.t('dash_ota_done'), 'success', 3000);
          setTimeout(() => window.location.reload(), 1200);
        }
      } catch (e) {
        // still down / restarting — keep polling
      }
      if (attempts > 60) {
        clearInterval(poll);
        STANNG.toast(STANNG.t('dash_ota_timeout'), 'error', 8000);
      }
    }, 3000);
  }

  document.getElementById('quickAddBtn').addEventListener('click', () => { showView('inbounds'); openInboundModal(); });

  // ---------------- inbounds ----------------
  const fpKeyMap = { chrome: 'fp_chrome', ios: 'fp_ios', firefox: 'fp_firefox', edge: 'fp_edge', random: 'fp_random' };

  async function loadInbounds() {
    try {
      const r = await STANNG.api('/api/inbounds');
      currentInbounds = r.inbounds || [];
      renderInboundsTable();
      renderTrafficTable();
      document.getElementById('navInboundCount').textContent = currentInbounds.length;
    } catch (e) { STANNG.toast(e.detail || 'error', 'error'); }
  }

  function renderInboundsTable(filter = '') {
    const tbody = document.getElementById('inboundsTableBody');
    const empty = document.getElementById('inboundsEmpty');
    const sortSel = document.getElementById('sortSelect');
    const sortMode = sortSel ? sortSel.value : 'newest';
    let rows = currentInbounds.filter(ib => !filter || ib.name.toLowerCase().includes(filter.toLowerCase()));
    if (statusFilter !== 'all') rows = rows.filter(ib => classifyIb(ib) === statusFilter);
    if (sortMode === 'name') rows = [...rows].sort((a, b) => a.name.localeCompare(b.name, 'fa'));
    else if (sortMode === 'usage') rows = [...rows].sort((a, b) => ((b.used_up || 0) + (b.used_down || 0)) - ((a.used_up || 0) + (a.used_down || 0)));
    else if (sortMode === 'expiry') rows = [...rows].sort((a, b) => (a.expire_at || 9e15) - (b.expire_at || 9e15));
    else rows = [...rows].sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    if (currentPage > totalPages) currentPage = totalPages;
    const pageRows = rows.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
    const pagerInfo = document.getElementById('pagerInfo');
    if (pagerInfo) pagerInfo.textContent = `${currentPage} / ${totalPages} · ${rows.length}`;
    const prevB = document.getElementById('pagerPrev');
    const nextB = document.getElementById('pagerNext');
    if (prevB) prevB.disabled = currentPage <= 1;
    if (nextB) nextB.disabled = currentPage >= totalPages;
    tbody.innerHTML = '';
    empty.style.display = rows.length ? 'none' : 'block';

    pageRows.forEach(ib => {
      const st = ib.status;
      const tr = document.createElement('tr');
      const statusPill = st.live_enabled
        ? `<span class="pill pill-on"><span class="pill-dot"></span>${STANNG.t('active')}</span>`
        : `<span class="pill pill-off"><span class="pill-dot"></span>${st.expired ? STANNG.t('expired') : STANNG.t('inactive')}</span>`;
      const quotaTxt = ib.quota_gb > 0
        ? `${STANNG.fmtBytes(st.used)} ${STANNG.t('inb_used_of')} ${ib.quota_gb} GB`
        : `${STANNG.fmtBytes(st.used)} / ${STANNG.t('unlimited')}`;
      const pct = ib.quota_gb > 0 ? Math.min(100, (st.used / st.quota_bytes) * 100) : (st.used > 0 ? 8 : 0);
      const expireTxt = ib.expire_at
        ? `${st.days_left} ${STANNG.t('inb_days_left')}`
        : STANNG.t('inb_no_expire');
      const uuidShort = (ib.uuid || '').slice(0, 8);
      const ips = ib.active_ips || [];
      const lastAgo = ib.last_conn
        ? STANNG.t('time_ago_s').replace('{n}', Math.max(0, Math.floor(Date.now() / 1000 - ib.last_conn)))
        : '—';
      const connTxt = ips.length ? `${escapeHtml(ips.slice(0, 2).join(', '))}<div class="small muted">${lastAgo}</div>` : `<span class="muted">—</span><div class="small muted">${lastAgo}</div>`;
      tr.innerHTML = `
        <td data-label="${STANNG.t('inb_name')}"><b>${escapeHtml(ib.name)}</b><div class="small muted">${ib.note ? escapeHtml(ib.note) : ''} · ${fmtDate(ib.created_at)}</div></td>
        <td data-label="UUID" style="direction:ltr;"><code class="small">${uuidShort}…</code> <button class="icon-btn btn-sm" data-action="copy-uuid" data-uid="${ib.uid}" title="UUID"><svg width="13" height="13"><use href="#icon-copy"/></svg></button></td>
        <td data-label="${STANNG.t('inb_status')}">${statusPill}</td>
        <td data-label="${STANNG.t('inb_usage')}" style="min-width:160px;">
          <div class="small">${quotaTxt}</div>
          <div class="bar progress-gold" style="margin-top:4px;"><span style="width:${pct}%"></span></div>
        </td>
        <td data-label="${STANNG.t('inb_remaining')}">${remainingTxt(ib)}</td>
        <td data-label="${STANNG.t('inb_lastconn')}">${connTxt}</td>
        <td data-label="${STANNG.t('inb_server')}"><span class="small">Local</span></td>
        <td data-label="${STANNG.t('inb_expire')}">${expireTxt}</td>
        <td data-label="${STANNG.t('inb_max_conn')}">${st.active_connections}${ib.max_connections ? ' / ' + ib.max_connections : ''} <span class="small muted">${STANNG.t('inb_active_devices')}</span></td>
        <td data-label="${STANNG.t('inb_actions')}">
          <div class="row-actions">
            <button class="icon-btn btn-sm" data-action="links" data-uid="${ib.uid}" title="${STANNG.t('inb_links')}"><svg width="15" height="15"><use href="#icon-qr"/></svg></button>
            <button class="icon-btn btn-sm" data-action="plan" data-uid="${ib.uid}" title="${STANNG.t('assign_plan')}"><svg width="15" height="15"><use href="#icon-crown"/></svg></button>
            <button class="icon-btn btn-sm" data-action="toggle" data-uid="${ib.uid}" title="on/off"><svg width="15" height="15"><use href="#icon-bolt"/></svg></button>
            <button class="icon-btn btn-sm" data-action="extend" data-uid="${ib.uid}" title="+"><svg width="15" height="15"><use href="#icon-plus"/></svg></button>
            <button class="icon-btn btn-sm" data-action="clone" data-uid="${ib.uid}" title="clone"><svg width="15" height="15"><use href="#icon-copy"/></svg></button>
            <button class="icon-btn btn-sm" data-action="edit" data-uid="${ib.uid}" title="${STANNG.t('edit')}"><svg width="15" height="15"><use href="#icon-edit"/></svg></button>
            <button class="icon-btn btn-sm" data-action="reset" data-uid="${ib.uid}" title="${STANNG.t('inb_reset_usage')}"><svg width="15" height="15"><use href="#icon-refresh"/></svg></button>
            <button class="icon-btn btn-sm" data-action="regen" data-uid="${ib.uid}" title="${STANNG.t('inb_regenerate')}"><svg width="15" height="15"><use href="#icon-key"/></svg></button>
            <button class="icon-btn btn-sm" data-action="delete" data-uid="${ib.uid}" title="${STANNG.t('delete')}" style="color:var(--crimson)"><svg width="15" height="15"><use href="#icon-trash"/></svg></button>
          </div>
        </td>`;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', () => handleInboundAction(btn.dataset.action, btn.dataset.uid));
    });
  }

  function renderTrafficTable() {
    const tbody = document.getElementById('trafficTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    currentInbounds.forEach(ib => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td data-label="${STANNG.t('inb_name')}"><b>${escapeHtml(ib.name)}</b></td>
        <td data-label="${STANNG.t('dash_upload')}">${STANNG.fmtBytes(ib.used_up || 0)}</td>
        <td data-label="${STANNG.t('dash_download')}">${STANNG.fmtBytes(ib.used_down || 0)}</td>
        <td data-label="${STANNG.t('inb_usage')}">${STANNG.fmtBytes((ib.used_up || 0) + (ib.used_down || 0))}</td>`;
      tbody.appendChild(tr);
    });
  }

  document.querySelectorAll('#settingsTabs [data-goto]').forEach(b => {
    b.addEventListener('click', () => {
      const nav = document.querySelector(`.nav-item[data-view="${b.dataset.goto}"]`);
      if (nav) nav.click();
    });
  });

  document.getElementById('inboundSearch').addEventListener('input', (e) => { currentPage = 1; renderInboundsTable(e.target.value); });
  const _pp = document.getElementById('pagerPrev');
  if (_pp) _pp.addEventListener('click', () => { if (currentPage > 1) { currentPage--; renderInboundsTable(document.getElementById('inboundSearch').value); } });
  const _pn = document.getElementById('pagerNext');
  if (_pn) _pn.addEventListener('click', () => { currentPage++; renderInboundsTable(document.getElementById('inboundSearch').value); });

  function escapeHtml(s) {
    return (s || '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
  }

  function openInboundModal(ib = null) {
    document.getElementById('inboundModalTitle').textContent = ib ? STANNG.t('edit') : STANNG.t('inb_add');
    document.getElementById('inboundUid').value = ib ? ib.uid : '';
    const uuidRow = document.getElementById('fUuidRow');
    if (uuidRow) {
      uuidRow.style.display = ib ? '' : 'none';
      if (ib) document.getElementById('fUuid').textContent = ib.uuid || '';
    }
    document.getElementById('fName').value = ib ? ib.name : '';
    const planSel = document.getElementById('fPlan');
    if (planSel) {
      STANNG.api('/api/plans').then(r => {
        planSel.innerHTML = '<option value="">—</option>' + (r.plans || []).filter(p => p.enabled).map(p =>
          `<option value="${p.id}">${p.name} · ${p.traffic_gb}GB · ${p.duration_days}d · ${Number(p.price || 0).toLocaleString()}</option>`).join('');
        if (ib && ib.plan_id) planSel.value = ib.plan_id;
      }).catch(() => {});
      planSel.closest('.field').style.display = ib ? 'none' : '';
    }
    document.getElementById('fQuota').value = ib ? (ib.quota_gb || '') : '';
    document.getElementById('fExpire').value = ib ? (ib.expire_days || '') : '';
    document.getElementById('fMaxConn').value = ib ? (ib.max_connections || '') : '';
    document.getElementById('fMaxReq').value = ib ? (ib.max_requests || '') : '';
    document.getElementById('fFingerprint').value = ib ? (ib.fp || 'chrome') : 'chrome';
    document.getElementById('fStrictIp').checked = ib ? !!ib.strict_single_ip : false;
    document.getElementById('fNote').value = ib ? (ib.note || '') : '';
    openModal('inboundModal');
  }

  document.querySelectorAll('#addInboundBtnTop, #addInboundBtn').forEach(btn => btn.addEventListener('click', () => openInboundModal()));

  document.getElementById('inboundSaveBtn').addEventListener('click', async () => {
    const uid = document.getElementById('inboundUid').value;
    const payload = {
      name: document.getElementById('fName').value.trim() || 'User',
      quota_gb: parseFloat(document.getElementById('fQuota').value || 0),
      expire_days: parseInt(document.getElementById('fExpire').value || 0),
      max_connections: parseInt(document.getElementById('fMaxConn').value || 0),
      max_requests: parseInt(document.getElementById('fMaxReq').value || 0),
      fp: document.getElementById('fFingerprint').value,
      strict_single_ip: document.getElementById('fStrictIp').checked,
      note: document.getElementById('fNote').value.trim(),
    };
    if (!uid) {
      const planSel = document.getElementById('fPlan');
      if (planSel && planSel.value) payload.plan_id = planSel.value;
    }
    const btn = document.getElementById('inboundSaveBtn');
    STANNG.setLoading(btn, true);
    try {
      if (uid) {
        await STANNG.api(`/api/inbounds/${uid}`, { method: 'PATCH', body: payload });
        STANNG.toast(STANNG.t('inb_updated'), 'success');
      } else {
        await STANNG.api('/api/inbounds', { method: 'POST', body: payload });
        STANNG.toast(STANNG.t('inb_created'), 'success');
      }
      closeModal('inboundModal');
      loadInbounds();
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
    } finally {
      STANNG.setLoading(btn, false);
    }
  });

  async function handleInboundAction(action, uid) {
    const ib = currentInbounds.find(x => x.uid === uid);
    if (!ib) return;
    if (action === 'edit') return openInboundModal(ib);
    if (action === 'links') return showLinksModal(uid);
    if (action === 'copy-uuid') {
      navigator.clipboard.writeText(ib.uuid || '').then(() => STANNG.toast(STANNG.t('copied'), 'success', 1600));
      return;
    }
    if (action === 'plan' && window.PREMIUM) return window.PREMIUM.openAssign(uid, ib.name);
    if (action === 'toggle') {
      try { await STANNG.api(`/api/inbounds/${uid}/toggle`, { method: 'POST' }); loadInbounds(); }
      catch (e) { STANNG.toast(e.detail || 'error', 'error'); }
      return;
    }
    if (action === 'clone') {
      try { await STANNG.api(`/api/inbounds/${uid}/clone`, { method: 'POST' }); STANNG.toast(STANNG.t('inb_cloned'), 'success'); loadInbounds(); }
      catch (e) { STANNG.toast(e.detail || 'error', 'error'); }
      return;
    }
    if (action === 'extend') {
      document.getElementById('extendUid').value = uid;
      document.getElementById('extendModal').classList.add('open');
      return;
    }
    if (action === 'reset') {
      try {
        await STANNG.api(`/api/inbounds/${uid}/reset-usage`, { method: 'POST' });
        STANNG.toast(STANNG.t('inb_reset_done'), 'success');
        loadInbounds();
      } catch (e) { STANNG.toast(e.detail || 'error', 'error'); }
      return;
    }
    if (action === 'regen') {
      if (!confirm(STANNG.t('inb_regenerate_confirm'))) return;
      try {
        await STANNG.api(`/api/inbounds/${uid}/regenerate`, { method: 'POST' });
        STANNG.toast(STANNG.t('inb_regenerated'), 'success');
        loadInbounds();
      } catch (e) { STANNG.toast(e.detail || 'error', 'error'); }
      return;
    }
    if (action === 'delete') {
      if (!confirm(STANNG.t('inb_delete_confirm'))) return;
      try {
        await STANNG.api(`/api/inbounds/${uid}`, { method: 'DELETE' });
        STANNG.toast(STANNG.t('inb_deleted'), 'success');
        loadInbounds();
      } catch (e) { STANNG.toast(e.detail || 'error', 'error'); }
      return;
    }
  }

  // ============ LINKS MODAL (v2.0: + clash/singbox) ============
  async function showLinksModal(uid) {
    try {
      const r = await STANNG.api(`/api/inbounds/${uid}/links`);
      window._lastLinks = r;
      window._lastUid = uid;

      // نمایش لینک TLS
      document.getElementById('linkTls').textContent = r.links.tls || '';

      // لینک اشتراک (با پروتکل https)
      document.getElementById('linkSub').textContent = r.sub_url || '';
      const stLine = document.getElementById('subStateLine');
      if (stLine) {
        stLine.innerHTML = r.sub_enabled === false
          ? `<span style="color:var(--crimson)">● ${STANNG.t('sub_disabled')}</span>`
          : `<span style="color:var(--emerald)">● ${STANNG.t('sub_active')}</span>`;
      }

      // لینک وضعیت
      document.getElementById('linkStatus').textContent = r.status_url || '';

      // لینک JSON
      document.getElementById('linkSubJson').textContent = r.sub_json_url || '';
      const elClash = document.getElementById('linkClash');
      if (elClash) elClash.textContent = r.sub_clash_url || '';
      const elSB = document.getElementById('linkSingbox');
      if (elSB) elSB.textContent = r.sub_singbox_url || '';

      // لینک DoH
      const elDoh = document.getElementById('linkDoh');
      if (elDoh) elDoh.textContent = r.doh_url || '';

      // QR Code
      document.getElementById('qrImg').src = `/api/inbounds/${uid}/qr?t=${Date.now()}`;

      openModal('linksModal');
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
    }
  }

  const _copyAll = document.getElementById('copyAllBtn');
  if (_copyAll) _copyAll.addEventListener('click', () => {
    const r = window._lastLinks;
    if (!r) return;
    const all = [r.links.tls, ...(r.links.all_links || []).slice(1), r.sub_url].filter(Boolean).join('\n');
    navigator.clipboard.writeText(all).then(() => STANNG.toast(STANNG.t('copied'), 'success'));
  });

  const _sort = document.getElementById('sortSelect');
  if (_sort) _sort.addEventListener('change', () => renderInboundsTable(document.getElementById('inboundSearch').value));

  // expose for premium module
  window.STANNG_INBOUNDS = { reload: loadInbounds, get: () => currentInbounds };

  // ---------------- copy functionality ----------------
  function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
      STANNG.toast(STANNG.t('copied'), 'success', 1600);
      STANNG.playSfx('click', 0.4);
    }).catch(() => STANNG.toast('error', 'error'));
  }

  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.copy;
      const el = document.getElementById(targetId);
      if (el) copyText(el.textContent);
    });
  });

  // ---------------- حذف کامل بخش Clean IP ----------------
  // تمام توابع مربوط به Clean IP حذف شدند: 
  // loadAddresses, renderAddressesTable, addAddressBtn, fetchCleanIpBtn, addressSaveBtn

  // ---------------- security ----------------
  document.getElementById('securityForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const old_password = document.getElementById('oldPassword').value;
    const new_username = document.getElementById('newUsername').value.trim();
    const new_password = document.getElementById('newPassword').value;
    const new_password2 = document.getElementById('newPassword2').value;
    if (new_password && new_password !== new_password2) {
      STANNG.toast(STANNG.t('setup_mismatch'), 'error');
      STANNG.shake(document.getElementById('securityForm'));
      return;
    }
    const btn = document.getElementById('securityBtn');
    STANNG.setLoading(btn, true);
    try {
      await STANNG.api('/api/change-password', { method: 'POST', body: { old_password, new_username, new_password } });
      STANNG.toast(STANNG.t('sec_updated'), 'success');
      document.getElementById('securityForm').reset();
    } catch (e) {
      let msg = e.detail;
      if (msg === 'wrong-old-password') msg = STANNG.t('sec_wrong_old');
      STANNG.toast(msg || 'error', 'error');
      STANNG.shake(document.getElementById('securityForm'));
    } finally {
      STANNG.setLoading(btn, false);
    }
  });

  // ---------------- settings ----------------
  document.getElementById('saveSettingsBtn').addEventListener('click', async () => {
    const payload = {
      public_domain: document.getElementById('settingPublicDomain').value.trim(),
      keep_alive: document.getElementById('settingKeepAlive').checked,
      maintenance_enabled: document.getElementById('settingMaint').checked,
      maintenance_message: document.getElementById('settingMaintMsg').value.trim(),
    };
    STANNG.setSoundEnabled(document.getElementById('settingSound').checked);
    const btn = document.getElementById('saveSettingsBtn');
    STANNG.setLoading(btn, true);
    try {
      await STANNG.api('/api/settings', { method: 'POST', body: payload });
      STANNG.toast(STANNG.t('settings_saved'), 'success');
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
    } finally {
      STANNG.setLoading(btn, false);
    }
  });

  // ---------------- advanced config settings ----------------
  document.getElementById('saveAdvancedBtn').addEventListener('click', async () => {
    const payload = {
      default_fingerprint: document.getElementById('settingFingerprint').value,
      default_alpn: document.getElementById('settingAlpn').value,
      sni_override: document.getElementById('settingSniOverride').value.trim(),
      fragment_enabled: document.getElementById('settingFragmentEnabled').checked,
      fragment_packets: document.getElementById('settingFragmentPackets').value.trim() || 'tlshello',
      fragment_length: document.getElementById('settingFragmentLength').value.trim() || '10-30',
      fragment_interval: document.getElementById('settingFragmentInterval').value.trim() || '10-20',
    };
    const btn = document.getElementById('saveAdvancedBtn');
    STANNG.setLoading(btn, true);
    try {
      await STANNG.api('/api/settings', { method: 'POST', body: payload });
      STANNG.toast(STANNG.t('settings_saved'), 'success');
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
    } finally {
      STANNG.setLoading(btn, false);
    }
  });

  document.getElementById('settingFragmentEnabled').addEventListener('change', (e) => {
    document.getElementById('fragmentFields').style.opacity = e.target.checked ? '1' : '.45';
    document.getElementById('fragmentFields').style.pointerEvents = e.target.checked ? 'auto' : 'none';
  });

  // ---------------- agent settings ----------------
  document.getElementById('saveAgentBtn').addEventListener('click', async () => {
    const payload = {
      agent_auth_secret: document.getElementById('agentSecret').value.trim(),
      heartbeat_threshold: parseInt(document.getElementById('agentHeartbeatThreshold').value) || 90,
    };
    const btn = document.getElementById('saveAgentBtn');
    STANNG.setLoading(btn, true);
    try {
      await STANNG.api('/api/settings', { method: 'POST', body: payload });
      STANNG.toast(STANNG.t('settings_saved'), 'success');
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
    } finally {
      STANNG.setLoading(btn, false);
    }
  });

  // ---------------- alert settings ----------------
  document.getElementById('saveAlertsBtn').addEventListener('click', async () => {
    const payload = {
      alert_cpu: parseFloat(document.getElementById('settingsAlertCpu').value) || 80,
      alert_mem: parseFloat(document.getElementById('settingsAlertMem').value) || 85,
      alert_disk: parseFloat(document.getElementById('settingsAlertDisk').value) || 90,
      alert_latency_ms: parseFloat(document.getElementById('settingsAlertLat').value) || 1000,
      alert_conns: parseFloat(document.getElementById('settingsAlertConns').value) || 200,
      server_poll_interval: parseInt(document.getElementById('settingsPollInterval').value) || 30,
    };
    const btn = document.getElementById('saveAlertsBtn');
    STANNG.setLoading(btn, true);
    try {
      await STANNG.api('/api/settings', { method: 'POST', body: payload });
      STANNG.toast(STANNG.t('settings_saved'), 'success');
    } catch (e) {
      STANNG.toast(e.detail || 'error', 'error');
    } finally {
      STANNG.setLoading(btn, false);
    }
  });

  // ---------------- initial load ----------------
  loadInbounds();
})();

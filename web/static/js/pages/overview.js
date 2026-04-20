/**
 * pages/overview.js — Dashboard overview: stat cards + recent activity
 */

const PageOverview = (() => {

  async function render() {
    const el = document.getElementById('page-overview');
    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Overview</h1>
          <p class="page-description">Real-time command &amp; control metrics</p>
        </div>
        <div class="page-actions">
          <button class="btn btn-secondary btn-sm" id="btn-refresh-overview">
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor">
              <path d="M1.705 8.005a.75.75 0 0 1 .834.656 5.5 5.5 0 0 0 9.592 2.97l-1.204-1.204a.25.25 0 0 1 .177-.427h3.646a.25.25 0 0 1 .25.25l.001 3.646a.25.25 0 0 1-.427.177l-1.38-1.38A7.002 7.002 0 0 1 1.05 8.84a.75.75 0 0 1 .656-.834ZM8 2.5a5.487 5.487 0 0 0-4.131 1.869l1.204 1.204A.25.25 0 0 1 4.896 6H1.25A.25.25 0 0 1 1 5.75V2.104a.25.25 0 0 1 .427-.177l1.38 1.38A7.002 7.002 0 0 1 14.95 7.16a.75.75 0 0 1-1.49.178A5.5 5.5 0 0 0 8 2.5Z"/>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <div class="grid grid-4 mb-4" id="overview-stats">
        ${skeletonCards(4)}
      </div>

      <div class="grid grid-2 mt-6">
        <div class="panel" id="overview-agents-panel">
          <div class="panel-header">
            <span class="panel-title">Agent Status</span>
          </div>
          <div class="panel-body no-pad" id="overview-agents-table">
            <div style="padding:var(--space-8);text-align:center">
              <div class="loading-spinner" style="margin:auto"></div>
            </div>
          </div>
        </div>

        <div class="panel" id="overview-activity-panel">
          <div class="panel-header">
            <span class="panel-title">Recent Activity</span>
            <span class="panel-subtitle" id="activity-count"></span>
          </div>
          <div class="panel-body no-pad" id="overview-activity">
            <div style="padding:var(--space-8);text-align:center">
              <div class="loading-spinner" style="margin:auto"></div>
            </div>
          </div>
        </div>
      </div>`;

    document.getElementById('btn-refresh-overview').addEventListener('click', load);
    await load();
  }

  async function load() {
    try {
      const [stats, health] = await Promise.all([
        API.server.stats(),
        API.server.health(),
      ]);
      renderStats(stats, health);
      renderAgentTable(stats.agents);
      renderActivity(stats);
    } catch (e) {
      Toast.error('Failed to load overview', e.message);
    }
  }

  function renderStats(stats, health) {
    const agt  = stats.agents  || {};
    const cmds = stats.command_queue || {};
    const srv  = stats.server  || {};

    const cards = [
      {
        label: 'Online Agents',
        value: agt.online ?? 0,
        icon:  iconCircle('green'),
        accent: 'var(--accent-green)',
        meta:  `${agt.total ?? 0} registered`,
      },
      {
        label: 'Pending Commands',
        value: cmds.total_queued ?? 0,
        icon:  iconClock(),
        accent: 'var(--accent-blue)',
        meta:  `${cmds.total_active ?? 0} executing`,
      },
      {
        label: 'Completed',
        value: cmds.total_completed ?? 0,
        icon:  iconCheck(),
        accent: 'var(--accent-purple)',
        meta:  'all time',
      },
      {
        label: 'Uptime',
        value: srv.uptime ? formatUptime(srv.uptime) : '—',
        icon:  iconServer(),
        accent: 'var(--accent-cyan)',
        meta:  `v${srv.version || '2.0.0'}`,
        small: true,
      },
    ];

    document.getElementById('overview-stats').innerHTML =
      cards.map(c => statCard(c)).join('');
  }

  function renderAgentTable(agt) {
    if (!agt) return;
    const statuses = [
      { label: 'Online',    key: 'online',    cls: 'badge-online' },
      { label: 'Dormant',   key: 'dormant',   cls: 'badge-dormant' },
      { label: 'Offline',   key: 'offline',   cls: 'badge-offline' },
      { label: 'Error',     key: 'error',     cls: 'badge-error' },
      { label: 'Suspected', key: 'suspected', cls: 'badge-suspected' },
    ];

    const rows = statuses.map(s => `
      <tr>
        <td><span class="badge ${s.cls}"><span class="badge-dot"></span>${s.label}</span></td>
        <td class="primary fw-semibold" style="text-align:right">${agt[s.key] ?? 0}</td>
        <td style="text-align:right">
          <div style="background:var(--bg-hover);border-radius:var(--radius-full);height:4px;width:100px;margin-left:auto;overflow:hidden">
            <div style="height:100%;border-radius:var(--radius-full);background:var(--accent-blue);width:${Math.round(((agt[s.key] ?? 0) / Math.max(agt.total || 1, 1)) * 100)}%"></div>
          </div>
        </td>
      </tr>`).join('');

    document.getElementById('overview-agents-table').innerHTML = `
      <table class="data-table">
        <thead><tr>
          <th>Status</th>
          <th style="text-align:right">Count</th>
          <th style="text-align:right;width:120px">Share</th>
        </tr></thead>
        <tbody>${rows}
          <tr style="border-top:1px solid var(--border)">
            <td class="text-muted fw-semibold">Total</td>
            <td class="primary fw-bold" style="text-align:right">${agt.total ?? 0}</td>
            <td></td>
          </tr>
        </tbody>
      </table>`;
  }

  function renderActivity(stats) {
    const count = document.getElementById('activity-count');
    // Show queue stats per agent as activity feed
    const byAgent = stats.command_queue?.by_agent || {};
    const entries = Object.entries(byAgent).slice(0, 8);

    if (entries.length === 0) {
      document.getElementById('overview-activity').innerHTML = `
        <div class="table-empty">
          <div class="table-empty-icon">📭</div>
          <div class="table-empty-text">No agent activity yet</div>
        </div>`;
      return;
    }

    count.textContent = `${entries.length} agents`;
    const rows = entries.map(([agentId, s]) => `
      <tr>
        <td class="mono text-muted">${escHtml(shortId(agentId))}</td>
        <td><span class="badge badge-pending">${s.queued ?? 0} queued</span></td>
        <td><span class="badge badge-executing">${s.active ?? 0} active</span></td>
        <td><span class="badge badge-completed">${s.completed ?? 0} done</span></td>
      </tr>`).join('');

    document.getElementById('overview-activity').innerHTML = `
      <table class="data-table">
        <thead><tr>
          <th>Agent</th><th>Queued</th><th>Active</th><th>Done</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function skeletonCards(n) {
    return Array(n).fill(0).map(() => `
      <div class="stat-card">
        <div class="stat-card-header">
          <span class="skeleton" style="width:80px;height:12px"></span>
          <span class="skeleton" style="width:32px;height:32px;border-radius:var(--radius-md)"></span>
        </div>
        <span class="skeleton" style="width:60px;height:28px"></span>
        <span class="skeleton" style="width:100px;height:11px"></span>
      </div>`).join('');
  }

  function statCard({ label, value, icon, accent, meta, small }) {
    return `
      <div class="stat-card" style="--card-accent:${accent}">
        <div class="stat-card-header">
          <span class="stat-card-label">${escHtml(label)}</span>
          <span class="stat-card-icon" style="background:${accent}1a;color:${accent}">${icon}</span>
        </div>
        <div class="stat-card-value" style="${small ? 'font-size:22px' : ''}">${escHtml(String(value))}</div>
        <div class="stat-card-meta">${escHtml(meta || '')}</div>
      </div>`;
  }

  function formatUptime(s) {
    // Go duration string like "2h3m4.5s"
    const m = s.match(/(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?/);
    if (!m) return s;
    const h = parseInt(m[1] || 0), min = parseInt(m[2] || 0);
    if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
    if (h > 0) return `${h}h ${min}m`;
    return `${min}m`;
  }

  function iconCircle(color) {
    const c = color === 'green' ? '#3fb950' : '#f85149';
    return `<svg width="16" height="16" viewBox="0 0 16 16" fill="${c}"><circle cx="8" cy="8" r="6"/></svg>`;
  }
  function iconClock() {
    return `<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 110 16A8 8 0 018 0zm0 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zm.75 3.25a.75.75 0 00-1.5 0v3.5c0 .199.079.39.22.53l2.25 2.25a.75.75 0 101.06-1.06L8.75 7.69V4.75z"/></svg>`;
  }
  function iconCheck() {
    return `<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M0 8a8 8 0 1116 0A8 8 0 010 8zm11.78-1.97a.75.75 0 00-1.06-1.06L6.75 8.94 5.28 7.47a.75.75 0 00-1.06 1.06l2 2a.75.75 0 001.06 0l4.5-4.5z"/></svg>`;
  }
  function iconServer() {
    return `<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M1.75 1h12.5c.966 0 1.75.784 1.75 1.75v3c0 .698-.409 1.301-1 1.582v.668c.591.281 1 .884 1 1.582v3A1.75 1.75 0 0114.25 14H1.75A1.75 1.75 0 010 12.25v-3c0-.698.409-1.301 1-1.582V7.332C.409 7.051 0 6.448 0 5.75v-3C0 1.784.784 1 1.75 1zM1.5 5.75c0 .138.112.25.25.25h12.5a.25.25 0 00.25-.25v-3a.25.25 0 00-.25-.25H1.75a.25.25 0 00-.25.25v3zm.25 5.75h12.5a.25.25 0 00.25-.25v-3a.25.25 0 00-.25-.25H1.75a.25.25 0 00-.25.25v3c0 .138.112.25.25.25zM7 4.75a.75.75 0 001.5 0V4a.75.75 0 00-1.5 0v.75zm.75 6.5a.75.75 0 00.75-.75V10a.75.75 0 00-1.5 0v.5a.75.75 0 00.75.75z"/></svg>`;
  }

  return { render };
})();

/**
 * pages/commands.js — Global command queue monitor
 */

const PageCommands = (() => {
  let agents = [];
  let refreshTimer = null;

  async function render() {
    const el = document.getElementById('page-commands');
    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Command Queue</h1>
          <p class="page-description">Queue monitor and bulk command dispatch</p>
        </div>
        <div class="page-actions">
          <button class="btn btn-secondary btn-sm" id="btn-refresh-cmds">↺ Refresh</button>
          <button class="btn btn-primary btn-sm" id="btn-open-dispatch">+ Dispatch Command</button>
        </div>
      </div>

      <!-- Queue stats cards -->
      <div class="grid grid-3 mb-4" id="queue-stats-cards">
        ${skeletonCards(3)}
      </div>

      <!-- Queue table -->
      <div class="panel">
        <div class="filter-bar">
          <select class="form-control" id="cmd-agent-filter" style="width:220px">
            <option value="">All Agents</option>
          </select>
          <select class="form-control" id="cmd-status-filter" style="width:140px">
            <option value="">All Status</option>
            <option value="pending">Pending</option>
            <option value="executing">Executing</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
            <option value="timeout">Timeout</option>
          </select>
          <div class="input-group" style="flex:1;min-width:180px">
            <svg class="input-group-icon" viewBox="0 0 16 16" fill="currentColor">
              <path d="M10.68 11.74a6 6 0 01-7.922-8.982 6 6 0 018.982 7.922l3.04 3.04a.749.749 0 01-.326 1.275.749.749 0 01-.734-.215l-3.04-3.04zM11.5 7a4.499 4.499 0 11-8.997 0A4.499 4.499 0 0111.5 7z"/>
            </svg>
            <input class="form-control" id="cmd-search" placeholder="Search command…" type="search">
          </div>
          <label style="display:flex;align-items:center;gap:var(--space-2);font-size:var(--text-sm);color:var(--text-secondary);cursor:pointer">
            <input type="checkbox" id="cmd-auto-refresh" style="accent-color:var(--accent-blue)">
            Auto-refresh
          </label>
        </div>

        <div id="cmds-table-body" class="panel-body no-pad">
          <div style="padding:var(--space-10);text-align:center">
            <div class="loading-spinner" style="margin:auto"></div>
          </div>
        </div>
      </div>

      <!-- Dispatch modal (hidden) -->
      <div id="dispatch-modal" style="display:none"></div>`;

    document.getElementById('btn-refresh-cmds').addEventListener('click', loadAll);
    document.getElementById('btn-open-dispatch').addEventListener('click', openDispatch);
    document.getElementById('cmd-agent-filter').addEventListener('change', applyFilters);
    document.getElementById('cmd-status-filter').addEventListener('change', applyFilters);
    document.getElementById('cmd-search').addEventListener('input', applyFilters);
    document.getElementById('cmd-auto-refresh').addEventListener('change', e => {
      if (e.target.checked) {
        refreshTimer = setInterval(loadAll, 5000);
      } else {
        clearInterval(refreshTimer);
        refreshTimer = null;
      }
    });

    await loadAll();
  }

  let allCommands = [];

  async function loadAll() {
    try {
      const [statsData, agentsData] = await Promise.all([
        API.server.queueStats(),
        API.agents.list(),
      ]);
      agents = agentsData.agents || [];
      renderStats(statsData);
      populateAgentFilter();
      await loadCommandsForAll();
    } catch (e) {
      Toast.error('Failed to load commands', e.message);
    }
  }

  function renderStats(s) {
    const cards = [
      { label: 'Queued',    value: s.total_queued    || 0, accent: 'var(--accent-blue)',   },
      { label: 'Executing', value: s.total_active    || 0, accent: 'var(--accent-cyan)',   },
      { label: 'Completed', value: s.total_completed || 0, accent: 'var(--accent-green)',  },
    ];
    document.getElementById('queue-stats-cards').innerHTML = cards.map(c => `
      <div class="stat-card" style="--card-accent:${c.accent}">
        <div class="stat-card-header">
          <span class="stat-card-label">${escHtml(c.label)}</span>
        </div>
        <div class="stat-card-value">${c.value}</div>
      </div>`).join('');
  }

  function populateAgentFilter() {
    const sel = document.getElementById('cmd-agent-filter');
    const current = sel.value;
    sel.innerHTML = '<option value="">All Agents</option>' +
      agents.map(a => `<option value="${escHtml(a.id)}">${escHtml(a.hostname || shortId(a.id))}</option>`).join('');
    sel.value = current;
  }

  async function loadCommandsForAll() {
    allCommands = [];
    await Promise.all(agents.slice(0, 20).map(async a => {
      try {
        const data = await API.commands.history(a.id, '?limit=30');
        const cmds = (data.commands || []).map(c => ({ ...c, _hostname: a.hostname }));
        allCommands.push(...cmds);
      } catch {}
    }));
    allCommands.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    applyFilters();
  }

  function applyFilters() {
    const agentFilter  = document.getElementById('cmd-agent-filter').value;
    const statusFilter = document.getElementById('cmd-status-filter').value;
    const q            = (document.getElementById('cmd-search').value || '').toLowerCase();

    const filtered = allCommands.filter(c => {
      const matchAgent  = !agentFilter  || c.agent_id === agentFilter;
      const matchStatus = !statusFilter || c.status   === statusFilter;
      const matchQ      = !q || (c.command || '').toLowerCase().includes(q);
      return matchAgent && matchStatus && matchQ;
    });

    renderTable(filtered);
  }

  function renderTable(cmds) {
    const body = document.getElementById('cmds-table-body');
    if (!cmds.length) {
      body.innerHTML = `<div class="table-empty">
        <div class="table-empty-icon">📋</div>
        <div class="table-empty-text">No commands match your filter</div>
      </div>`;
      return;
    }

    const rows = cmds.slice(0, 200).map(c => `
      <tr>
        <td class="mono text-muted">${escHtml(shortId(c.id))}</td>
        <td class="text-secondary">${escHtml(c._hostname || shortId(c.agent_id))}</td>
        <td class="primary mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;display:table-cell">${escHtml(c.command || c.operation_type || '—')}</td>
        <td>${statusBadge(c.status)}</td>
        <td class="text-muted">${escHtml(relTime(c.created_at))}</td>
        <td class="mono text-muted">${c.exit_code !== undefined && c.exit_code !== null ? escHtml(String(c.exit_code)) : '—'}</td>
        <td>
          <button class="btn btn-ghost btn-xs" onclick="PageAgents.viewResult('${escHtml(c.id)}')">View</button>
        </td>
      </tr>`).join('');

    body.innerHTML = `
      <div class="data-table-wrapper">
        <table class="data-table">
          <thead><tr>
            <th style="width:90px">ID</th>
            <th style="width:150px">Agent</th>
            <th>Command</th>
            <th style="width:110px">Status</th>
            <th style="width:100px">Time</th>
            <th style="width:70px">Exit</th>
            <th style="width:60px"></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  function openDispatch() {
    const agentOptions = agents.map(a =>
      `<option value="${escHtml(a.id)}">${escHtml(a.hostname || shortId(a.id))}</option>`
    ).join('');

    if (!agentOptions) {
      Toast.warning('No agents', 'No agents are currently registered');
      return;
    }

    const formEl = document.createElement('div');
    formEl.innerHTML = `
      <div style="display:grid;gap:var(--space-4)">
        <div class="form-group">
          <label class="form-label">Target Agent</label>
          <select class="form-control" id="dispatch-agent">${agentOptions}</select>
        </div>
        <div class="form-group">
          <label class="form-label">Command</label>
          <input class="form-control mono" id="dispatch-cmd" placeholder="whoami" autocomplete="off">
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3)">
          <div class="form-group">
            <label class="form-label">Working Directory</label>
            <input class="form-control mono" id="dispatch-workdir" placeholder="(optional)">
          </div>
          <div class="form-group">
            <label class="form-label">Timeout (s)</label>
            <input class="form-control" id="dispatch-timeout" type="number" value="60" min="0" max="3600">
          </div>
        </div>
      </div>`;

    const { close } = Modal.create({
      title: 'Dispatch Command',
      body: formEl,
      footer: `
        <button class="btn btn-secondary btn-sm" id="modal-cancel">Cancel</button>
        <button class="btn btn-primary btn-sm" id="modal-dispatch">Dispatch</button>`,
    });

    document.getElementById('modal-cancel').addEventListener('click', close);
    document.getElementById('modal-dispatch').addEventListener('click', async () => {
      const agentId = document.getElementById('dispatch-agent').value;
      const cmd     = document.getElementById('dispatch-cmd').value.trim();
      const workdir = document.getElementById('dispatch-workdir').value.trim();
      const timeout = parseInt(document.getElementById('dispatch-timeout').value) || 60;
      if (!cmd) { Toast.warning('Empty command'); return; }
      try {
        await API.commands.execute(agentId, cmd, { working_dir: workdir || undefined, timeout, operation_type: 'execute' });
        Toast.success('Command dispatched', cmd);
        close();
        await loadAll();
      } catch (e) {
        Toast.error('Dispatch failed', e.message);
      }
    });
  }

  function skeletonCards(n) {
    return Array(n).fill(0).map(() => `
      <div class="stat-card">
        <div class="stat-card-header">
          <span class="skeleton" style="width:70px;height:11px"></span>
        </div>
        <span class="skeleton" style="width:48px;height:26px"></span>
      </div>`).join('');
  }

  return { render };
})();

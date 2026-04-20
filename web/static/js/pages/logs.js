/**
 * pages/logs.js — Server log viewer with filtering and live tail
 */

const PageLogs = (() => {
  let tailTimer  = null;
  let lastTs     = null;
  let allLogs    = [];

  const LEVEL_COLORS = {
    DEBUG:    'var(--text-muted)',
    INFO:     'var(--accent-blue)',
    WARN:     'var(--accent-orange)',
    WARNING:  'var(--accent-orange)',
    ERROR:    'var(--accent-red)',
    CRITICAL: 'var(--accent-red)',
  };

  async function render() {
    const el = document.getElementById('page-logs');
    el.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Logs</h1>
          <p class="page-description">Server event stream with filtering</p>
        </div>
        <div class="page-actions">
          <button class="btn btn-secondary btn-sm" id="btn-refresh-logs">↺ Refresh</button>
          <button class="btn btn-secondary btn-sm" id="btn-export-logs">⬇ Export</button>
          <label style="display:flex;align-items:center;gap:6px;font-size:var(--text-sm);color:var(--text-secondary);cursor:pointer;border:1px solid var(--border);padding:4px 10px;border-radius:var(--radius-md)">
            <input type="checkbox" id="logs-tail" style="accent-color:var(--accent-blue)">
            Live tail
          </label>
        </div>
      </div>

      <div class="panel">
        <div class="filter-bar">
          <select class="form-control" id="log-level-filter" style="width:120px">
            <option value="">All Levels</option>
            <option value="DEBUG">DEBUG</option>
            <option value="INFO">INFO</option>
            <option value="WARN">WARN</option>
            <option value="ERROR">ERROR</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
          <select class="form-control" id="log-category-filter" style="width:160px">
            <option value="">All Categories</option>
            <option value="SYSTEM">System</option>
            <option value="AGENT_CONNECTION">Agent Connection</option>
            <option value="COMMAND_EXEC">Command Exec</option>
            <option value="FILE_TRANSFER">File Transfer</option>
            <option value="AUTHENTICATION">Authentication</option>
            <option value="AUDIT">Audit</option>
          </select>
          <div class="input-group" style="flex:1;min-width:180px">
            <svg class="input-group-icon" viewBox="0 0 16 16" fill="currentColor">
              <path d="M10.68 11.74a6 6 0 01-7.922-8.982 6 6 0 018.982 7.922l3.04 3.04a.749.749 0 01-.326 1.275.749.749 0 01-.734-.215l-3.04-3.04zM11.5 7a4.499 4.499 0 11-8.997 0A4.499 4.499 0 0111.5 7z"/>
            </svg>
            <input class="form-control" id="log-search" placeholder="Search message, agent ID…" type="search">
          </div>
          <select class="form-control" id="log-limit" style="width:90px">
            <option value="100">100</option>
            <option value="250">250</option>
            <option value="500">500</option>
            <option value="1000">1000</option>
          </select>
          <span id="log-count" class="text-muted" style="font-size:var(--text-sm);white-space:nowrap"></span>
        </div>

        <div id="log-view-type">
          <div class="tabs" style="padding:0 var(--space-4)">
            <div class="tab active" data-view="table">Table</div>
            <div class="tab" data-view="raw">Raw</div>
          </div>
        </div>

        <div id="logs-body" class="panel-body no-pad">
          <div style="padding:var(--space-10);text-align:center">
            <div class="loading-spinner" style="margin:auto"></div>
          </div>
        </div>
      </div>`;

    document.getElementById('btn-refresh-logs').addEventListener('click', loadLogs);
    document.getElementById('btn-export-logs').addEventListener('click', exportLogs);
    document.getElementById('log-level-filter').addEventListener('change', applyFilters);
    document.getElementById('log-category-filter').addEventListener('change', applyFilters);
    document.getElementById('log-search').addEventListener('input', applyFilters);
    document.getElementById('log-limit').addEventListener('change', loadLogs);
    document.getElementById('logs-tail').addEventListener('change', e => {
      if (e.target.checked) {
        tailTimer = setInterval(loadLogs, 3000);
      } else {
        clearInterval(tailTimer);
        tailTimer = null;
      }
    });

    document.querySelectorAll('#log-view-type .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('#log-view-type .tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        applyFilters();
      });
    });

    await loadLogs();
  }

  async function loadLogs() {
    const limit    = document.getElementById('log-limit').value || 100;
    const level    = document.getElementById('log-level-filter').value;
    const category = document.getElementById('log-category-filter').value;

    let qs = `?count=${limit}`;
    if (level)    qs += `&level=${level}`;
    if (category) qs += `&category=${category}`;

    try {
      const data = await API.server.logs(qs);
      allLogs = data.logs || [];
      applyFilters();
    } catch (e) {
      Toast.error('Failed to load logs', e.message);
    }
  }

  function applyFilters() {
    const q  = (document.getElementById('log-search').value || '').toLowerCase();
    const filtered = q
      ? allLogs.filter(l =>
          (l.message || '').toLowerCase().includes(q) ||
          (l.agent_id || '').toLowerCase().includes(q) ||
          (l.category || '').toLowerCase().includes(q))
      : allLogs;

    document.getElementById('log-count').textContent =
      `${filtered.length} / ${allLogs.length} entries`;

    const view = document.querySelector('#log-view-type .tab.active')?.dataset.view || 'table';
    if (view === 'raw') renderRaw(filtered);
    else renderTable(filtered);
  }

  function renderTable(logs) {
    const body = document.getElementById('logs-body');
    if (!logs.length) {
      body.innerHTML = `<div class="table-empty">
        <div class="table-empty-icon">📄</div>
        <div class="table-empty-text">No log entries</div>
      </div>`;
      return;
    }

    const rows = logs.map(l => {
      const lvl   = (l.level || '').toUpperCase();
      const color = LEVEL_COLORS[lvl] || 'var(--text-secondary)';
      return `<tr>
        <td class="mono text-muted" style="white-space:nowrap;width:160px">${escHtml(fmtTs(l.timestamp))}</td>
        <td style="width:80px">
          <span style="font-size:var(--text-xs);font-weight:600;font-family:var(--font-mono);color:${color}">${escHtml(lvl)}</span>
        </td>
        <td style="width:140px"><span class="badge badge-gray">${escHtml(l.category || '—')}</span></td>
        <td class="mono" style="width:100px;overflow:hidden;text-overflow:ellipsis">${escHtml(shortId(l.agent_id))}</td>
        <td style="color:var(--text-secondary);max-width:500px">${escHtml(l.message || '')}</td>
      </tr>`;
    }).join('');

    body.innerHTML = `
      <div class="data-table-wrapper">
        <table class="data-table">
          <thead><tr>
            <th>Timestamp</th>
            <th>Level</th>
            <th>Category</th>
            <th>Agent</th>
            <th>Message</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  function renderRaw(logs) {
    const body = document.getElementById('logs-body');
    const lines = logs.map(l => {
      const lvl   = (l.level || '').toUpperCase().padEnd(8);
      const color = LEVEL_COLORS[lvl.trim()] || 'var(--text-secondary)';
      return `<span style="color:var(--text-muted)">${escHtml(fmtTs(l.timestamp))}</span> ` +
             `<span style="color:${color};font-weight:600">${escHtml(lvl)}</span>` +
             `<span style="color:var(--text-muted)"> [${escHtml(l.category || '')}]</span> ` +
             escHtml(l.message || '');
    }).join('\n');

    body.innerHTML = `
      <div class="terminal-body" style="min-height:400px;max-height:600px">${lines || '(empty)'}</div>`;
  }

  function exportLogs() {
    const q = document.getElementById('log-search').value.toLowerCase();
    const filtered = q ? allLogs.filter(l =>
      (l.message || '').toLowerCase().includes(q) ||
      (l.agent_id || '').toLowerCase().includes(q)) : allLogs;

    const csv = [
      ['timestamp','level','category','agent_id','message'].join(','),
      ...filtered.map(l => [
        l.timestamp || '', l.level || '', l.category || '',
        l.agent_id || '', `"${(l.message || '').replace(/"/g, '""')}"`,
      ].join(',')),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `taburtuai-logs-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    Toast.success('Export ready', `${filtered.length} entries downloaded`);
  }

  function fmtTs(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    if (isNaN(d)) return ts;
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  }

  return { render };
})();

/**
 * ui.js — Shared UI primitives: Toast, Modal, Table builder, helpers.
 */

// ── Toast ────────────────────────────────────────────────────────────────────
const Toast = (() => {
  let container;

  function getContainer() {
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    return container;
  }

  const icons = {
    success: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M13.78 4.22a.75.75 0 010 1.06l-7.25 7.25a.75.75 0 01-1.06 0L2.22 9.28a.75.75 0 011.06-1.06L6 10.94l6.72-6.72a.75.75 0 011.06 0z"/></svg>`,
    error:   `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M2.343 13.657A8 8 0 1113.657 2.343 8 8 0 012.343 13.657zM6.03 4.97a.75.75 0 00-1.06 1.06L6.94 8 4.97 9.97a.75.75 0 101.06 1.06L8 9.06l1.97 1.97a.75.75 0 101.06-1.06L9.06 8l1.97-1.97a.75.75 0 10-1.06-1.06L8 6.94 6.03 4.97z"/></svg>`,
    warning: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M6.457 1.047c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575zm1.763.707a.25.25 0 00-.44 0L1.698 13.132a.25.25 0 00.22.368h12.164a.25.25 0 00.22-.368L8.22 1.754zM9 11a1 1 0 11-2 0 1 1 0 012 0zM8.25 6.75a.75.75 0 00-1.5 0v2.5a.75.75 0 001.5 0v-2.5z"/></svg>`,
    info:    `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M0 8a8 8 0 1116 0A8 8 0 010 8zm8-6.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM6.5 7.75A.75.75 0 017.25 7h1a.75.75 0 01.75.75v2.75h.25a.75.75 0 010 1.5h-2a.75.75 0 010-1.5h.25v-2h-.25a.75.75 0 01-.75-.75zM8 6a1 1 0 110-2 1 1 0 010 2z"/></svg>`,
  };

  function show(type, title, msg, duration = 4000) {
    const t = document.createElement('div');
    t.className = `toast toast-${type}`;
    t.innerHTML = `
      <span class="toast-icon">${icons[type] || icons.info}</span>
      <div class="toast-body">
        <div class="toast-title">${escHtml(title)}</div>
        ${msg ? `<div class="toast-msg">${escHtml(msg)}</div>` : ''}
      </div>`;
    getContainer().appendChild(t);
    if (duration > 0) setTimeout(() => dismiss(t), duration);
    return t;
  }

  function dismiss(el) {
    el.classList.add('removing');
    el.addEventListener('animationend', () => el.remove(), { once: true });
  }

  return {
    success: (title, msg, d)  => show('success', title, msg, d),
    error:   (title, msg, d)  => show('error',   title, msg, d),
    warning: (title, msg, d)  => show('warning', title, msg, d),
    info:    (title, msg, d)  => show('info',    title, msg, d),
  };
})();

// ── Modal ────────────────────────────────────────────────────────────────────
const Modal = (() => {
  function create({ title, body, footer, size = '' } = {}) {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.innerHTML = `
      <div class="modal${size ? ' modal-' + size : ''}">
        <div class="modal-header">
          <h4 class="modal-title">${escHtml(title || '')}</h4>
          <button class="modal-close" aria-label="Close">✕</button>
        </div>
        <div class="modal-body"></div>
        ${footer ? `<div class="modal-footer"></div>` : ''}
      </div>`;

    const bodyEl   = backdrop.querySelector('.modal-body');
    const footerEl = backdrop.querySelector('.modal-footer');

    if (typeof body === 'string') bodyEl.innerHTML = body;
    else if (body instanceof Node) bodyEl.appendChild(body);

    if (footerEl) {
      if (typeof footer === 'string') footerEl.innerHTML = footer;
      else if (footer instanceof Node) footerEl.appendChild(footer);
    }

    backdrop.querySelector('.modal-close').addEventListener('click', close);
    backdrop.addEventListener('click', e => { if (e.target === backdrop) close(); });
    document.addEventListener('keydown', onKey);
    document.body.appendChild(backdrop);
    requestAnimationFrame(() => backdrop.classList.add('open'));

    function close() {
      backdrop.classList.remove('open');
      document.removeEventListener('keydown', onKey);
      backdrop.addEventListener('transitionend', () => backdrop.remove(), { once: true });
    }

    function onKey(e) { if (e.key === 'Escape') close(); }

    return { el: backdrop, bodyEl, close };
  }

  return { create };
})();

// ── Table builder ────────────────────────────────────────────────────────────
function buildTable(columns, rows, opts = {}) {
  if (!rows || rows.length === 0) {
    return `<div class="table-empty">
      <div class="table-empty-icon">📭</div>
      <div class="table-empty-text">${opts.emptyText || 'No data'}</div>
    </div>`;
  }

  const thead = columns.map(c =>
    `<th style="${c.width ? `width:${c.width}` : ''}">${escHtml(c.label)}</th>`
  ).join('');

  const tbody = rows.map(row => {
    const cells = columns.map(c => {
      const raw = typeof c.value === 'function' ? c.value(row) : (row[c.key] ?? '');
      const cls = [c.cls, c.mono ? 'mono' : '', c.primary ? 'primary' : ''].filter(Boolean).join(' ');
      return `<td class="${cls}">${c.render ? c.render(raw, row) : escHtml(String(raw))}</td>`;
    }).join('');
    const rowAttrs = opts.onRow ? ` data-id="${row.id || ''}" style="cursor:pointer"` : '';
    return `<tr${rowAttrs}>${cells}</tr>`;
  }).join('');

  const html = `
    <div class="data-table-wrapper">
      <table class="data-table">
        <thead><tr>${thead}</tr></thead>
        <tbody>${tbody}</tbody>
      </table>
    </div>`;

  return html;
}

// ── Status badge helper ──────────────────────────────────────────────────────
function statusBadge(status) {
  if (!status) return '';
  const s = status.toLowerCase();
  return `<span class="badge badge-${s}"><span class="badge-dot"></span>${escHtml(status)}</span>`;
}

// ── Relative time ────────────────────────────────────────────────────────────
function relTime(isoOrUnix) {
  if (!isoOrUnix) return '—';
  const d = new Date(typeof isoOrUnix === 'number' ? isoOrUnix * 1000 : isoOrUnix);
  if (isNaN(d)) return '—';
  const diff = Date.now() - d.getTime();
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return d.toLocaleDateString();
}

// ── HTML escape ──────────────────────────────────────────────────────────────
function escHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Format duration ──────────────────────────────────────────────────────────
function fmtDuration(ms) {
  if (!ms || ms < 0) return '—';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

// ── Format bytes ─────────────────────────────────────────────────────────────
function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

// ── Truncate UUID ─────────────────────────────────────────────────────────────
function shortId(id) {
  if (!id) return '—';
  return id.slice(0, 8) + '…';
}

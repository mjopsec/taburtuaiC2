/**
 * app.js — Entry point: router, sidebar navigation, clock, health pulse.
 *
 * Pages are rendered into pre-existing <div id="page-*"> elements.
 * Navigating to a page calls its render() function once, then marks it loaded.
 * Subsequent visits are instant (no re-render) unless the user hits Refresh.
 */

const App = (() => {

  const PAGES = {
    overview: { title: 'Overview',       module: () => PageOverview },
    agents:   { title: 'Agents',         module: () => PageAgents },
    commands: { title: 'Commands',       module: () => PageCommands },
    logs:     { title: 'Logs',           module: () => PageLogs },
  };

  let currentPage = null;
  const rendered  = new Set();

  // ── Boot ──────────────────────────────────────────────────────────────────
  function init() {
    startClock();
    bindNav();
    bindKeyboard();
    navigate(getHashPage() || 'overview');
    pollHealth();
    setInterval(pollHealth, 15000);
  }

  // ── Router ────────────────────────────────────────────────────────────────
  async function navigate(pageId) {
    if (!PAGES[pageId]) pageId = 'overview';
    if (currentPage === pageId) return;

    // Deactivate current
    if (currentPage) {
      document.getElementById(`page-${currentPage}`)?.classList.remove('active');
      document.querySelector(`.nav-item[data-page="${currentPage}"]`)?.classList.remove('active');
    }

    currentPage = pageId;
    window.location.hash = pageId;

    // Activate new
    const pageEl = document.getElementById(`page-${pageId}`);
    if (pageEl) pageEl.classList.add('active');

    document.querySelector(`.nav-item[data-page="${pageId}"]`)?.classList.add('active');

    // Update topbar title
    const topTitle = document.getElementById('topbar-title');
    if (topTitle) topTitle.textContent = PAGES[pageId].title;

    // Render if not yet rendered
    if (!rendered.has(pageId)) {
      rendered.add(pageId);
      try {
        await PAGES[pageId].module().render();
      } catch (e) {
        console.error(`[App] Failed to render page ${pageId}:`, e);
        Toast.error('Page error', e.message);
      }
    }
  }

  function getHashPage() {
    return window.location.hash.replace('#', '') || null;
  }

  // ── Sidebar nav ───────────────────────────────────────────────────────────
  function bindNav() {
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      item.addEventListener('click', () => navigate(item.dataset.page));
    });
    window.addEventListener('hashchange', () => navigate(getHashPage() || 'overview'));
  }

  // ── Keyboard shortcuts ────────────────────────────────────────────────────
  function bindKeyboard() {
    document.addEventListener('keydown', e => {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' ||
          e.target.tagName === 'SELECT') return;
      const map = { '1': 'overview', '2': 'agents', '3': 'commands', '4': 'logs' };
      if (map[e.key]) { e.preventDefault(); navigate(map[e.key]); }
    });
  }

  // ── Clock ─────────────────────────────────────────────────────────────────
  function startClock() {
    const el = document.getElementById('topbar-clock');
    if (!el) return;
    function tick() {
      el.textContent = new Date().toLocaleTimeString('en-US', {
        hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
      });
    }
    tick();
    setInterval(tick, 1000);
  }

  // ── Health pulse ──────────────────────────────────────────────────────────
  async function pollHealth() {
    const dot   = document.querySelector('.status-dot');
    const label = document.querySelector('.status-label');
    const value = document.querySelector('.status-value');
    if (!dot) return;

    try {
      const h = await API.server.health();
      const status = (h.status || 'healthy').toLowerCase();
      dot.className   = `status-dot${status !== 'healthy' ? ' offline' : ''}`;
      if (label) label.textContent = status === 'healthy' ? 'Server Online' : 'Degraded';
      if (value) value.textContent = `v${h.version || '2.0.0'} · ${formatUptime(h.uptime)}`;

      // Update online agents badge in nav
      if (h.components) {
        const agentsData = await API.agents.list().catch(() => ({ agents: [] }));
        const online = (agentsData.agents || []).filter(a => a.status === 'online').length;
        const badge  = document.querySelector('.nav-item[data-page="agents"] .nav-badge');
        if (badge) {
          badge.textContent = online;
          badge.style.display = online > 0 ? '' : 'none';
        }
      }
    } catch {
      if (dot) { dot.className = 'status-dot offline'; }
      if (label) label.textContent = 'Server Offline';
    }
  }

  function formatUptime(s) {
    if (!s) return '';
    const m = s.match(/(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?/);
    if (!m) return s;
    const h = parseInt(m[1] || 0), min = parseInt(m[2] || 0);
    if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
    if (h > 0) return `${h}h ${min}m`;
    return `${min}m uptime`;
  }

  // expose navigate for cross-module use
  return { init, navigate };
})();

// Bootstrap when DOM is ready
document.addEventListener('DOMContentLoaded', () => App.init());

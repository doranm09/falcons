// static/dashboard/js/home.js - Home dashboard KPI updates
document.addEventListener('DOMContentLoaded', function () {
  // Elements
  const kpiTotalNodes = document.getElementById('kpi-total-nodes');
  const kpiOnlineNodes = document.getElementById('kpi-online-nodes');
  const kpiOnlineAgents = document.getElementById('kpi-online-agents');
  const kpiCriticalVulns = document.getElementById('kpi-critical-vulns');

  // --- CSRF helpers ---
  function getCSRFToken() {
    const input = document.querySelector('[name=csrfmiddlewaretoken]');
    if (input && input.value) return input.value;
    const name = 'csrftoken=';
    const cookies = document.cookie ? document.cookie.split(';') : [];
    for (let c of cookies) { c = c.trim(); if (c.startsWith(name)) return decodeURIComponent(c.slice(name.length)); }
    return '';
  }

  async function jsonFetch(url, opts = {}) {
    const headers = opts.headers || {};
    const method  = (opts.method || 'GET').toUpperCase();
    const csrf    = getCSRFToken();
    const final = {
      ...opts,
      method,
      headers: {
        'Accept': 'application/json',
        ...(method !== 'GET' && method !== 'HEAD' ? {'X-CSRFToken': csrf} : {}),
        ...headers
      }
    };
    const res = await fetch(url, final);
    let data; try { data = await res.json(); } catch { data = null; }
    if (!res.ok) throw new Error((data && (data.detail || data.error || data.message)) || `HTTP ${res.status}`);
    return data;
  }

  // --- KPI Updates ---
  async function updateKPIs() {
    try {
      // Get agent status data
      const agentData = await jsonFetch('/agent/status/');
      const agents = agentData.agents || [];

      // Count online agents
      const onlineAgents = agents.filter(agent => agent.status === 'online').length;

      // Get node count from agents (since agents also create nodes)
      const nodeCount = agents.length; // Each agent has a corresponding node

      // Update KPIs
      if (kpiTotalNodes) kpiTotalNodes.textContent = nodeCount.toString();
      if (kpiOnlineAgents) {
        kpiOnlineAgents.textContent = onlineAgents.toString();
      }
      if (kpiOnlineNodes) {
        // For now, online nodes = online agents (since agents report as nodes)
        kpiOnlineNodes.textContent = onlineAgents.toString();
      }

      // For critical vulnerabilities, we could add a vuln count endpoint
      // For now, leave as placeholder

    } catch (e) {
      console.warn('KPI update failed:', e.message);
    }
  }

  // --- Initialize ---
  updateKPIs();

  // Update KPIs every 30 seconds
  setInterval(updateKPIs, 30000);
});

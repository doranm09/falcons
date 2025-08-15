// static/dashboard/js/scan.js

document.addEventListener('DOMContentLoaded', function () {
  // Elements
  const scanForm   = document.getElementById('scan-form');
  const vulnForm   = document.getElementById('vuln-scan-form');
  const scanStatus = document.getElementById('scan-status');
  const nodesBody  = document.getElementById('nodes-body');
  const historyTbody = document.getElementById('scan-history-body');

  // --- CSRF helpers ---
  function getCSRFToken() {
    // Prefer hidden input (Django forms), fallback to cookie
    const input = document.querySelector('[name=csrfmiddlewaretoken]');
    if (input && input.value) return input.value;

    // Cookie fallback
    const name = 'csrftoken=';
    const cookies = document.cookie ? document.cookie.split(';') : [];
    for (let c of cookies) {
      c = c.trim();
      if (c.startsWith(name)) return decodeURIComponent(c.slice(name.length));
    }
    return '';
  }

  function jsonFetch(url, opts = {}) {
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
    return fetch(url, final).then(async res => {
      // Try to parse JSON even on non-2xx to surface server error messages
      let data;
      try { data = await res.json(); } catch { data = null; }
      if (!res.ok) {
        const msg = data && (data.detail || data.error || data.message) || `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return data;
    });
  }

  // --- UI helpers ---
  function setStatus(msg, type = 'muted') {
    if (!scanStatus) return;
    scanStatus.className = `mt-3 text-${type}`;
    scanStatus.innerText = msg;
  }

  function disableForm(form, disabled) {
    if (!form) return;
    const btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = disabled;
    const input = form.querySelector('input,select,textarea');
    if (input) input.disabled = disabled;
  }

  // --- History table refresh ---
  async function updateScanHistory() {
    try {
      const data = await jsonFetch('/scan/history/');
      if (!historyTbody) return;
      historyTbody.innerHTML = '';
      (data.history || []).forEach(run => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(run.timestamp || '')}</td>
          <td>${escapeHtml(run.cidr || '')}</td>
          <td>${escapeHtml(run.status || '')}</td>
          <td>${escapeHtml(run.summary || run.result_summary || '-')}</td>
        `;
        historyTbody.appendChild(tr);
      });
      if (!data.history || data.history.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="4">No scans found.</td>`;
        historyTbody.appendChild(tr);
      }
    } catch (err) {
      // non-fatal
      console.warn('Failed to refresh scan history:', err.message);
    }
  }

  // --- Nodes table refresh (from scan status payload) ---
  function renderNodes(nodes = []) {
    if (!nodesBody) return;
    nodesBody.innerHTML = '';
    nodes.forEach(node => {
      const li = (node.interfaces || []).map(i =>
        `<li>${escapeHtml(i.name || '')}: ${escapeHtml(i.ip || '')} / ${escapeHtml(i.mac || '')}</li>`
      ).join('');

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escapeHtml(node.ip_address || '')}</td>
        <td>${escapeHtml(node.name || '')}</td>
        <td>${escapeHtml(node.status || '')}</td>
        <td>${escapeHtml(node.last_heartbeat || '')}</td>
        <td>
          ${escapeHtml(node.description || '')}
          ${li ? `<ul style="font-size: 0.85em; margin-top: 0.5em;">${li}</ul>` : ''}
        </td>
      `;
      nodesBody.appendChild(tr);
    });
  }

  // --- Cytoscape graph ---
  let cyInstance = null;
  async function renderGraph() {
    try {
      const data = await jsonFetch('/graph/data/');
      // Destroy old instance if present to avoid overlays
      if (cyInstance) {
        cyInstance.destroy();
        cyInstance = null;
      }
      cyInstance = cytoscape({
        container: document.getElementById('cy'),
        elements: data,
        style: [
          {
            selector: 'node',
            style: {
              'label': 'data(label)',
              'background-color': '#007bff',
              'text-valign': 'bottom',
              'text-halign': 'center',
              'color': '#000',
              'font-size': 12,
              'text-margin-y': 6,
              'text-background-color': '#fff',
              'text-background-opacity': 1,
              'text-background-shape': 'roundrectangle',
              'text-border-color': '#333',
              'text-border-width': 0.5,
              'text-border-opacity': 0.8,
              'border-width': 1,
              'border-color': '#fff'
            }
          },
          {
            selector: 'edge',
            style: {
              'label': 'data(weight)',
              'font-size': 10,
              'color': '#000',
              'text-background-color': '#fff',
              'text-background-opacity': 1,
              'text-background-shape': 'roundrectangle',
              'text-rotation': 'autorotate',
              'curve-style': 'bezier',
              'width': 2,
              'line-color': 'mapData(raw_weight, 0, 6, green, red)',
              'target-arrow-shape': 'triangle',
              'target-arrow-color': 'mapData(raw_weight, 0, 6, green, red)'
            }
          }
        ],
        layout: {
          name: 'concentric',
          concentric: node => node.degree(),
          levelWidth: () => 2,
          spacingFactor: 5,
          animate: true
        }
      });

      // Shortest path tap-to-select behavior
      const pathResult = document.getElementById('path-result');
      let selectedNode = null;

      cyInstance.on('tap', 'node', function (evt) {
        const tapped = evt.target;
        if (!selectedNode) {
          selectedNode = tapped;
          tapped.style('background-color', '#ffc107');
        } else {
          const sourceId = selectedNode.id();
          const targetId = tapped.id();
          jsonFetch(`/shortest-paths/${encodeURIComponent(sourceId)}/`)
            .then(pathData => {
              const cost = pathData[targetId];
              if (pathResult) {
                pathResult.innerText = `Shortest path from ${selectedNode.data('label')} to ${tapped.data('label')}: ${cost}`;
              }
            })
            .catch(err => {
              if (pathResult) {
                pathResult.innerText = `Could not fetch shortest path: ${err.message}`;
              }
            });
          selectedNode.style('background-color', '#007bff');
          selectedNode = null;
        }
      });

      // Handle container resizes (e.g., when tabs or panels change)
      debounceResize(() => {
        if (cyInstance) cyInstance.resize();
      });

    } catch (err) {
      console.warn('Graph render failed:', err.message);
    }
  }

  // --- Debounce resize helper ---
  let resizeTimer = null;
  function debounceResize(cb, delay = 150) {
    window.removeEventListener('resize', onResize);
    function onResize() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(cb, delay);
    }
    window.addEventListener('resize', onResize);
  }

  // --- HTML escape to reduce accidental injection from server data ---
  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // --- Polling engines ---
  function pollTask({ statusUrl, onTick, onDone, onError, intervalMs = 2000, maxMinutes = 30 }) {
    const started = Date.now();
    let stopped = false;

    async function tick() {
      if (stopped) return;
      try {
        const statusData = await jsonFetch(statusUrl);
        onTick && onTick(statusData);

        if (statusData.state === 'SUCCESS' || statusData.state === 'FAILURE' || statusData.state === 'REVOKED') {
          stopped = true;
          onDone && onDone(statusData);
          return;
        }
      } catch (err) {
        // Stop (or keep going) based on error type; we’ll stop to avoid hammering
        stopped = true;
        onError && onError(err);
        return;
      }

      if ((Date.now() - started) > maxMinutes * 60 * 1000) {
        stopped = true;
        onError && onError(new Error('Timed out.'));
        return;
      }
      setTimeout(tick, intervalMs);
    }

    tick();
    return () => { stopped = true; };
  }

  // --- Network scan submit ---
  if (scanForm) {
    scanForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      disableForm(scanForm, true);
      setStatus('Starting discovery scan…');

      try {
        const formData = new FormData(scanForm);
        const data = await fetch('/scan/start/', {
          method: 'POST',
          headers: { 'X-CSRFToken': getCSRFToken() },
          body: formData
        }).then(r => r.json());

        const taskId = data.task_id;
        if (!taskId) throw new Error('Missing task id');
        setStatus('Scan started…');

        // Begin polling
        pollTask({
          statusUrl: `/scan/status/${encodeURIComponent(taskId)}/`,
          onTick: (statusData) => {
            setStatus(`Scanning… (${statusData.state})`);
          },
          onDone: (statusData) => {
            if (statusData.state === 'SUCCESS') {
              setStatus('Scan complete. Nodes updated.', 'success');
              renderNodes(statusData.nodes || []);
              updateScanHistory();
              renderGraph();
            } else {
              setStatus(`Scan finished with state: ${statusData.state}`, 'warning');
            }
            disableForm(scanForm, false);
          },
          onError: (err) => {
            setStatus(`Scan failed: ${err.message}`, 'danger');
            disableForm(scanForm, false);
          }
        });
      } catch (err) {
        setStatus(`Could not start scan: ${err.message}`, 'danger');
        disableForm(scanForm, false);
      }
    });
  }

  // --- Vulnerability (OpenVAS) scan submit ---
  if (vulnForm) {
    vulnForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      disableForm(vulnForm, true);

      try {
        const formData = new FormData(vulnForm);
        const res = await fetch('/scan/vuln/start/', {
          method: 'POST',
          headers: { 'X-CSRFToken': getCSRFToken() },
          body: formData
        });
        const payload = await res.json();
        const taskId = payload.task_id;
        if (!taskId) throw new Error('Missing task id');

        setStatus(`OpenVAS scan launched (task ${taskId}). Monitoring progress…`, 'warning');

        // Try polling a conventional endpoint if your backend exposes it
        // If not available, we’ll just leave the “launched” notice.
        pollTask({
          statusUrl: `/scan/vuln/status/${encodeURIComponent(taskId)}/`,
          onTick: (statusData) => {
            // You can surface more details if your API returns % complete
            setStatus(`OpenVAS scanning… (${statusData.state})`, 'warning');
          },
          onDone: (statusData) => {
            if (statusData.state === 'SUCCESS') {
              setStatus('OpenVAS scan complete. Results ready.', 'success');
              // If your endpoint returns summaries, you could append them here
              updateScanHistory();
            } else {
              setStatus(`OpenVAS scan finished with state: ${statusData.state}`, 'warning');
            }
            disableForm(vulnForm, false);
          },
          onError: (err) => {
            // If the status endpoint doesn’t exist, keep a friendly message
            setStatus(`OpenVAS status check unavailable or failed (${err.message}). Scan is running in the background.`, 'muted');
            disableForm(vulnForm, false);
          }
        });
      } catch (err) {
        setStatus(`Could not start OpenVAS scan: ${err.message}`, 'danger');
        disableForm(vulnForm, false);
      }
    });
  }

  // Initial draws/refreshes
  renderGraph();
  updateScanHistory();
});

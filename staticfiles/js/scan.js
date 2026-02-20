// static/dashboard/js/scan.js
document.addEventListener('DOMContentLoaded', function () {
  // Elements
  const scanForm     = document.getElementById('scan-form');
  const vulnForm     = document.getElementById('vuln-scan-form');
  const agentScanForm = document.getElementById('agent-scan-form');
  const campaignForm = document.getElementById('campaign-form');
  const scanStatus   = document.getElementById('scan-status');
  const campaignStatus = document.getElementById('campaign-status');
  const campaignOpenvasUiLink = document.getElementById('campaign-openvas-ui-link');
  const campaignReportLink = document.getElementById('campaign-report-link');
  const campaignOpenvasTask = document.getElementById('campaign-openvas-task');
  const campaignLogConsole = document.getElementById('campaign-log-console');
  const nodesBody    = document.getElementById('nodes-body');
  const historyTbody = document.getElementById('scan-history-body');
  const campaignHistoryBody = document.getElementById('campaign-history-body');
  const btnDownloadPng = document.getElementById('btn-download-png');

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

  // --- UI helpers ---
  function setStatus(msg, type = 'muted') {
    if (!scanStatus) return;
    scanStatus.className = `mt-3 text-${type}`;
    scanStatus.innerText = msg;
  }
  function setCampaignStatus(msg, type = 'muted') {
    if (!campaignStatus) return;
    campaignStatus.className = `mt-3 small text-${type}`;
    campaignStatus.innerText = msg;
  }
  function setCampaignLogLines(lines = []) {
    if (!campaignLogConsole) return;
    const normalized = Array.isArray(lines)
      ? lines.map(line => String(line)).slice(-200)
      : [];
    campaignLogConsole.textContent = normalized.length
      ? normalized.join('\n')
      : 'Waiting for campaign output...';
    campaignLogConsole.scrollTop = campaignLogConsole.scrollHeight;
  }
  function appendCampaignLogLine(line) {
    if (!campaignLogConsole) return;
    const text = String(line || '').trim();
    if (!text) return;

    const current = campaignLogConsole.textContent === 'Waiting for campaign output...'
      ? []
      : String(campaignLogConsole.textContent || '').split('\n');
    if (current.length && current[current.length - 1] === text) return;
    current.push(text);
    while (current.length > 200) current.shift();
    campaignLogConsole.textContent = current.join('\n');
    campaignLogConsole.scrollTop = campaignLogConsole.scrollHeight;
  }
  function updateCampaignLinks(data = {}) {
    if (campaignOpenvasUiLink) {
      campaignOpenvasUiLink.href = data.openvas_ui_url || 'http://127.0.0.1:9392';
    }
    if (campaignReportLink) {
      if (data.report_url) {
        campaignReportLink.href = data.report_url;
        campaignReportLink.classList.remove('d-none');
      } else {
        campaignReportLink.href = '#';
        campaignReportLink.classList.add('d-none');
      }
    }
    if (campaignOpenvasTask) {
      campaignOpenvasTask.innerText = data.openvas_task_id ? `OpenVAS task: ${data.openvas_task_id}` : '';
    }
  }
  function disableForm(form, disabled) {
    if (!form) return;
    form.querySelectorAll('input,select,textarea,button').forEach(el => el.disabled = disabled);
  }
  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  }
  function badgeClass(status) {
    const normalized = String(status || '').toLowerCase();
    if (normalized === 'complete' || normalized === 'completed') return 'success';
    if (normalized === 'running' || normalized === 'in_progress') return 'info';
    if (normalized === 'failed') return 'danger';
    return 'secondary';
  }

  // --- History refresh ---
  async function updateScanHistory() {
    try {
      const data = await jsonFetch('/scan/history/');
      if (!historyTbody) return;
      historyTbody.innerHTML = '';
      (data.history || []).forEach(run => {
        const badge = badgeClass(run.status);
        const reportHref = run.scan_type === 'openvas' && run.id
          ? `/vulnerabilities/${encodeURIComponent(run.id)}/`
          : null;
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(run.timestamp || '')}</td>
          <td>${escapeHtml(run.cidr || '')}</td>
          <td><span class="badge bg-${badge}">${escapeHtml(run.status || '')}</span></td>
          <td>${escapeHtml(run.summary || run.result_summary || '-')}</td>
          <td>
            <div class="btn-group btn-group-sm">
              ${reportHref
                ? `<a class="btn btn-outline-primary" href="${reportHref}">Report</a>`
                : `<button class="btn btn-outline-primary" disabled>Report</button>`}
              <button class="btn btn-outline-secondary" disabled>Rescan</button>
              <button class="btn btn-outline-danger" disabled>Cancel</button>
            </div>
          </td>`;
        historyTbody.appendChild(tr);
      });
      if (!data.history || !data.history.length) {
        const tr = document.createElement('tr'); tr.innerHTML = `<td colspan="5">No scans found.</td>`; historyTbody.appendChild(tr);
      }
    } catch(e){ console.warn('History refresh failed:', e.message); }
  }

  async function updateCampaignHistory() {
    try {
      if (!campaignHistoryBody) return;
      const data = await jsonFetch('/scan/campaign/history/');
      campaignHistoryBody.innerHTML = '';

      (data.history || []).forEach(run => {
        const badge = badgeClass(run.status);
        const duration = run.duration_seconds == null ? '-' : `${run.duration_seconds}s`;
        const taskHint = run.openvas_task_id
          ? `<span class="small text-muted me-2">Task ${escapeHtml(run.openvas_task_id)}</span>`
          : '';
        const reportAction = run.report_url
          ? `<a class="btn btn-sm btn-outline-primary" href="${escapeHtml(run.report_url)}">Report</a>
             <a class="btn btn-sm btn-outline-secondary" href="${escapeHtml(run.openvas_ui_url || 'http://127.0.0.1:9392')}" target="_blank" rel="noopener">OpenVAS UI</a>`
          : '<button class="btn btn-sm btn-outline-secondary" disabled>-</button>';

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(run.started_at || '')}</td>
          <td>${escapeHtml(run.cidr || '')}</td>
          <td><span class="badge bg-${badge}">${escapeHtml(run.status || '')}</span></td>
          <td>${escapeHtml(duration)}</td>
          <td>${escapeHtml(run.discovered_hosts_count ?? 0)}</td>
          <td>${escapeHtml(run.vulnerability_count ?? 0)}</td>
          <td title="${escapeHtml(run.error_details || '')}">${escapeHtml(run.error_count ?? 0)}</td>
          <td>${taskHint}${reportAction}</td>
        `;
        campaignHistoryBody.appendChild(tr);
      });

      if (!data.history || !data.history.length) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td colspan="8">No campaign runs found.</td>';
        campaignHistoryBody.appendChild(tr);
      }
    } catch (e) {
      console.warn('Campaign history refresh failed:', e.message);
    }
  }

  // --- Nodes table ---
  function renderNodes(nodes = []) {
    if (!nodesBody) return;
    nodesBody.innerHTML = '';
    nodes.forEach(node => {
      const li = (node.interfaces || []).map(i =>
        `<li>${escapeHtml(i.name || '')}: ${escapeHtml(i.ip || '')} / ${escapeHtml(i.mac || '')}</li>`).join('');
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escapeHtml(node.ip_address || '')}</td>
        <td>${escapeHtml(node.name || '')}</td>
        <td>${escapeHtml(node.status || '')}</td>
        <td>${escapeHtml(node.last_heartbeat || '')}</td>
        <td>${escapeHtml(node.description || '')}${li ? `<ul style="font-size:.85em;margin-top:.5em;">${li}</ul>` : ''}</td>`;
      nodesBody.appendChild(tr);
    });
  }

  // --- Cytoscape graph ---
  let cyInstance = null;

  async function renderGraph() {
    const cyContainer = document.getElementById('cy');
    if (!cyContainer) return;
    try {
      const data = await jsonFetch('/graph/data/');
      if (cyInstance) { cyInstance.destroy(); cyInstance = null; }
      cyInstance = cytoscape({
        container: cyContainer,
        elements: data,
        style: [
          { selector: 'node', style: {
            'label':'data(label)', 'background-color':'#007bff', 'text-valign':'bottom', 'text-halign':'center',
            'color':'#000','font-size':12,'text-margin-y':6,'text-background-color':'#fff','text-background-opacity':1,
            'text-background-shape':'roundrectangle','text-border-color':'#333','text-border-width':0.5,'border-width':1,'border-color':'#fff'
          }},
          { selector: 'edge', style: {
            'label':'data(weight)','font-size':10,'color':'#000','text-background-color':'#fff','text-background-opacity':1,
            'text-background-shape':'roundrectangle','text-rotation':'autorotate','curve-style':'bezier','width':2,
            'line-color':'mapData(raw_weight,0,6,green,red)','target-arrow-shape':'triangle','target-arrow-color':'mapData(raw_weight,0,6,green,red)'
          }}
        ],
        layout: { name:'concentric', concentric:n=>n.degree(), levelWidth:()=>2, spacingFactor:5, animate:true }
      });

      // Path find (tap-to-select)
      const pathResult = document.getElementById('path-result');
      let selectedNode = null;
      cyInstance.on('tap','node',evt=>{
        const tapped = evt.target;
        const original = evt.originalEvent || {};

        if (original.shiftKey) {
          if (!selectedNode) { selectedNode = tapped; tapped.style('background-color','#ffc107'); }
          else {
            const src = selectedNode.data('path_id') || selectedNode.data('node_id') || selectedNode.id();
            const dst = tapped.data('path_id') || tapped.data('node_id') || tapped.id();
            if (!/^\d+$/.test(String(src)) || !/^\d+$/.test(String(dst))) {
              if (pathResult) pathResult.innerText = 'Shortest path unavailable for non-scan nodes.';
            } else {
              jsonFetch(`/shortest-paths/${encodeURIComponent(src)}/`).then(pd=>{
                const cost = pd[dst]; if (pathResult) pathResult.innerText = `Shortest path from ${selectedNode.data('label')} to ${tapped.data('label')}: ${cost}`;
              }).catch(err=>{ if (pathResult) pathResult.innerText = `Path error: ${err.message}`; });
            }
            selectedNode.style('background-color','#007bff'); selectedNode = null;
          }
          return;
        }

        const agentId = tapped.data('agent_id');
        if (agentId) {
          window.location.href = `/dashboard/agent/${encodeURIComponent(agentId)}/`;
          return;
        }

        const nodeId = tapped.data('node_id') || tapped.id();
        if (/^\d+$/.test(String(nodeId))) {
          window.location.href = `/dashboard/node/${encodeURIComponent(nodeId)}/`;
          return;
        }

        if (pathResult) pathResult.innerText = `No detail page for ${tapped.data('label') || tapped.id()}.`;
      });

    } catch (e) { console.warn('Graph render failed:', e.message); }
  }

  // --- PNG export (robust)
  function dataURLtoBlob(dataURL) {
    const [meta, data] = dataURL.split(',');
    const mime = (meta.match(/data:([^;]+)/) || [,'image/png'])[1];
    const bin = atob(data), len = bin.length, arr = new Uint8Array(len);
    for (let i=0;i<len;i++) arr[i] = bin.charCodeAt(i);
    return new Blob([arr], { type: mime });
  }
  function timestampFilename(prefix='network-graph', ext='png') {
    const pad=n=>String(n).padStart(2,'0'); const d=new Date();
    return `${prefix}_${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${ext}`;
  }
  function elementIsHidden(el){ return !el || el.offsetParent === null || el.clientWidth === 0 || el.clientHeight === 0; }
  function waitForRender(cy) {
    return new Promise(resolve => {
      // resolve on the next concrete render; use once() to avoid leaks
      const done = () => { cy.off('render', done); resolve(); };
      cy.on('render', done);
      // kick the renderer
      cy.resize(); cy.emit('render');
    });
  }
  async function exportPng() {
    if (!cyInstance) { setStatus('Graph not ready.','warning'); return; }
    const container = cyInstance.container();
    // guard: hidden or zero-size container -> white image
    if (elementIsHidden(container)) {
      console.warn('Export blocked — #cy size:', container.clientWidth, 'x', container.clientHeight);
      setStatus('Graph must be visible (non-zero size) before exporting.','warning');
      return;
    }

    try {
      // remember view
      const pan  = cyInstance.pan();
      const zoom = cyInstance.zoom();

      // fit for snapshot (toggle to false to keep current view)
      const SNAP_FULL_GRAPH = true;
      if (SNAP_FULL_GRAPH) cyInstance.fit();

      // ensure a real render happened at this size
      await waitForRender(cyInstance);

      // create data URL (sync)
      const dataUrl = cyInstance.png({ full: SNAP_FULL_GRAPH, scale: 2, bg: '#111111' }); // darker bg like your UI
      const blob = dataURLtoBlob(dataUrl);

      // restore view
      cyInstance.zoom(zoom); cyInstance.pan(pan);

      // download
      const filename = timestampFilename();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      setStatus('PNG downloaded.','success');
    } catch (err) {
      console.error(err);
      setStatus(`PNG export failed: ${err.message}`, 'danger');
    }
  }
  if (btnDownloadPng) btnDownloadPng.addEventListener('click', exportPng);

  // --- Polling ---
  function pollTask({ statusUrl, onTick, onDone, onError, intervalMs=2000, doneStates=['SUCCESS','FAILURE','REVOKED'] }) {
    let stopped=false;
    async function tick(){
      if(stopped) return;
      try{
        const data=await jsonFetch(statusUrl); onTick && onTick(data);
        if(doneStates.includes(data.state)){ stopped=true; onDone && onDone(data); return; }
      }catch(err){ stopped=true; onError && onError(err); return; }
      setTimeout(tick, intervalMs);
    }
    tick(); return ()=>{stopped=true;};
  }

  // --- Scan form ---
  if (scanForm) {
    scanForm.addEventListener('submit', async e=>{
      e.preventDefault();
      const formData=new FormData(scanForm);
      disableForm(scanForm,true);
      setStatus('Starting discovery scan…');
      try {
        const res=await fetch('/scan/start/',{method:'POST',headers:{'X-CSRFToken':getCSRFToken()},body:formData});
        const data=await res.json(); const taskId=data.task_id; if(!taskId) throw new Error('No task id');
        pollTask({
          statusUrl:`/scan/status/${encodeURIComponent(taskId)}/`,
          onTick:s=>{
            const p = s.progress;
            if (p && typeof p === 'object' && p.percent != null) {
              const detail = p.total ? `${p.current}/${p.total}` : `${p.current || 0}`;
              setStatus(`Scanning… ${p.percent}% (${detail})`,'info');
              return;
            }
            if (typeof p === 'string') {
              setStatus(`Scanning… ${p}`,'info');
              return;
            }
            setStatus(`Scanning… (${s.state})`,'info');
          },
          onDone:s=>{
            if(s.state==='SUCCESS'){ setStatus('Scan complete. Nodes updated.','success'); renderNodes(s.nodes||[]); updateScanHistory(); renderGraph(); }
            else setStatus(`Scan finished: ${s.state}`,'warning');
            disableForm(scanForm,false);
          },
          onError:err=>{ setStatus(`Scan failed: ${err.message}`,'danger'); disableForm(scanForm,false); }
        });
      } catch(err) {
        setStatus(`Could not start: ${err.message}`,'danger'); disableForm(scanForm,false);
      }
    });
  }

  // --- Vuln form ---
  if (vulnForm) {
    vulnForm.addEventListener('submit', async e=>{
      e.preventDefault();
      const formData=new FormData(vulnForm);
      disableForm(vulnForm,true);
      try {
        const res=await fetch('/scan/vuln/start/',{method:'POST',headers:{'X-CSRFToken':getCSRFToken()},body:formData});
        const data=await res.json(); const scan_id=data.scan_id; if(!scan_id) throw new Error(data.error || 'No scan id');
        const reportHref = `/vulnerabilities/${encodeURIComponent(scan_id)}/`;
        setStatus(`OpenVAS scan queued (scan ${scan_id}).`,'warning');
        pollTask({
          statusUrl:`/scan/vuln/status/${encodeURIComponent(scan_id)}/`,
          doneStates:['Done','ERROR'],
          onTick:s=>{
            if (s.state === 'LAUNCHING') {
              setStatus('OpenVAS scan launching…','warning');
              return;
            }
            const progress = s.progress ? ` ${s.progress}%` : '';
            setStatus(`OpenVAS scanning… (${s.state}${progress})`,'warning');
          },
          onDone:s=>{
            if (s.state === 'Done') {
              setStatus(`OpenVAS done. Report ready: ${reportHref}`,'success');
            } else {
              setStatus(`OpenVAS error: ${s.error || s.state}`,'danger');
            }
            updateScanHistory();
            disableForm(vulnForm,false);
          },
          onError:err=>{ setStatus(`OpenVAS status failed (${err.message})`,'muted'); disableForm(vulnForm,false); }
        });
      } catch(err){ setStatus(`Could not start OpenVAS: ${err.message}`,'danger'); disableForm(vulnForm,false); }
    });
  }

  if (agentScanForm) {
    agentScanForm.addEventListener('submit', async e => {
      e.preventDefault();
      const formData = new FormData(agentScanForm);
      const payload = Object.fromEntries(formData.entries());
      disableForm(agentScanForm, true);
      setStatus('Dispatching agent scan…');
      try {
        const res = await fetch('/scan/agent/start/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
          },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        setStatus(`Agent scan queued (scan ${data.scan_id}).`, 'success');
        updateScanHistory();
      } catch (err) {
        setStatus(`Agent scan failed: ${err.message}`, 'danger');
      } finally {
        disableForm(agentScanForm, false);
      }
    });
  }

  if (campaignForm) {
    campaignForm.addEventListener('submit', async e => {
      e.preventDefault();
      const formData = new FormData(campaignForm);
      const openvasEnabled = campaignForm.querySelector('[name="run_openvas"]')?.checked;
      const collectLootEnabled = campaignForm.querySelector('[name="collect_loot"]')?.checked;
      formData.set('run_openvas', openvasEnabled ? '1' : '0');
      formData.set('collect_loot', collectLootEnabled ? '1' : '0');
      disableForm(campaignForm, true);
      setCampaignStatus('Starting OT campaign...', 'info');
      setCampaignLogLines(['Waiting for first campaign update...']);
      try {
        const res = await fetch('/scan/campaign/start/', {
          method: 'POST',
          headers: { 'X-CSRFToken': getCSRFToken() },
          body: formData
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        const taskId = data.task_id;
        if (!taskId) throw new Error('No campaign task id returned');
        const campaignRunId = data.campaign_run_id;
        if (campaignRunId) {
          setCampaignStatus(`Campaign #${campaignRunId} started. Waiting for progress...`, 'info');
          appendCampaignLogLine(`${new Date().toLocaleTimeString()} [queued] Campaign #${campaignRunId} accepted by worker.`);
        }
        updateCampaignLinks();
        updateCampaignHistory();

        pollTask({
          statusUrl: `/scan/campaign/status/${encodeURIComponent(taskId)}/`,
          intervalMs: 4000,
          onTick: s => {
            const campaign = s.campaign || {};
            if (campaign && Object.keys(campaign).length) {
              updateCampaignLinks(campaign);
              if (Array.isArray(campaign.log_lines) && campaign.log_lines.length) {
                setCampaignLogLines(campaign.log_lines);
              }
            }
            if (s.state === 'PROGRESS') {
              const step = s.step ? `[${s.step}] ` : '';
              const openvasProgress = s.step === 'openvas' && s.details && s.details.progress != null
                ? ` ${s.details.progress}%`
                : '';
              const openvasTask = campaign.openvas_task_id ? ` (task ${campaign.openvas_task_id})` : '';
              const progress = (s.steps_completed != null && s.total_steps != null)
                ? ` (${s.steps_completed}/${s.total_steps})`
                : '';
              setCampaignStatus(`${step}${s.message || 'Running...'}${openvasProgress}${openvasTask}${progress}`, 'info');
              if (!Array.isArray(campaign.log_lines) || !campaign.log_lines.length) {
                appendCampaignLogLine(`${new Date().toLocaleTimeString()} ${step}${s.message || 'Running...'}`);
              }
              return;
            }
            setCampaignStatus(`Campaign state: ${s.state}`, 'info');
            if (!Array.isArray(campaign.log_lines) || !campaign.log_lines.length) {
              appendCampaignLogLine(`${new Date().toLocaleTimeString()} [state] ${s.state}`);
            }
          },
          onDone: s => {
            const campaign = s.campaign || {};
            if (campaign && Object.keys(campaign).length) {
              updateCampaignLinks(campaign);
              if (Array.isArray(campaign.log_lines) && campaign.log_lines.length) {
                setCampaignLogLines(campaign.log_lines);
              }
            }
            const result = s.result || {};
            if (s.state === 'SUCCESS') {
              const found = Array.isArray(result.discovered_ips) ? result.discovered_ips.length : 0;
              const vulnCount = result.openvas && typeof result.openvas.vulnerability_count === 'number'
                ? result.openvas.vulnerability_count
                : 0;
              const errCount = Array.isArray(result.errors) ? result.errors.length : 0;
              setCampaignStatus(
                `Campaign complete: hosts=${found}, vulns=${vulnCount}, errors=${errCount}.`,
                errCount ? 'warning' : 'success'
              );
              appendCampaignLogLine(
                `${new Date().toLocaleTimeString()} [complete] hosts=${found}, vulns=${vulnCount}, errors=${errCount}`
              );
            } else {
              const msg = s.message || (result && result.error) || 'Campaign failed.';
              setCampaignStatus(`Campaign failed: ${msg}`, 'danger');
              appendCampaignLogLine(`${new Date().toLocaleTimeString()} [failed] ${msg}`);
            }
            updateScanHistory();
            updateCampaignHistory();
            renderGraph();
            disableForm(campaignForm, false);
          },
          onError: err => {
            setCampaignStatus(`Campaign status error: ${err.message}`, 'danger');
            appendCampaignLogLine(`${new Date().toLocaleTimeString()} [error] ${err.message}`);
            updateCampaignHistory();
            disableForm(campaignForm, false);
          }
        });
      } catch (err) {
        setCampaignStatus(`Could not start campaign: ${err.message}`, 'danger');
        appendCampaignLogLine(`${new Date().toLocaleTimeString()} [error] ${err.message}`);
        disableForm(campaignForm, false);
      }
    });
  }

    // --- PNG export: robust off-screen mirror ---
  function cloneElementsWithPositions(cy) {
    const els = cy.elements().map(ele => {
      const json = ele.json();
      // Cytoscape keeps authoritative positions on live nodes; copy them explicitly
      if (ele.isNode()) {
        const p = ele.position();
        json.position = { x: p.x, y: p.y };
      }
      return json;
    });
    return els;
  }

  function buildHiddenContainer(width = 1600, height = 1200, bg = '#111') {
    const div = document.createElement('div');
    Object.assign(div.style, {
      position: 'fixed',
      left: '-10000px',
      top: '0',
      width: `${width}px`,
      height: `${height}px`,
      visibility: 'hidden',      // renders, unlike display:none
      background: bg,
      zIndex: -1,
    });
    document.body.appendChild(div);
    return div;
  }

  async function exportGraphPNG(cy, {bg = '#111', width = 1600, height = 1200, scale = 2, fit = true} = {}) {
    if (!cy) throw new Error('Graph not ready');

    // 1) Make a mirror container
    const container = buildHiddenContainer(width, height, bg);

    // 2) Create a mirror instance with identical style + element positions
    const mirror = cytoscape({
      container,
      elements: cloneElementsWithPositions(cy),
      style: cy.style().json(),
      wheelSensitivity: cy._private?.wheelSensitivity ?? 1,
      pixelRatio: 1,                 // we control resolution via scale below
      textureOnViewport: false,
      motionBlur: false,
      // Force canvas renderer for widest snapshot compatibility
      renderer: { name: 'canvas' }
    });

    // 3) Match viewport or fit
    if (fit) {
      mirror.fit();
    } else {
      mirror.zoom(cy.zoom());
      mirror.pan(cy.pan());
    }

    // 4) Wait for a real render tick
    await new Promise(res => {
      const done = () => { mirror.off('render', done); res(); };
      mirror.on('render', done);
      mirror.resize(); mirror.emit('render');
    });

    // 5) Snapshot (use data URL → Blob to avoid WebGL preserveDrawingBuffer quirks)
    const dataUrl = mirror.png({ full: true, scale, bg });
    const blob = dataURLtoBlob(dataUrl);

    // 6) Cleanup
    mirror.destroy();
    container.remove();

    return blob;
  }

  function dataURLtoBlob(dataURL) {
    const [meta, data] = dataURL.split(',');
    const mime = (meta.match(/data:([^;]+)/) || [,'image/png'])[1];
    const bin = atob(data);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return new Blob([arr], { type: mime });
  }

  function timestampFilename(prefix='network-graph', ext='png') {
    const pad = n => String(n).padStart(2,'0');
    const d = new Date();
    return `${prefix}_${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}.${ext}`;
  }

  function wireDownloadPngButton() {
    const btn = document.getElementById('btn-download-png');
    if (!btn) return;
    btn.onclick = async () => {
      try {
        if (!cyInstance) { setStatus('Graph not ready.', 'warning'); return; }

        // Guard: exporting from a hidden tab = blank image
        const cyDiv = cyInstance.container();
        if (!cyDiv || cyDiv.clientWidth === 0 || cyDiv.clientHeight === 0 || cyDiv.offsetParent === null) {
          setStatus('Graph must be visible before exporting.', 'warning');
          return;
        }

        setStatus('Rendering PNG…', 'muted');

        // Export via mirror (fit whole graph; tweak width/height/scale as desired)
        const blob = await exportGraphPNG(cyInstance, {
          bg: '#111',         // matches your dark UI
          width: 1800,        // export size in CSS pixels
          height: 1200,
          scale: 2,           // resolution multiplier (2 → 3600x2400)
          fit: true           // true = whole graph; false = current viewport
        });

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = timestampFilename();
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        setStatus('PNG downloaded.', 'success');
      } catch (err) {
        console.error(err);
        setStatus(`PNG export failed: ${err.message}`, 'danger');
      }
    };
  }


  // Init
  renderGraph();
  updateScanHistory();
  updateCampaignHistory();

  const refreshCampaignHistory = document.getElementById('refresh-campaign-history');
  if (refreshCampaignHistory) {
    refreshCampaignHistory.addEventListener('click', () => updateCampaignHistory());
  }
  setInterval(updateCampaignHistory, 10000);

  const refreshTopology = document.getElementById('refresh-topology');
  if (refreshTopology) {
    refreshTopology.addEventListener('click', () => {
      setStatus('Refreshing topology…', 'muted');
      renderGraph();
    });
  }
});

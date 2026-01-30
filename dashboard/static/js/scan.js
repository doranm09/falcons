// static/dashboard/js/scan.js
document.addEventListener('DOMContentLoaded', function () {
  // Elements
  const scanForm     = document.getElementById('scan-form');
  const vulnForm     = document.getElementById('vuln-scan-form');
  const agentScanForm = document.getElementById('agent-scan-form');
  const scanStatus   = document.getElementById('scan-status');
  const nodesBody    = document.getElementById('nodes-body');
  const historyTbody = document.getElementById('scan-history-body');
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
  function disableForm(form, disabled) {
    if (!form) return;
    form.querySelectorAll('input,select,textarea,button').forEach(el => el.disabled = disabled);
  }
  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  }

  // --- History refresh ---
  async function updateScanHistory() {
    try {
      const data = await jsonFetch('/scan/history/');
      if (!historyTbody) return;
      historyTbody.innerHTML = '';
      (data.history || []).forEach(run => {
        const status = (run.status || '').toLowerCase();
        const badge =
          status === 'complete' || status === 'completed' ? 'success' :
          status === 'running' || status === 'in_progress' ? 'info' :
          status === 'failed' ? 'danger' : 'secondary';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(run.timestamp || '')}</td>
          <td>${escapeHtml(run.cidr || '')}</td>
          <td><span class="badge bg-${badge}">${escapeHtml(run.status || '')}</span></td>
          <td>${escapeHtml(run.summary || run.result_summary || '-')}</td>
          <td>
            <div class="btn-group btn-group-sm">
              <button class="btn btn-outline-primary" disabled>Report</button>
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
        if (!selectedNode) { selectedNode = tapped; tapped.style('background-color','#ffc107'); }
        else {
          const src = selectedNode.id(), dst = tapped.id();
          jsonFetch(`/shortest-paths/${encodeURIComponent(src)}/`).then(pd=>{
            const cost = pd[dst]; if (pathResult) pathResult.innerText = `Shortest path from ${selectedNode.data('label')} to ${tapped.data('label')}: ${cost}`;
          }).catch(err=>{ if (pathResult) pathResult.innerText = `Path error: ${err.message}`; });
          selectedNode.style('background-color','#007bff'); selectedNode = null;
        }
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
  function pollTask({ statusUrl, onTick, onDone, onError, intervalMs=2000 }) {
    let stopped=false;
    async function tick(){
      if(stopped) return;
      try{
        const data=await jsonFetch(statusUrl); onTick && onTick(data);
        if(['SUCCESS','FAILURE','REVOKED'].includes(data.state)){ stopped=true; onDone && onDone(data); return; }
      }catch(err){ stopped=true; onError && onError(err); return; }
      setTimeout(tick, intervalMs);
    }
    tick(); return ()=>{stopped=true;};
  }

  // --- Scan form ---
  if (scanForm) {
    scanForm.addEventListener('submit', async e=>{
      e.preventDefault(); disableForm(scanForm,true); setStatus('Starting discovery scan…');
      try {
        const formData=new FormData(scanForm);
        const res=await fetch('/scan/start/',{method:'POST',headers:{'X-CSRFToken':getCSRFToken()},body:formData});
        const data=await res.json(); const taskId=data.task_id; if(!taskId) throw new Error('No task id');
        pollTask({
          statusUrl:`/scan/status/${encodeURIComponent(taskId)}/`,
          onTick:s=>setStatus(`Scanning… (${s.state})`),
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
      e.preventDefault(); disableForm(vulnForm,true);
      try {
        const formData=new FormData(vulnForm);
        const res=await fetch('/scan/vuln/start/',{method:'POST',headers:{'X-CSRFToken':getCSRFToken()},body:formData});
        const {task_id}=await res.json(); if(!task_id) throw new Error('No task id');
        setStatus(`OpenVAS scan launched (task ${task_id}).`,'warning');
        pollTask({
          statusUrl:`/scan/vuln/status/${encodeURIComponent(task_id)}/`,
          onTick:s=>setStatus(`OpenVAS scanning… (${s.state})`,'warning'),
          onDone:s=>{ setStatus(`OpenVAS done: ${s.state}`,'success'); updateScanHistory(); disableForm(vulnForm,false); },
          onError:err=>{ setStatus(`OpenVAS status failed (${err.message})`,'muted'); disableForm(vulnForm,false); }
        });
      } catch(err){ setStatus(`Could not start OpenVAS: ${err.message}`,'danger'); disableForm(vulnForm,false); }
    });
  }

  if (agentScanForm) {
    agentScanForm.addEventListener('submit', async e => {
      e.preventDefault();
      disableForm(agentScanForm, true);
      setStatus('Dispatching agent scan…');
      try {
        const formData = new FormData(agentScanForm);
        const payload = Object.fromEntries(formData.entries());
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

  const refreshTopology = document.getElementById('refresh-topology');
  if (refreshTopology) {
    refreshTopology.addEventListener('click', () => {
      setStatus('Refreshing topology…', 'muted');
      renderGraph();
    });
  }
});

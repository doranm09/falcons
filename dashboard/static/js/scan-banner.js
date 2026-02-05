document.addEventListener('DOMContentLoaded', () => {
  const banner = document.getElementById('scan-banner');
  const bannerText = document.getElementById('scan-banner-text');
  const progressEl = document.getElementById('scan-banner-progress');
  const progressBar = progressEl ? progressEl.querySelector('.scan-progress__bar') : null;
  const percentEl = document.getElementById('scan-banner-percent');

  if (!banner || !bannerText || !progressEl || !progressBar || !percentEl) return;

  const runningStates = new Set(['running', 'in_progress', 'pending', 'started']);

  async function getJson(url) {
    const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    if (!res.ok) {
      const msg = (data && (data.detail || data.error || data.message)) || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  function showBanner() {
    banner.classList.remove('hidden');
  }

  function hideBanner() {
    banner.classList.add('hidden');
  }

  function setIndeterminate() {
    progressEl.classList.add('indeterminate');
    progressBar.style.width = '35%';
    percentEl.textContent = '';
  }

  function setPercent(value) {
    const clamped = Math.max(0, Math.min(100, Number(value)));
    progressEl.classList.remove('indeterminate');
    progressBar.style.width = `${clamped}%`;
    percentEl.textContent = `${clamped}%`;
  }

  async function updateOpenvasProgress(scanId) {
    try {
      const status = await getJson(`/scan/vuln/status/${encodeURIComponent(scanId)}/`);
      const raw = status && status.progress != null ? String(status.progress).trim() : '';
      const pct = raw.endsWith('%') ? parseInt(raw.slice(0, -1), 10) : parseInt(raw, 10);
      if (Number.isFinite(pct)) {
        setPercent(pct);
      } else {
        setIndeterminate();
      }
    } catch {
      setIndeterminate();
    }
  }

  function parseTimestamp(ts) {
    if (!ts) return null;
    const iso = ts.includes('T') ? ts : ts.replace(' ', 'T');
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  function hostCountFromCidr(cidr) {
    if (!cidr || !cidr.includes('/')) return null;
    const [ip, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);
    if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
    if (!ip || ip.split('.').length !== 4) return null;
    const total = Math.pow(2, 32 - prefix);
    return prefix >= 31 ? total : Math.max(1, total - 2);
  }

  function estimatePercent({ scanType, cidr, startedAt }) {
    const now = Date.now();
    const startMs = startedAt ? startedAt.getTime() : null;
    if (!startMs) return null;
    const elapsedSec = Math.max(1, (now - startMs) / 1000);
    const hosts = hostCountFromCidr(cidr);
    let perHostSec = 0.1;
    if (scanType === 'ping') perHostSec = 1.0;
    if (scanType === 'agent') perHostSec = 0.25;
    const estimatedTotal = hosts ? Math.max(8, Math.min(7200, hosts * perHostSec)) : 120;
    const rawPct = Math.min(99, Math.floor((elapsedSec / estimatedTotal) * 100));
    return Math.max(1, rawPct);
  }

  async function updateTaskProgress(taskId, scanInfo) {
    try {
      const status = await getJson(`/scan/status/${encodeURIComponent(taskId)}/`);
      const progress = status && status.progress;
      if (progress && typeof progress === 'object' && progress.percent != null) {
        setPercent(progress.percent);
        return;
      }
      if (typeof progress === 'string') {
        setIndeterminate();
        return;
      }
      if (status && status.state && String(status.state).toUpperCase() === 'SUCCESS') {
        setPercent(100);
        return;
      }

      const est = estimatePercent(scanInfo);
      if (est != null) {
        setPercent(est);
        if (bannerText && !bannerText.textContent.includes('est.')) {
          bannerText.textContent += ' (est.)';
        }
        return;
      }

      setIndeterminate();
    } catch {
      const est = estimatePercent(scanInfo);
      if (est != null) {
        setPercent(est);
        if (bannerText && !bannerText.textContent.includes('est.')) {
          bannerText.textContent += ' (est.)';
        }
        return;
      }
      setIndeterminate();
    }
  }

  async function poll() {
    try {
      const data = await getJson('/scan/history/');
      const history = Array.isArray(data.history) ? data.history : [];
      const running = history.find(run => runningStates.has(String(run.status || '').toLowerCase()));

      if (!running) {
        hideBanner();
        return;
      }

      showBanner();
      const scanType = (running.scan_type || 'scan').toUpperCase();
      const cidr = running.cidr || 'network';
      const status = String(running.status || '').toUpperCase();
      bannerText.textContent = `${scanType} scan running on ${cidr} (${status})`;

      const scanType = String(running.scan_type || '').toLowerCase();
      if (scanType === 'openvas') {
        await updateOpenvasProgress(running.id);
      } else if (running.task_id) {
        const startedAt = parseTimestamp(running.timestamp);
        await updateTaskProgress(running.task_id, {
          scanType,
          cidr: running.cidr,
          startedAt,
        });
      } else {
        setIndeterminate();
      }
    } catch {
      hideBanner();
    }
  }

  poll();
  setInterval(poll, 5000);
});

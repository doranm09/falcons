(function () {
  const root = document.getElementById('siem-ids-live');
  if (!root) return;

  const updatesUrl = root.dataset.updatesUrl;
  const liveKind = root.dataset.liveKind || '';
  let afterId = Number(root.dataset.afterId || '0');
  let pollTimer = null;

  const tbody = document.querySelector('#ids-live-table tbody');
  const latestEventEl = document.getElementById('ids-latest-event');
  const stateBadge = document.getElementById('ids-connection-state');
  const clearButton = document.getElementById('ids-clear-table');
  const modalEl = document.getElementById('ids-raw-modal');
  const modalContent = document.getElementById('ids-raw-content');
  const modal = modalEl ? new bootstrap.Modal(modalEl) : null;
  const rawCache = new Map();

  function isProcessLive() {
    return liveKind === 'process';
  }

  function formatTimestamp(value) {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return value || '-';
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  }

  function renderLatest(ts, eventType) {
    if (!ts && !eventType) {
      latestEventEl.textContent = 'Waiting for IDS events...';
      return;
    }
    latestEventEl.textContent = `${formatTimestamp(ts)} | ${eventType || '-'}`;
  }

  function formatScore(value) {
    if (value === null || value === undefined || value === '') return '-';
    const num = Number(value);
    if (Number.isFinite(num)) return num.toFixed(2);
    return String(value);
  }

  function localizeInitialTimestamps() {
    document.querySelectorAll('[data-ids-ts]').forEach((el) => {
      const value = el.dataset.idsTs;
      if (!value) return;
      el.textContent = formatTimestamp(value);
    });

    renderLatest(
      latestEventEl.dataset.ts || '',
      latestEventEl.dataset.eventType || ''
    );
  }

  function typeBadge(eventType) {
    if (isAnomalyType(eventType)) return `<span class="badge bg-danger">${eventType || 'ids.anomaly'}</span>`;
    return `<span class="badge bg-secondary">${eventType || '-'}</span>`;
  }

  function isAnomalyType(eventType) {
    return typeof eventType === 'string' && eventType.endsWith('.anomaly');
  }

  function emptyColspan() {
    return isProcessLive() ? '5' : '8';
  }

  function defaultSource() {
    if (liveKind === 'network') return 'ids-network';
    if (liveKind === 'process') return 'ids-process';
    return 'ids-live';
  }

  function cleanText(value) {
    const text = String(value ?? '').trim();
    return text || '-';
  }

  function payloadFromRow(row, rawPayload) {
    const cells = row.querySelectorAll('td');
    const source = row.dataset.source || defaultSource();
    const base = {
      id: row.dataset.eventId || null,
      source,
      event_type: row.dataset.eventType || '-',
      timestamp: cleanText(cells[0]?.textContent),
      raw: rawPayload,
    };

    if (isProcessLive()) {
      base.score = cleanText(cells[2]?.textContent);
      base.decision_threshold = cleanText(cells[3]?.textContent);
      return base;
    }

    base.src_ip = cleanText(cells[2]?.textContent);
    base.dst_ip = cleanText(cells[3]?.textContent);
    base.protocol = cleanText(cells[4]?.textContent);
    base.score = cleanText(cells[5]?.textContent);
    base.decision_threshold = cleanText(cells[6]?.textContent);
    return base;
  }

  function showRaw(payload) {
    if (!modalContent) return;
    modalContent.textContent = JSON.stringify(payload || {}, null, 2);
    modal?.show();
  }

  function parseRawText(rawText) {
    if (!rawText) return {};
    try {
      return JSON.parse(rawText);
    } catch (_err) {
      return {};
    }
  }

  function primeRawCacheFromRows() {
    tbody.querySelectorAll('tr[data-event-id]').forEach((row) => {
      const eventId = row.dataset.eventId;
      const raw = row.dataset.raw;
      if (!eventId) return;
      const payload = parseRawText(raw);
      rawCache.set(String(eventId), payloadFromRow(row, payload));
    });
  }

  function prependRow(event) {
    const emptyRow = tbody.querySelector(`td[colspan="${emptyColspan()}"]`);
    if (emptyRow) {
      emptyRow.closest('tr')?.remove();
    }

    const eventId = String(event.id || '');
    const source = event.source || defaultSource();
    const raw = event.raw && typeof event.raw === 'object' ? event.raw : {};
    rawCache.set(eventId, {
      id: event.id ?? null,
      source,
      event_type: event.event_type || '-',
      timestamp: event.timestamp || '-',
      src_ip: isProcessLive() ? undefined : (event.src_ip || '-'),
      dst_ip: isProcessLive() ? undefined : (event.dst_ip || '-'),
      protocol: isProcessLive() ? undefined : (event.protocol || '-'),
      score: event.score ?? '-',
      decision_threshold: event.decision_threshold ?? '-',
      raw,
    });

    const row = document.createElement('tr');
    row.dataset.eventId = eventId;
    row.dataset.eventType = event.event_type || '';
    row.dataset.source = source;
    row.dataset.raw = JSON.stringify(raw);

    row.innerHTML = `
      <td>${formatTimestamp(event.timestamp)}</td>
      <td>${typeBadge(event.event_type)}</td>
      ${isProcessLive() ? '' : `<td><code class="small">${event.src_ip || '-'}</code></td><td><code class="small">${event.dst_ip || '-'}</code></td><td>${event.protocol || '-'}</td>`}
      <td>${formatScore(event.score)}</td>
      <td>${event.decision_threshold ?? '-'}</td>
      <td><button class="btn btn-sm btn-outline-primary" data-action="view-raw" data-event-id="${event.id || ''}">View</button></td>
    `;

    tbody.prepend(row);

    // Keep UI bounded.
    while (tbody.children.length > 300) {
      tbody.lastElementChild?.remove();
    }
  }

  function setState(label, level) {
    stateBadge.textContent = label;
    stateBadge.classList.remove('bg-secondary-subtle', 'text-secondary', 'bg-success-subtle', 'text-success', 'bg-danger-subtle', 'text-danger');
    if (level === 'ok') {
      stateBadge.classList.add('bg-success-subtle', 'text-success');
      return;
    }
    if (level === 'error') {
      stateBadge.classList.add('bg-danger-subtle', 'text-danger');
      return;
    }
    stateBadge.classList.add('bg-secondary-subtle', 'text-secondary');
  }

  async function poll() {
    try {
      const res = await fetch(`${updatesUrl}?after_id=${encodeURIComponent(String(afterId))}`, {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }

      const payload = await res.json();
      const events = Array.isArray(payload.events) ? payload.events : [];

      setState('live', 'ok');
      for (const event of events) {
        if (!event || typeof event !== 'object') continue;
        if (event.id && event.id > afterId) {
          afterId = event.id;
        }

        renderLatest(event.timestamp, event.event_type || '-');
        prependRow(event);
      }
    } catch (_err) {
      setState('reconnecting', 'error');
    }
  }

  clearButton.addEventListener('click', () => {
    tbody.innerHTML = `<tr><td colspan="${emptyColspan()}" class="text-muted text-center">Live table cleared. Waiting for new IDS events...</td></tr>`;
  });

  tbody.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.dataset.action !== 'view-raw') return;
    const eventId = target.dataset.eventId;
    if (!eventId) return;

    let payload = rawCache.get(String(eventId));
    if (!payload) {
      const row = target.closest('tr');
      if (!row) return;
      payload = payloadFromRow(row, parseRawText(row.dataset.raw));
      rawCache.set(String(eventId), payload);
    }
    showRaw(payload);
  });

  // Browsers may restore this page from back-forward cache without rerunning
  // script initialization; re-prime cached payloads on restore.
  window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return;
    primeRawCacheFromRows();
  });

  localizeInitialTimestamps();
  primeRawCacheFromRows();
  setState('connecting', 'idle');
  poll();
  pollTimer = window.setInterval(poll, 1000);

  window.addEventListener('beforeunload', () => {
    if (pollTimer) {
      window.clearInterval(pollTimer);
    }
  });
})();

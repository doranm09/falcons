(function () {
  const explorer = document.getElementById('siem-explorer');
  if (!explorer) return;

  const searchUrl = explorer.dataset.searchUrl;
  const form = document.getElementById('siem-search-form');
  const defaultStart = explorer.dataset.defaultStart || '';
  const defaultEnd = explorer.dataset.defaultEnd || '';
  const statusEl = document.getElementById('siem-status');
  const resultsCountBadge = document.querySelector('[data-testid="siem-results-count"]');
  const tbody = document.querySelector('[data-testid="siem-events-body"]');
  const modalEl = document.getElementById('siem-raw-modal');
  const modalContent = document.getElementById('siem-raw-content');
  const quickRangeButtons = explorer.querySelectorAll('[data-range]');
  const resetButton = document.getElementById('siem-reset');

  const rawCache = new Map();
  const modal = modalEl ? new bootstrap.Modal(modalEl) : null;

  const inputs = {
    start: document.getElementById('siem-start'),
    end: document.getElementById('siem-end'),
    eventType: document.getElementById('siem-event-type'),
    source: document.getElementById('siem-source'),
    assetIp: document.getElementById('siem-asset-ip'),
    assetId: document.getElementById('siem-asset-id'),
    severity: document.getElementById('siem-severity'),
    query: document.getElementById('siem-query'),
    limit: document.getElementById('siem-limit'),
  };

  function formatSeverityBadge(severity) {
    if (severity === null || severity === undefined || severity === '') {
      return '<span class="text-muted">-</span>';
    }
    const value = Number(severity);
    if (Number.isNaN(value)) return '<span class="text-muted">-</span>';
    if (value >= 7) return `<span class="badge bg-danger">${value}</span>`;
    if (value >= 4) return `<span class="badge bg-warning text-dark">${value}</span>`;
    return `<span class="badge bg-success">${value}</span>`;
  }

  function formatDateTime(value) {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    const pad = (n) => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  }

  function buildParams() {
    const params = new URLSearchParams();
    if (inputs.start.value) params.set('start', new Date(inputs.start.value).toISOString());
    if (inputs.end.value) params.set('end', new Date(inputs.end.value).toISOString());
    if (inputs.eventType.value) params.set('event_type', inputs.eventType.value.trim());
    if (inputs.source.value) params.set('source', inputs.source.value.trim());
    if (inputs.assetIp.value) params.set('asset_ip', inputs.assetIp.value.trim());
    if (inputs.assetId.value) params.set('asset_id', inputs.assetId.value.trim());
    if (inputs.severity.value) params.set('severity', inputs.severity.value.trim());
    if (inputs.query.value) params.set('q', inputs.query.value.trim());
    if (inputs.limit.value) params.set('limit', inputs.limit.value.trim());
    return params;
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.classList.toggle('text-danger', Boolean(isError));
  }

  function renderRows(events) {
    tbody.innerHTML = '';
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center">No events match this search.</td></tr>';
      return;
    }

    events.forEach((event, idx) => {
      const eventId = event.id ?? `tmp-${idx}`;
      rawCache.set(eventId, event.raw || {});

      const row = document.createElement('tr');
      row.dataset.eventId = eventId;
      row.innerHTML = `
        <td>${formatDateTime(event.timestamp)}</td>
        <td><span class="badge bg-light text-dark border">${event.source || '-'}</span></td>
        <td>${event.event_type || '-'}</td>
        <td>${formatSeverityBadge(event.severity)}</td>
        <td>${event.asset_ip || '-'}</td>
        <td>${event.asset_id || '-'}</td>
        <td>${event.summary || '-'}</td>
        <td><button class="btn btn-sm btn-outline-primary" data-action="view-raw" data-event-id="${eventId}">View</button></td>
      `;
      tbody.appendChild(row);
    });
  }

  async function runSearch() {
    setStatus('Searching…');
    const params = buildParams();
    const url = `${searchUrl}?${params.toString()}`;

    try {
      const resp = await fetch(url, { headers: { 'Accept': 'application/json' } });
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${resp.status})`);
      }
      const data = await resp.json();
      renderRows(data.results || []);
      if (resultsCountBadge) {
        resultsCountBadge.textContent = `${data.count || 0} results`;
      }
      setStatus(`Loaded ${data.results?.length || 0} events.`);
    } catch (err) {
      setStatus(err.message || 'Search failed', true);
    }
  }

  function showRawFromCache(eventId) {
    const payload = rawCache.get(eventId);
    modalContent.textContent = JSON.stringify(payload || {}, null, 2);
    modal?.show();
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    runSearch();
  });

  resetButton.addEventListener('click', () => {
    Object.values(inputs).forEach((input) => {
      if (!input) return;
      if (input.id === 'siem-limit') {
        input.value = '100';
        return;
      }
      if (input.id === 'siem-start') {
        input.value = defaultStart;
        return;
      }
      if (input.id === 'siem-end') {
        input.value = defaultEnd;
        return;
      }
      input.value = '';
    });
    setStatus('Filters cleared. Showing most recent events.');
    runSearch();
  });

  quickRangeButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const minutes = Number(button.dataset.range || '0');
      if (!minutes) return;
      const end = new Date();
      const start = new Date(end.getTime() - minutes * 60 * 1000);
      inputs.end.value = end.toISOString().slice(0, 16);
      inputs.start.value = start.toISOString().slice(0, 16);
      runSearch();
    });
  });

  tbody.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const action = target.dataset.action;
    if (action !== 'view-raw') return;
    const rawData = target.dataset.raw;
    const eventId = target.dataset.eventId;
    if (rawData) {
      try {
        const parsed = JSON.parse(rawData);
        modalContent.textContent = JSON.stringify(parsed, null, 2);
        modal?.show();
      } catch (err) {
        modalContent.textContent = 'Failed to parse raw payload.';
        modal?.show();
      }
    } else if (eventId) {
      showRawFromCache(eventId);
    }
  });
})();

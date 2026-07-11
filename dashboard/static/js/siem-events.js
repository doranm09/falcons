(function () {
  const explorer = document.getElementById('siem-explorer');
  if (!explorer) return;

  const searchUrl = explorer.dataset.searchUrl;
  const form = document.getElementById('siem-search-form');
  const defaultSource = explorer.dataset.defaultSource || 'ids-network';
  const defaultEventType = explorer.dataset.defaultEventType || 'ids-network.anomaly';
  const statusEl = document.getElementById('siem-status');
  const resultsCountBadge = document.querySelector('[data-testid="siem-results-count"]');
  const tbody = document.querySelector('[data-testid="siem-events-body"]');
  const modalEl = document.getElementById('siem-raw-modal');
  const modalContent = document.getElementById('siem-raw-content');
  const quickRangeButtons = explorer.querySelectorAll('[data-range]');
  const resetButton = document.getElementById('siem-reset');
  const timelineBars = document.getElementById('siem-timeline-bars');
  const timelineLabel = document.getElementById('siem-timeline-label');

  const rawCache = new Map();
  const modal = modalEl ? new bootstrap.Modal(modalEl) : null;

  const inputs = {
    start: document.getElementById('siem-start'),
    end: document.getElementById('siem-end'),
    eventType: document.getElementById('siem-event-type'),
    source: document.getElementById('siem-source'),
    query: document.getElementById('siem-query'),
    limit: document.getElementById('siem-limit'),
  };

  function toDatetimeLocalValue(date) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  const defaultEndDate = new Date();
  const defaultStartDate = new Date(defaultEndDate.getTime() - 24 * 60 * 60 * 1000);
  const defaultStart = toDatetimeLocalValue(defaultStartDate);
  const defaultEnd = toDatetimeLocalValue(defaultEndDate);

  function localizeInitialTimestamps() {
    document.querySelectorAll('[data-siem-ts]').forEach((el) => {
      const value = el.getAttribute('data-siem-ts');
      if (!value) return;
      el.textContent = formatDateTime(value);
    });
  }

  function setParamIfPresent(params, key, input) {
    if (!input || !input.value) return;
    params.set(key, input.value.trim());
  }

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
    if (inputs.start?.value) params.set('start', new Date(inputs.start.value).toISOString());
    if (inputs.end?.value) params.set('end', new Date(inputs.end.value).toISOString());
    setParamIfPresent(params, 'event_type', inputs.eventType);
    setParamIfPresent(params, 'source', inputs.source);
    setParamIfPresent(params, 'q', inputs.query);
    setParamIfPresent(params, 'limit', inputs.limit);
    return params;
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.classList.toggle('text-danger', Boolean(isError));
  }

  function getSearchRange() {
    const end = inputs.end.value ? new Date(inputs.end.value) : new Date();
    const start = inputs.start.value ? new Date(inputs.start.value) : new Date(end.getTime() - 24 * 60 * 60 * 1000);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
      return { start: new Date(Date.now() - 24 * 60 * 60 * 1000), end: new Date() };
    }
    if (end < start) return { start: end, end: start };
    return { start, end };
  }

  function renderTimeline(events) {
    if (!timelineBars) return;
    const range = getSearchRange();
    const bins = 24;
    const spanMs = range.end.getTime() - range.start.getTime();
    const binMs = spanMs / bins;
    const buckets = Array.from({ length: bins }, () => ({ count: 0, maxSeverity: 0 }));

    events.forEach((event) => {
      const ts = new Date(event.timestamp || '');
      if (Number.isNaN(ts.getTime())) return;
      const idx = Math.min(bins - 1, Math.max(0, Math.floor((ts.getTime() - range.start.getTime()) / binMs)));
      if (!buckets[idx]) return;
      buckets[idx].count += 1;
      const sev = Number(event.severity || 0);
      if (!Number.isNaN(sev)) {
        buckets[idx].maxSeverity = Math.max(buckets[idx].maxSeverity, sev);
      }
    });

    const maxCount = Math.max(...buckets.map((b) => b.count));
    if (!maxCount) {
      timelineBars.innerHTML = '<div class="siem-timeline__empty">No events in selected range.</div>';
      if (timelineLabel) timelineLabel.textContent = 'No data';
      return;
    }

    timelineBars.innerHTML = '';
    buckets.forEach((bucket) => {
      const bar = document.createElement('div');
      const height = Math.max(6, Math.round((bucket.count / maxCount) * 80));
      bar.className = 'siem-timeline__bar';
      if (bucket.maxSeverity >= 7) bar.classList.add('siem-timeline__bar--high');
      else if (bucket.maxSeverity >= 4) bar.classList.add('siem-timeline__bar--mid');
      else if (bucket.maxSeverity > 0) bar.classList.add('siem-timeline__bar--low');
      bar.style.height = `${height}px`;
      bar.title = `${bucket.count} events`;
      timelineBars.appendChild(bar);
    });

    if (timelineLabel) {
      timelineLabel.textContent = `${range.start.toLocaleString()} → ${range.end.toLocaleString()}`;
    }
  }

  function renderRows(events) {
    tbody.innerHTML = '';
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-muted text-center">No events match this search.</td></tr>';
      return;
    }

    events.forEach((event, idx) => {
      const eventId = String(event.id ?? `tmp-${idx}`);
      rawCache.set(eventId, event.raw || {});

      const row = document.createElement('tr');
      row.dataset.eventId = eventId;
      row.innerHTML = `
        <td>${formatDateTime(event.timestamp)}</td>
        <td><span class="badge bg-light text-dark border">${event.source || '-'}</span></td>
        <td>${event.event_type || '-'}</td>
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
      renderTimeline(data.results || []);
      if (resultsCountBadge) {
        resultsCountBadge.textContent = `${data.count || 0} results`;
      }
      setStatus(`Loaded ${data.results?.length || 0} events.`);
    } catch (err) {
      setStatus(err.message || 'Search failed', true);
    }
  }

  function showRawFromCache(eventId) {
    const payload = rawCache.get(String(eventId));
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
      if (input.id === 'siem-source') {
        input.value = defaultSource;
        return;
      }
      if (input.id === 'siem-event-type') {
        input.value = defaultEventType;
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
      inputs.end.value = toDatetimeLocalValue(end);
      inputs.start.value = toDatetimeLocalValue(start);
      runSearch();
    });
  });

  tbody.addEventListener('click', async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const action = target.dataset.action;
    const row = target.closest('tr');
    if (!row) return;
    if (action === 'view-raw') {
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
      return;
    }

  });

  if (inputs.start && !inputs.start.value) {
    inputs.start.value = defaultStart;
  }
  if (inputs.end && !inputs.end.value) {
    inputs.end.value = defaultEnd;
  }
  localizeInitialTimestamps();

  if (timelineBars) {
    runSearch();
  }
})();

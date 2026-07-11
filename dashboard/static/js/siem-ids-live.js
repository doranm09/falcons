(function () {
  const root = document.getElementById('siem-ids-live');
  if (!root) return;

  const updatesUrl = root.dataset.updatesUrl;
  let afterId = Number(root.dataset.afterId || '0');
  let pollTimer = null;

  const tbody = document.querySelector('#ids-live-table tbody');
  const latestEventEl = document.getElementById('ids-latest-event');
  const stateBadge = document.getElementById('ids-connection-state');
  const anomalyOnlyToggle = document.getElementById('ids-anomaly-only');
  const clearButton = document.getElementById('ids-clear-table');

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
    if (eventType === 'ids.anomaly') return '<span class="badge bg-danger">ids.anomaly</span>';
    return `<span class="badge bg-secondary">${eventType || '-'}</span>`;
  }

  function shouldRender(event) {
    if (!anomalyOnlyToggle.checked) return true;
    return event.event_type === 'ids.anomaly';
  }

  function prependRow(event) {
    const emptyRow = tbody.querySelector('td[colspan="7"]');
    if (emptyRow) {
      emptyRow.closest('tr')?.remove();
    }

    const row = document.createElement('tr');
    row.dataset.eventId = String(event.id || '');
    row.dataset.eventType = event.event_type || '';

    row.innerHTML = `
      <td>${formatTimestamp(event.timestamp)}</td>
      <td>${typeBadge(event.event_type)}</td>
      <td><code class="small">${event.src_ip || '-'}</code></td>
      <td><code class="small">${event.dst_ip || '-'}</code></td>
      <td>${event.protocol || '-'}</td>
      <td>${formatScore(event.score)}</td>
      <td>${event.decision_threshold ?? '-'}</td>
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
        if (shouldRender(event)) {
          prependRow(event);
        }
      }
    } catch (_err) {
      setState('reconnecting', 'error');
    }
  }

  anomalyOnlyToggle.addEventListener('change', () => {
    Array.from(tbody.querySelectorAll('tr')).forEach((row) => {
      const eventType = row.dataset.eventType || '';
      if (anomalyOnlyToggle.checked && eventType && eventType !== 'ids.anomaly') {
        row.classList.add('d-none');
      } else {
        row.classList.remove('d-none');
      }
    });
  });

  clearButton.addEventListener('click', () => {
    tbody.innerHTML = '<tr><td colspan="7" class="text-muted text-center">Live table cleared. Waiting for new IDS events...</td></tr>';
  });

  localizeInitialTimestamps();
  setState('connecting', 'idle');
  poll();
  pollTimer = window.setInterval(poll, 1000);

  window.addEventListener('beforeunload', () => {
    if (pollTimer) {
      window.clearInterval(pollTimer);
    }
  });
})();

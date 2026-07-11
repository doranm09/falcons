(function () {
  const root = document.getElementById('siem-ids-live');
  if (!root) return;

  const updatesUrl = root.dataset.updatesUrl;
  const liveKind = root.dataset.liveKind || '';
  const processTelemetryUrl = root.dataset.processTelemetryUrl || '';
  let afterId = Number(root.dataset.afterId || '0');
  let pollTimer = null;
  let processTelemetryTimer = null;

  const tbody = document.querySelector('#ids-live-table tbody');
  const latestEventEl = document.getElementById('ids-latest-event');
  const stateBadge = document.getElementById('ids-connection-state');
  const clearButton = document.getElementById('ids-clear-table');
  const modalEl = document.getElementById('ids-raw-modal');
  const modalContent = document.getElementById('ids-raw-content');
  const modal = modalEl ? new bootstrap.Modal(modalEl) : null;
  const rawCache = new Map();
  const PROCESS_TELEMETRY_FETCH_TIMEOUT_MS = 1500;
  const PROCESS_PROFILE_META = {
    main: { label: 'Main PLC', color: '#0d6efd' },
    backup: { label: 'Backup PLC', color: '#fd7e14' },
  };
  const PROCESS_SCORE_COLOR = '#2563eb';
  const processCards = new Map();
  const processProfileState = new Map();
  const processScoreCardEl = document.querySelector('[data-process-score-card]');
  const processScoreCard = processScoreCardEl ? {
    chart: processScoreCardEl.querySelector('[data-process-score-role="chart"]'),
    legend: processScoreCardEl.querySelector('[data-process-score-role="legend"]'),
    status: processScoreCardEl.querySelector('[data-process-score-role="status"]'),
    meta: processScoreCardEl.querySelector('[data-process-score-role="meta"]'),
  } : null;

  document.querySelectorAll('[data-process-profile-card]').forEach((card) => {
    const profile = String(card.dataset.processProfile || '').trim();
    if (!profile) return;
    processCards.set(profile, {
      chart: card.querySelector('[data-process-role="chart"]'),
      legend: card.querySelector('[data-process-role="legend"]'),
      status: card.querySelector('[data-process-role="status"]'),
      meta: card.querySelector('[data-process-role="meta"]'),
    });
  });

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
    if (!latestEventEl) return;
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

  function formatPressure(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) return '-';
    return num.toLocaleString();
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function hasProcessTelemetryChart() {
    return isProcessLive() && !!processTelemetryUrl && processCards.size > 0;
  }

  function normalizeFiniteNumber(value) {
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }

  function pickNestedValue(payload, ...keys) {
    let cursor = payload;
    while (cursor && typeof cursor === 'object') {
      for (const key of keys) {
        const value = cursor[key];
        if (value !== null && value !== undefined && value !== '') {
          return value;
        }
      }
      cursor = cursor.raw && typeof cursor.raw === 'object' ? cursor.raw : null;
    }
    return null;
  }

  function processMetaFor(profile) {
    return PROCESS_PROFILE_META[profile] || {
      label: profile || 'Process',
      color: '#0d6efd',
    };
  }

  function getProcessCard(profile) {
    return processCards.get(profile) || null;
  }

  function getProcessState(profile) {
    const key = String(profile || 'main');
    if (!processProfileState.has(key)) {
      const meta = processMetaFor(key);
      processProfileState.set(key, {
        key,
        label: meta.label,
        color: meta.color,
        connected: null,
        endpoint: '',
        historianStatus: '',
        pressureValue: null,
        pressureUpdatedAt: '',
        pressurePoints: [],
        scoreValue: null,
        scoreUpdatedAt: '',
        scorePoints: [],
        thresholdValue: null,
        thresholdUpdatedAt: '',
        lastEventType: '',
      });
    }
    return processProfileState.get(key);
  }

  function upsertSeriesPoint(points, nextPoint) {
    const existing = Array.isArray(points) ? [...points] : [];
    const lastPoint = existing[existing.length - 1];
    if (lastPoint && lastPoint.tsMs === nextPoint.tsMs) {
      existing[existing.length - 1] = nextPoint;
    } else {
      existing.push(nextPoint);
    }
    existing.sort((left, right) => left.tsMs - right.tsMs);
    while (existing.length > 90) {
      existing.shift();
    }
    return existing;
  }

  function extractProcessProfile(payload) {
    const rawProfile = pickNestedValue(payload, 'profile');
    const profile = String(rawProfile || '').trim().toLowerCase();
    if (profile) return profile;
    return 'main';
  }

  function setProcessTelemetryStatus(profile, message, level = 'muted') {
    const card = getProcessCard(profile);
    if (!card?.status) return;
    card.status.textContent = message;
    card.status.classList.remove('text-muted', 'text-danger', 'text-success');
    if (level === 'error') {
      card.status.classList.add('text-danger');
      return;
    }
    if (level === 'ok') {
      card.status.classList.add('text-success');
      return;
    }
    card.status.classList.add('text-muted');
  }

  function setProcessTelemetryMeta(profile, message) {
    const card = getProcessCard(profile);
    if (!card?.meta) return;
    card.meta.textContent = message;
  }

  function setProcessScoreStatus(message, level = 'muted') {
    if (!processScoreCard?.status) return;
    processScoreCard.status.textContent = message;
    processScoreCard.status.classList.remove('text-muted', 'text-danger', 'text-success');
    if (level === 'error') {
      processScoreCard.status.classList.add('text-danger');
      return;
    }
    if (level === 'ok') {
      processScoreCard.status.classList.add('text-success');
      return;
    }
    processScoreCard.status.classList.add('text-muted');
  }

  function setProcessScoreMeta(message) {
    if (!processScoreCard?.meta) return;
    processScoreCard.meta.textContent = message;
  }

  function rememberProcessTelemetrySample(seriesEntry, sampleTime, historianStatus) {
    if (!seriesEntry || typeof seriesEntry !== 'object') return;
    const profile = String(seriesEntry.key || seriesEntry.label || 'main');
    const state = getProcessState(profile);
    const meta = processMetaFor(profile);
    const parsedTime = new Date(sampleTime || seriesEntry.updated_at || Date.now());
    const tsMs = Number.isNaN(parsedTime.getTime()) ? Date.now() : parsedTime.getTime();
    const value = normalizeFiniteNumber(seriesEntry.value);

    state.label = seriesEntry.label || meta.label;
    state.color = seriesEntry.color || meta.color;
    state.connected = !!seriesEntry.connected;
    state.endpoint = seriesEntry.endpoint || state.endpoint;
    state.historianStatus = historianStatus || state.historianStatus;
    state.pressureUpdatedAt = seriesEntry.updated_at || state.pressureUpdatedAt || new Date(tsMs).toISOString();
    if (value !== null) {
      state.pressureValue = value;
      state.pressurePoints = upsertSeriesPoint(state.pressurePoints, { tsMs, value });
    }
  }

  function rememberProcessEventSample(event) {
    if (!event || typeof event !== 'object') return;
    const profile = extractProcessProfile(event.raw);
    const state = getProcessState(profile);
    const parsedTime = new Date(event.timestamp || pickNestedValue(event.raw, 'timestamp', 'raw_time') || Date.now());
    const tsMs = Number.isNaN(parsedTime.getTime()) ? Date.now() : parsedTime.getTime();
    const score = normalizeFiniteNumber(event.score);
    const threshold = normalizeFiniteNumber(event.decision_threshold);

    state.lastEventType = String(event.event_type || state.lastEventType || '');
    if (score !== null) {
      state.scoreValue = score;
      state.scoreUpdatedAt = event.timestamp || state.scoreUpdatedAt || new Date(tsMs).toISOString();
      state.scorePoints = upsertSeriesPoint(state.scorePoints, { tsMs, value: score });
    }
    if (threshold !== null) {
      state.thresholdValue = threshold;
      state.thresholdUpdatedAt = event.timestamp || state.thresholdUpdatedAt || new Date(tsMs).toISOString();
    }
  }

  function renderProcessLegend(profile) {
    const card = getProcessCard(profile);
    if (!card?.legend) return;

    const state = getProcessState(profile);
    const pressureText = state.connected && state.pressureValue !== null
      ? `${formatPressure(state.pressureValue)} pressure`
      : (state.connected === false ? 'Historian offline' : 'Waiting for pressure');

    card.legend.innerHTML = `
      <span class="badge text-bg-light border d-inline-flex align-items-center gap-2">
        <span aria-hidden="true" style="display:inline-block;width:0.65rem;height:0.65rem;border-radius:999px;background:${escapeHtml(state.color)}"></span>
        <span>Pressure</span>
        <span class="text-${state.connected ? 'success' : 'secondary'}">${escapeHtml(pressureText)}</span>
      </span>
    `;
  }

  function buildValueRange(values, fractionPad, minimumPad) {
    if (!Array.isArray(values) || !values.length) return null;
    const minRaw = Math.min(...values);
    const maxRaw = Math.max(...values);
    const span = maxRaw - minRaw;
    const pad = Math.max(minimumPad, span * fractionPad || minimumPad);
    return {
      min: minRaw - pad,
      max: maxRaw + pad,
    };
  }

  function buildPolylinePath(points, xForTs, yForValue, extendSinglePoint = false, fullWidth = null) {
    if (!points.length) return '';
    if (points.length === 1) {
      const y = yForValue(points[0].value);
      if (extendSinglePoint && fullWidth) {
        return `M ${fullWidth.left} ${y} L ${fullWidth.right} ${y}`;
      }
      const x = xForTs(points[0].tsMs, 0, points);
      return `M ${x} ${y}`;
    }
    return points.map((point, index) => {
      const x = xForTs(point.tsMs, index, points);
      const y = yForValue(point.value);
      return `${index === 0 ? 'M' : 'L'} ${x} ${y}`;
    }).join(' ');
  }

  function renderProcessChart(profile) {
    const card = getProcessCard(profile);
    if (!card?.chart) return;

    const state = getProcessState(profile);
    const pressurePoints = state.pressurePoints.filter((point) => Number.isFinite(point.value));
    const allTimestamps = [
      ...pressurePoints.map((point) => point.tsMs),
    ].filter(Number.isFinite);

    if (!allTimestamps.length) {
      card.chart.innerHTML = `
        <text x="360" y="280" text-anchor="middle" fill="#64748b" font-size="14">
          Waiting for live process telemetry...
        </text>
      `;
      return;
    }

    const width = 720;
    const height = 560;
    const padding = { top: 28, right: 64, bottom: 46, left: 64 };
    const innerWidth = width - padding.left - padding.right;
    const innerHeight = height - padding.top - padding.bottom;
    const minTs = Math.min(...allTimestamps);
    const maxTs = Math.max(...allTimestamps);
    const pressureRange = buildValueRange(pressurePoints.map((point) => point.value), 0.08, 4) || { min: 0, max: 1 };

    function xForTs(tsMs, index, points) {
      if (!Number.isFinite(minTs) || !Number.isFinite(maxTs) || maxTs <= minTs) {
        if (points.length === 1) return padding.left + innerWidth / 2;
        return padding.left + (index / Math.max(1, points.length - 1)) * innerWidth;
      }
      return padding.left + ((tsMs - minTs) / Math.max(1, maxTs - minTs)) * innerWidth;
    }

    function yForPressure(value) {
      return padding.top + ((pressureRange.max - value) / Math.max(1, pressureRange.max - pressureRange.min)) * innerHeight;
    }

    const gridParts = [];
    for (let idx = 0; idx < 4; idx += 1) {
      const ratio = idx / 3;
      const y = padding.top + ratio * innerHeight;
      const pressureLabel = pressureRange.max - ratio * (pressureRange.max - pressureRange.min);
      gridParts.push(`<line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" stroke="rgba(148, 163, 184, 0.35)" stroke-width="1" />`);
      gridParts.push(`<text x="${padding.left - 10}" y="${y + 4}" text-anchor="end" fill="#64748b" font-size="11">${escapeHtml(formatPressure(Math.round(pressureLabel)))}</text>`);
    }
    gridParts.push(`<line x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${height - padding.bottom}" stroke="rgba(71, 85, 105, 0.45)" stroke-width="1" />`);
    gridParts.push(`<text x="${padding.left}" y="${padding.top - 8}" fill="${escapeHtml(state.color)}" font-size="11" font-weight="600">Pressure</text>`);

    const chartParts = [];
    const pressurePath = buildPolylinePath(
      pressurePoints,
      xForTs,
      yForPressure,
      false,
      { left: padding.left, right: width - padding.right },
    );
    if (pressurePath) {
      const lastPressure = pressurePoints[pressurePoints.length - 1];
      chartParts.push(`<path d="${pressurePath}" fill="none" stroke="${escapeHtml(state.color)}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path>`);
      if (lastPressure) {
        chartParts.push(`<circle cx="${xForTs(lastPressure.tsMs, pressurePoints.length - 1, pressurePoints)}" cy="${yForPressure(lastPressure.value)}" r="4" fill="${escapeHtml(state.color)}"></circle>`);
      }
    }

    const firstLabel = formatTimestamp(new Date(minTs).toISOString());
    const lastLabel = formatTimestamp(new Date(maxTs).toISOString());
    card.chart.innerHTML = `
      <rect x="0" y="0" width="${width}" height="${height}" rx="12" ry="12" fill="transparent"></rect>
      ${gridParts.join('')}
      ${chartParts.join('')}
      <text x="${padding.left}" y="${height - 10}" fill="#64748b" font-size="11">${escapeHtml(firstLabel)}</text>
      <text x="${width - padding.right}" y="${height - 10}" text-anchor="end" fill="#64748b" font-size="11">${escapeHtml(lastLabel)}</text>
    `;
  }

  function latestScoredProcessState() {
    let bestState = null;
    let bestScoreUpdatedAt = 0;
    processProfileState.forEach((state) => {
      const hasScoreData = state.scorePoints.length > 0 || state.scoreValue !== null || state.thresholdValue !== null;
      if (!hasScoreData) return;
      const updatedAt = Date.parse(state.scoreUpdatedAt || state.thresholdUpdatedAt || '');
      const updatedAtMs = Number.isFinite(updatedAt) ? updatedAt : 0;
      if (!bestState || updatedAtMs >= bestScoreUpdatedAt) {
        bestState = state;
        bestScoreUpdatedAt = updatedAtMs;
      }
    });
    return bestState;
  }

  function renderProcessScoreLegend() {
    if (!processScoreCard?.legend) return;

    const state = latestScoredProcessState();
    const scoreText = state && state.scoreValue !== null
      ? `${formatScore(state.scoreValue)} current score`
      : 'Waiting for IDS score';
    const thresholdText = state && state.thresholdValue !== null
      ? `${formatScore(state.thresholdValue)} threshold`
      : 'Threshold pending';

    processScoreCard.legend.innerHTML = `
      <span class="badge text-bg-light border d-inline-flex align-items-center gap-2">
        <span aria-hidden="true" style="display:inline-block;width:0.65rem;height:0.65rem;border-radius:999px;background:${escapeHtml(PROCESS_SCORE_COLOR)}"></span>
        <span>IDS Score</span>
        <span class="text-primary">${escapeHtml(scoreText)}</span>
      </span>
      <span class="badge text-bg-light border d-inline-flex align-items-center gap-2">
        <span aria-hidden="true" style="display:inline-block;width:0.7rem;height:0.7rem;border-radius:999px;border:2px dashed #dc2626"></span>
        <span>Threshold</span>
        <span class="text-danger">${escapeHtml(thresholdText)}</span>
      </span>
    `;
  }

  function renderProcessScoreChart() {
    if (!processScoreCard?.chart) return;

    const state = latestScoredProcessState();
    const scorePoints = state ? state.scorePoints.filter((point) => Number.isFinite(point.value)) : [];
    const thresholdValue = state ? normalizeFiniteNumber(state.thresholdValue) : null;
    const allTimestamps = scorePoints.map((point) => point.tsMs).filter(Number.isFinite);

    if (!allTimestamps.length) {
      processScoreCard.chart.innerHTML = `
        <text x="360" y="280" text-anchor="middle" fill="#64748b" font-size="14">
          Waiting for live IDS score samples...
        </text>
      `;
      return;
    }

    const width = 720;
    const height = 560;
    const padding = { top: 28, right: 48, bottom: 46, left: 64 };
    const innerWidth = width - padding.left - padding.right;
    const innerHeight = height - padding.top - padding.bottom;
    const minTs = Math.min(...allTimestamps);
    const maxTs = Math.max(...allTimestamps);
    const scaleValues = [
      ...scorePoints.map((point) => point.value),
      ...(thresholdValue !== null ? [thresholdValue] : []),
    ];
    const scoreRange = buildValueRange(scaleValues, 0.15, 0.5) || { min: 0, max: 1 };

    function xForTs(tsMs, index, points) {
      if (!Number.isFinite(minTs) || !Number.isFinite(maxTs) || maxTs <= minTs) {
        if (points.length === 1) return padding.left + innerWidth / 2;
        return padding.left + (index / Math.max(1, points.length - 1)) * innerWidth;
      }
      return padding.left + ((tsMs - minTs) / Math.max(1, maxTs - minTs)) * innerWidth;
    }

    function yForScore(value) {
      return padding.top + ((scoreRange.max - value) / Math.max(1e-6, scoreRange.max - scoreRange.min)) * innerHeight;
    }

    const gridParts = [];
    for (let idx = 0; idx < 4; idx += 1) {
      const ratio = idx / 3;
      const y = padding.top + ratio * innerHeight;
      const label = scoreRange.max - ratio * (scoreRange.max - scoreRange.min);
      gridParts.push(`<line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" stroke="rgba(148, 163, 184, 0.35)" stroke-width="1" />`);
      gridParts.push(`<text x="${padding.left - 10}" y="${y + 4}" text-anchor="end" fill="#64748b" font-size="11">${escapeHtml(formatScore(label))}</text>`);
    }
    gridParts.push(`<line x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${height - padding.bottom}" stroke="rgba(71, 85, 105, 0.45)" stroke-width="1" />`);
    gridParts.push(`<text x="${padding.left}" y="${padding.top - 8}" fill="${escapeHtml(PROCESS_SCORE_COLOR)}" font-size="11" font-weight="600">IDS score</text>`);
    if (thresholdValue !== null) {
      gridParts.push(`<text x="${width - padding.right}" y="${padding.top - 8}" text-anchor="end" fill="#dc2626" font-size="11" font-weight="600">Anomaly threshold</text>`);
    }

    const chartParts = [];
    const scorePath = buildPolylinePath(
      scorePoints,
      xForTs,
      yForScore,
      false,
      { left: padding.left, right: width - padding.right },
    );
    if (scorePath) {
      const lastScore = scorePoints[scorePoints.length - 1];
      const scoreStroke = isAnomalyType(state?.lastEventType || '') ? '#dc2626' : PROCESS_SCORE_COLOR;
      chartParts.push(`<path d="${scorePath}" fill="none" stroke="${escapeHtml(scoreStroke)}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"></path>`);
      if (lastScore) {
        chartParts.push(`<circle cx="${xForTs(lastScore.tsMs, scorePoints.length - 1, scorePoints)}" cy="${yForScore(lastScore.value)}" r="4" fill="${escapeHtml(scoreStroke)}"></circle>`);
      }
    }

    if (thresholdValue !== null) {
      const thresholdY = yForScore(thresholdValue);
      chartParts.push(
        `<line x1="${padding.left}" y1="${thresholdY}" x2="${width - padding.right}" y2="${thresholdY}" stroke="#dc2626" stroke-width="2.5" stroke-dasharray="8 6" stroke-linecap="round"></line>`
      );
    }

    const firstLabel = formatTimestamp(new Date(minTs).toISOString());
    const lastLabel = formatTimestamp(new Date(maxTs).toISOString());
    processScoreCard.chart.innerHTML = `
      <rect x="0" y="0" width="${width}" height="${height}" rx="12" ry="12" fill="transparent"></rect>
      ${gridParts.join('')}
      ${chartParts.join('')}
      <text x="${padding.left}" y="${height - 10}" fill="#64748b" font-size="11">${escapeHtml(firstLabel)}</text>
      <text x="${width - padding.right}" y="${height - 10}" text-anchor="end" fill="#64748b" font-size="11">${escapeHtml(lastLabel)}</text>
    `;
  }

  function renderProcessScoreCard() {
    if (!processScoreCard) return;

    const state = latestScoredProcessState();
    const statusParts = [];
    if (state?.label) {
      statusParts.push(`Profile ${state.label}`);
    }
    if (state?.scoreUpdatedAt) {
      statusParts.push(`score ${formatTimestamp(state.scoreUpdatedAt)}`);
    } else {
      statusParts.push('waiting for IDS score');
    }
    if (state?.thresholdValue !== null && state?.thresholdValue !== undefined) {
      statusParts.push(`threshold ${formatScore(state.thresholdValue)}`);
    } else {
      statusParts.push('threshold pending');
    }

    renderProcessScoreLegend();
    renderProcessScoreChart();
    setProcessScoreStatus(statusParts.join(' • '), state ? 'ok' : 'muted');
    if (state?.lastEventType) {
      setProcessScoreMeta(`Latest event type: ${state.lastEventType}`);
    } else {
      setProcessScoreMeta('IDS score samples appear here once process IDS events are ingested.');
    }
  }

  function renderProcessCard(profile) {
    const state = getProcessState(profile);
    const statusParts = [];
    if (state.connected === true) {
      statusParts.push(`Historian ${state.historianStatus || 'ok'}`);
    } else if (state.connected === false) {
      statusParts.push('Historian offline');
    } else {
      statusParts.push('Waiting for historian sample');
    }
    if (state.pressureUpdatedAt) {
      statusParts.push(`pressure ${formatTimestamp(state.pressureUpdatedAt)}`);
    }

    renderProcessLegend(profile);
    renderProcessChart(profile);
    const statusLevel = state.connected === false ? 'error' : (state.connected === true ? 'ok' : 'muted');
    setProcessTelemetryStatus(profile, statusParts.join(' • '), statusLevel);
    setProcessTelemetryMeta(profile, state.endpoint ? `Endpoint: ${state.endpoint}` : 'Endpoint not available yet.');
  }

  function renderAllProcessCards() {
    processCards.forEach((_card, profile) => {
      renderProcessCard(profile);
    });
    renderProcessScoreCard();
  }

  function processTelemetryCandidateUrls() {
    const urls = [];
    const pushCandidate = (url) => {
      const text = String(url || '').trim();
      if (text && !urls.includes(text)) {
        urls.push(text);
      }
    };

    if (isProcessLive() && typeof window !== 'undefined' && window.location) {
      const protocol = window.location.protocol || 'http:';
      const hostname = String(window.location.hostname || '').trim();
      pushCandidate(`${protocol}//127.0.0.1:4840/`);
      pushCandidate(`${protocol}//localhost:4840/`);
      if (hostname && hostname !== '127.0.0.1' && hostname !== 'localhost') {
        pushCandidate(`${protocol}//${hostname}:4840/`);
      }
    }
    pushCandidate(processTelemetryUrl);
    return urls;
  }

  async function fetchJsonWithTimeout(url) {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => {
      controller.abort();
    }, PROCESS_TELEMETRY_FETCH_TIMEOUT_MS);

    try {
      const res = await fetch(url, {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
        signal: controller.signal,
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.error || `HTTP ${res.status}`);
      }
      return payload;
    } catch (err) {
      if (err && err.name === 'AbortError') {
        throw new Error(`Timed out after ${PROCESS_TELEMETRY_FETCH_TIMEOUT_MS}ms`);
      }
      throw err;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  function normalizeProcessTelemetryPayload(payload) {
    if (!payload || typeof payload !== 'object') return null;
    if (Array.isArray(payload.series)) {
      return payload;
    }

    const profiles = payload.profiles;
    if (!profiles || typeof profiles !== 'object') return null;

    const metaByKey = {
      main: { label: 'Main PLC', color: '#0d6efd' },
      backup: { label: 'Backup PLC', color: '#fd7e14' },
    };
    const series = Object.entries(metaByKey).map(([key, meta]) => {
      const profile = profiles[key];
      const values = profile && typeof profile.values === 'object' ? profile.values : {};
      return {
        key,
        label: meta.label,
        color: meta.color,
        connected: !!(profile && profile.connected),
        endpoint: profile && profile.endpoint ? profile.endpoint : '',
        updated_at: profile && profile.updated_at ? new Date(Number(profile.updated_at) * 1000).toISOString() : '',
        metric: 'average_pressure',
        value: values.average_pressure,
        health_code: values.health_code,
        bridge_online: values.bridge_online,
      };
    });

    const sampleRaw = payload.generated_at || Date.now() / 1000;
    return {
      status: 'ok',
      historian_status: payload.status || 'ok',
      sample_time: new Date(Number(sampleRaw) * 1000).toISOString(),
      series,
    };
  }

  async function pollProcessTelemetry() {
    if (!hasProcessTelemetryChart()) return;

    let lastError = new Error('No telemetry source available');

    for (const candidateUrl of processTelemetryCandidateUrls()) {
      try {
        const payload = await fetchJsonWithTimeout(candidateUrl);
        const normalized = normalizeProcessTelemetryPayload(payload);
        if (!normalized) {
          throw new Error('Unsupported telemetry payload');
        }

        const series = Array.isArray(normalized.series) ? normalized.series : [];
        const sampleTime = normalized.sample_time || new Date().toISOString();
        series.forEach((entry) => rememberProcessTelemetrySample(entry, sampleTime, normalized.historian_status));
        renderAllProcessCards();
        return;
      } catch (err) {
        lastError = err;
      }
    }

    Object.keys(PROCESS_PROFILE_META).forEach((profile) => {
      if (!processCards.has(profile)) return;
      renderProcessCard(profile);
      setProcessTelemetryStatus(profile, `Process telemetry unavailable: ${lastError.message}`, 'error');
    });
  }

  function pentestErrorMessage(data, fallbackMessage) {
    if (!data || typeof data !== 'object') {
      return fallbackMessage;
    }

    const parts = [];
    if (data.error) {
      parts.push(`Error: ${data.error}`);
    } else if (fallbackMessage) {
      parts.push(fallbackMessage);
    }
    if (data.hint) {
      parts.push(`Hint: ${data.hint}`);
    }
    if (Array.isArray(data.details) && data.details.length) {
      parts.push(`Details: ${data.details[0]}`);
    }
    return parts.join('\n\n') || fallbackMessage;
  }

  function localizeInitialTimestamps() {
    document.querySelectorAll('[data-ids-ts]').forEach((el) => {
      const value = el.dataset.idsTs;
      if (!value) return;
      el.textContent = formatTimestamp(value);
    });

    if (latestEventEl) {
      renderLatest(
        latestEventEl.dataset.ts || '',
        latestEventEl.dataset.eventType || ''
      );
    }
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
      profile: extractProcessProfile(rawPayload),
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
      const normalized = payloadFromRow(row, payload);
      rawCache.set(String(eventId), normalized);
      if (isProcessLive()) {
        rememberProcessEventSample(normalized);
      }
    });
    if (isProcessLive()) {
      renderAllProcessCards();
    }
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
      profile: extractProcessProfile(raw),
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
    if (isProcessLive()) {
      rememberProcessEventSample(rawCache.get(eventId));
      renderAllProcessCards();
    }

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

  // Pentest demo handler
  function runPentestDemo(button, url, attackType) {
    if (!button || !url) return;
    
    const originalText = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Running...';
    
    const csrfToken = window.CSRF_TOKEN || document.querySelector('[name=csrftoken]')?.value || '';
    
    fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRFToken': csrfToken,
        'Content-Type': 'application/json'
      },
      signal: AbortSignal.timeout(70000)
    })
    .then(r => {
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${r.statusText}`);
      return r.json();
    })
    .then(data => {
      if (data.error) {
        alert(pentestErrorMessage(data, `Error running ${attackType}`));
      }
    })
    .catch(error => {
      alert(`Error: ${error.message}`);
    })
    .finally(() => {
      // Re-enable button
      button.disabled = false;
      button.innerHTML = originalText;
    });
  }
  
  // Event listeners for buttons
  clearButton.addEventListener('click', () => {
    const emptyRow = tbody.querySelector(`td[colspan="${emptyColspan()}"]`);
    if (emptyRow) {
      emptyRow.closest('tr')?.remove();
    }
    tbody.innerHTML = `<tr><td colspan="${emptyColspan()}" class="text-muted text-center">Live table cleared. Waiting for new IDS events...</td></tr>`;
  });

  const networkScanBtn = document.getElementById('ids-network-scan-demo');
  if (networkScanBtn) {
    networkScanBtn.addEventListener('click', () => {
      runPentestDemo(networkScanBtn, networkScanBtn.dataset.url, 'Network Scan');
    });
  }

  const modbusAttackBtn = document.getElementById('ids-modbus-attack-demo');
  if (modbusAttackBtn) {
    modbusAttackBtn.addEventListener('click', () => {
      runPentestDemo(modbusAttackBtn, modbusAttackBtn.dataset.url, 'Modbus Attack');
    });
  }

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
  if (hasProcessTelemetryChart()) {
    renderAllProcessCards();
    pollProcessTelemetry();
    processTelemetryTimer = window.setInterval(pollProcessTelemetry, 2000);
  }

  window.addEventListener('beforeunload', () => {
    if (pollTimer) {
      window.clearInterval(pollTimer);
    }
    if (processTelemetryTimer) {
      window.clearInterval(processTelemetryTimer);
    }
  });
})();

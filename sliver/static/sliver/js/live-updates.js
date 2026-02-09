(() => {
    const config = window.SLIVER_LIVE;
    if (!config || !config.type || !config.endpoint) {
        return;
    }

    const intervalMs = config.interval || 10000;
    const statusEl = document.getElementById('sliver-live-status');
    const updatedEl = document.getElementById('sliver-live-updated');
    const toggleBtn = document.getElementById('sliver-live-toggle');
    const refreshBtn = document.getElementById('sliver-live-refresh');

    const pausedKey = `sliver-live-paused-${config.type}`;
    let paused = localStorage.getItem(pausedKey) === '1';
    let lastSuccessAt = null;

    const escapeHtml = (value) => {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    };

    const truncate = (value, max = 40) => {
        if (!value) return '';
        const str = String(value);
        return str.length > max ? `${str.slice(0, max - 1)}…` : str;
    };

    const timeSince = (dateString) => {
        if (!dateString) return 'Never';
        const date = new Date(dateString.replace(' ', 'T') + 'Z');
        if (Number.isNaN(date.getTime())) return dateString;
        const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
        const intervals = [
            { label: 'day', seconds: 86400 },
            { label: 'hour', seconds: 3600 },
            { label: 'minute', seconds: 60 },
            { label: 'second', seconds: 1 },
        ];
        for (const interval of intervals) {
            const count = Math.floor(seconds / interval.seconds);
            if (count >= 1) {
                return `${count} ${interval.label}${count > 1 ? 's' : ''} ago`;
            }
        }
        return 'just now';
    };

    const formatTimestamp = (dateString) => {
        if (!dateString) return '—';
        const date = new Date(dateString.replace(' ', 'T') + 'Z');
        if (Number.isNaN(date.getTime())) return dateString;
        return date.toLocaleString();
    };

    const getCSRFToken = () => {
        const match = document.cookie.match(/csrftoken=([^;]+)/);
        return match ? match[1] : '';
    };

    const setStatus = (ok, message) => {
        if (!statusEl) return;
        statusEl.classList.remove('bg-success', 'bg-secondary', 'bg-danger', 'bg-warning', 'text-dark');
        if (message === 'Paused') {
            statusEl.classList.add('bg-warning', 'text-dark');
        } else {
            statusEl.classList.add(ok ? 'bg-success' : 'bg-danger');
        }
        statusEl.textContent = message;
    };

    const setUpdated = (text) => {
        if (updatedEl) {
            updatedEl.textContent = text;
        }
    };

    const updateToggleState = () => {
        if (!toggleBtn) return;
        toggleBtn.textContent = paused ? 'Resume' : 'Pause';
        toggleBtn.classList.toggle('btn-outline-warning', paused);
        toggleBtn.classList.toggle('btn-outline-secondary', !paused);
    };

    const updateLastUpdated = () => {
        if (!lastSuccessAt) return;
        const seconds = Math.floor((Date.now() - lastSuccessAt) / 1000);
        let label = 'Updated just now';
        if (seconds >= 60) {
            const minutes = Math.floor(seconds / 60);
            label = `Updated ${minutes}m ago`;
        } else if (seconds >= 10) {
            label = `Updated ${seconds}s ago`;
        }
        setUpdated(label);
    };

    const updateSessionsTable = (sessions) => {
        const table = document.getElementById('sessionsTable');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        if (!tbody) return;

        const rows = sessions.map((session) => {
            const statusBadge = session.status === 'ACTIVE' ? 'success' :
                (session.status === 'DEAD' ? 'danger' : 'warning');
            const typeBadge = session.session_type === 'BEACON' ? 'info' : 'primary';
            const onlineText = session.is_online ? 'Online' : 'Offline';
            const onlineClass = session.is_online ? 'text-success' : 'text-muted';
            const rowClass = session.is_online ? 'table-info' : '';
            const nameLabel = truncate(session.name || session.session_id, 20);
            const transport = session.transport || '?';
            const hostname = session.hostname || 'Unknown';
            const username = session.username || '?';
            const remote = session.remote_address || '?';
            const os = session.os || '?';
            const arch = session.arch || '?';
            const checkin = session.last_checkin ? timeSince(session.last_checkin) : 'Never';
            const interval = session.session_type === 'BEACON' && session.reconfigure_interval
                ? `<br><small class="text-muted">${session.reconfigure_interval}s interval</small>` : '';
            const privBadge = session.is_privileged ? '<span class="badge bg-warning ms-1">PRIV</span>' : '';

            return `
                <tr class="${rowClass}">
                  <td>
                    <div>
                      <strong>${escapeHtml(nameLabel)}</strong>
                      ${privBadge}
                    </div>
                    <small class="text-muted">${escapeHtml(session.session_id)}</small>
                  </td>
                  <td><span class="badge bg-secondary">${escapeHtml(session.engagement)}</span></td>
                  <td>
                    <span class="badge bg-${statusBadge}">${escapeHtml(session.status)}</span>
                    <small class="${onlineClass} d-block">${onlineText}</small>
                  </td>
                  <td>
                    <span class="badge bg-${typeBadge}">${escapeHtml(session.session_type)}</span>
                  </td>
                  <td>
                    <div>${escapeHtml(hostname)}</div>
                    <small class="text-muted">${escapeHtml(username)}@${escapeHtml(remote)}</small>
                  </td>
                  <td><code>${escapeHtml(os)}/${escapeHtml(arch)}</code></td>
                  <td>
                    <span title="${escapeHtml(session.last_checkin || '')}">${checkin}</span>
                    ${interval}
                  </td>
                  <td><code>${escapeHtml(transport)}</code></td>
                  <td>
                    <div class="btn-group" role="group">
                      <a href="/sliver/sessions/${encodeURIComponent(session.session_id)}/" class="btn btn-sm btn-outline-primary" title="View Details">
                        <i class="bi bi-eye"></i>
                      </a>
                      <button type="button" class="btn btn-sm btn-outline-secondary execute-btn"
                              data-session-id="${escapeHtml(session.session_id)}"
                              data-session-name="${escapeHtml(session.name || session.session_id)}"
                              title="Execute Command">
                        <i class="bi bi-terminal"></i>
                      </button>
                      <button type="button" class="btn btn-sm btn-outline-secondary template-btn"
                              data-session-id="${escapeHtml(session.session_id)}"
                              data-session-name="${escapeHtml(session.name || session.session_id)}"
                              title="Run Template">
                        <i class="bi bi-list-check"></i>
                      </button>
                      <form method="post" action="/sliver/sessions/${encodeURIComponent(session.session_id)}/loot/collect/" class="d-inline">
                        <input type="hidden" name="csrfmiddlewaretoken" value="${escapeHtml(getCSRFToken())}">
                        <button type="submit" class="btn btn-sm btn-outline-success" title="Collect Loot">
                          <i class="bi bi-download"></i>
                        </button>
                      </form>
                      <div class="dropdown">
                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                          <i class="bi bi-three-dots"></i>
                        </button>
                        <ul class="dropdown-menu">
                          <li><a class="dropdown-item" href="/sliver/sessions/${encodeURIComponent(session.session_id)}/">
                            <i class="bi bi-info-circle"></i> Session Details
                          </a></li>
                          <li><a class="dropdown-item" href="/sliver/sessions/${encodeURIComponent(session.session_id)}/jobs/">
                            <i class="bi bi-list-ul"></i> View Jobs
                          </a></li>
                        </ul>
                      </div>
                    </div>
                  </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = rows;
        const emptyState = document.getElementById('sessionsEmptyState');
        if (emptyState) {
            emptyState.classList.toggle('d-none', sessions.length > 0);
        }
        if (typeof window.sliverApplySessionFilter === 'function') {
            window.sliverApplySessionFilter();
        }
    };

    const updateJobsTable = (jobs) => {
        const table = document.getElementById('jobsTable');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        if (!tbody) return;

        const rows = jobs.map((job) => {
            const statusBadge = job.status === 'COMPLETED' ? 'success' :
                (job.status === 'FAILED' ? 'danger' : (job.status === 'RUNNING' ? 'info' : 'secondary'));
            const sessionLabel = job.session_name || job.session_id;
            const rowClass = job.status === 'FAILED' ? 'table-danger' : (job.status === 'RUNNING' ? 'table-warning' : '');

            return `
                <tr class="${rowClass}">
                  <td><code>${escapeHtml(job.job_id)}</code></td>
                  <td>
                    <a href="/sliver/sessions/${encodeURIComponent(job.session_id)}/">
                      ${escapeHtml(sessionLabel || job.session_id)}
                    </a>
                  </td>
                  <td>
                    <span class="badge bg-${statusBadge}">${escapeHtml(job.status)}</span>
                  </td>
                  <td>${escapeHtml(truncate(job.command || '', 50))}</td>
                  <td>${escapeHtml(formatTimestamp(job.started_at))}</td>
                  <td>${escapeHtml(job.completed_at ? formatTimestamp(job.completed_at) : '—')}</td>
                  <td>
                    <div class="btn-group" role="group">
                      <a class="btn btn-sm btn-outline-primary" href="/sliver/jobs/${encodeURIComponent(job.job_id)}/">
                        <i class="bi bi-eye"></i> View
                      </a>
                      <form method="post" action="/sliver/jobs/${encodeURIComponent(job.job_id)}/retry/" class="d-inline" onsubmit="return confirm('Retry job ${escapeHtml(job.job_id)}?')">
                        <input type="hidden" name="csrfmiddlewaretoken" value="${escapeHtml(getCSRFToken())}">
                        <button type="submit" class="btn btn-sm btn-outline-warning">
                          <i class="bi bi-arrow-repeat"></i> Retry
                        </button>
                      </form>
                    </div>
                  </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = rows;
        const emptyState = document.getElementById('jobsEmptyState');
        if (emptyState) {
            emptyState.classList.toggle('d-none', jobs.length > 0);
        }
    };

    const updateLootTable = (loot) => {
        const table = document.getElementById('lootTable');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        if (!tbody) return;

        const rows = loot.map((item) => {
            const downloadDisabled = !(item.has_file || item.has_content);
            const downloadButton = downloadDisabled
                ? '<span class="text-muted">—</span>'
                : `<a class="btn btn-sm btn-outline-primary" href="${escapeHtml(item.download_url)}">
                      <i class="bi bi-download"></i> Download
                   </a>`;

            return `
                <tr>
                  <td>${escapeHtml(item.name || item.loot_id)}</td>
                  <td>${escapeHtml(item.loot_type)}</td>
                  <td>
                    <a href="/sliver/sessions/${encodeURIComponent(item.session_id)}/">
                      ${escapeHtml(item.session_name || item.session_id)}
                    </a>
                  </td>
                  <td>${escapeHtml(item.engagement || '')}</td>
                  <td>${escapeHtml(formatTimestamp(item.collected_at))}</td>
                  <td>${escapeHtml(item.size_bytes || '—')}</td>
                  <td>${downloadButton}</td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = rows;
        const emptyState = document.getElementById('lootEmptyState');
        if (emptyState) {
            emptyState.classList.toggle('d-none', loot.length > 0);
        }
    };

    const updateUI = (data) => {
        if (config.type === 'sessions') {
            updateSessionsTable(data.sessions || []);
        } else if (config.type === 'jobs') {
            updateJobsTable(data.jobs || []);
        } else if (config.type === 'loot') {
            updateLootTable(data.loot || []);
        }
    };

    const poll = async (force = false) => {
        if (paused && !force) {
            return;
        }
        try {
            const response = await fetch(config.endpoint, {
                headers: { 'Accept': 'application/json' },
                credentials: 'same-origin',
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            updateUI(data);
            setStatus(true, paused ? 'Paused' : 'Live');
            lastSuccessAt = Date.now();
            updateLastUpdated();
            if (refreshBtn) {
                refreshBtn.classList.remove('btn-outline-danger');
            }
        } catch (error) {
            setStatus(false, 'Offline');
            setUpdated('Update failed');
            if (refreshBtn) {
                refreshBtn.classList.add('btn-outline-danger');
            }
        }
    };

    updateToggleState();
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            paused = !paused;
            localStorage.setItem(pausedKey, paused ? '1' : '0');
            setStatus(true, paused ? 'Paused' : 'Live');
            updateToggleState();
            if (!paused) {
                poll(true);
            }
        });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            refreshBtn.classList.remove('btn-outline-danger');
            poll(true);
        });
    }

    poll(true);
    setInterval(() => poll(), intervalMs);
    setInterval(updateLastUpdated, 10000);
})();

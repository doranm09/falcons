/**
 * React-based Session Monitor Component
 * Provides enhanced real-time session monitoring with modern UI
 */

class SessionMonitor extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            sessions: [],
            isConnected: false,
            lastUpdate: null,
            searchTerm: '',
            statusFilter: 'all',
            isLoading: true
        };

        this.ws = null;
        this.reconnectInterval = null;
    }

    componentDidMount() {
        this.connectWebSocket();
        window.addEventListener('beforeunload', this.cleanup);
    }

    componentWillUnmount() {
        this.cleanup();
    }

    connectWebSocket = () => {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/sliver/sessions/`;

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('WebSocket connected for session monitoring');
                this.setState({ isConnected: true });
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            };

            this.ws.onclose = () => {
                console.log('WebSocket closed, attempting to reconnect...');
                this.setState({ isConnected: false });
                this.attemptReconnect();
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };

        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this.attemptReconnect();
        }
    };

    attemptReconnect = () => {
        if (this.reconnectInterval) clearInterval(this.reconnectInterval);

        this.reconnectInterval = setInterval(() => {
            if (!this.state.isConnected) {
                console.log('Attempting to reconnect WebSocket...');
                this.connectWebSocket();
            } else {
                clearInterval(this.reconnectInterval);
                this.reconnectInterval = null;
            }
        }, 5000); // Reconnect every 5 seconds
    };

    handleWebSocketMessage = (data) => {
        switch (data.type) {
            case 'connection_established':
                this.setState({ isConnected: true });
                break;

            case 'initial_sessions':
                this.setState({
                    sessions: data.sessions,
                    isLoading: false,
                    lastUpdate: new Date()
                });
                break;

            case 'session_status_change':
                this.updateSessionStatus(data.session_id, data.status, data.last_checkin);
                break;

            case 'new_session':
                this.addNewSession(data.session);
                break;

            case 'session_lost':
                this.removeSession(data.session_id);
                break;

            case 'job_status_update':
                // Handle job updates if needed for session context
                break;

            default:
                console.log('Unknown WebSocket message type:', data.type);
        }
    };

    updateSessionStatus = (sessionId, status, lastCheckin) => {
        this.setState(prevState => ({
            sessions: prevState.sessions.map(session =>
                session.session_id === sessionId
                    ? { ...session, status, last_checkin: lastCheckin, is_online: status === 'ACTIVE' }
                    : session
            ),
            lastUpdate: new Date()
        }));
    };

    addNewSession = (sessionData) => {
        this.setState(prevState => ({
            sessions: [...prevState.sessions, sessionData],
            lastUpdate: new Date()
        }));

        // Show notification for new session
        this.showNotification(`New session detected: ${sessionData.name || sessionData.session_id}`, 'success');
    };

    removeSession = (sessionId) => {
        this.setState(prevState => ({
            sessions: prevState.sessions.filter(session => session.session_id !== sessionId),
            lastUpdate: new Date()
        }));

        this.showNotification(`Session lost: ${sessionId}`, 'warning');
    };

    showNotification = (message, type = 'info') => {
        // Create a simple notification system
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        notification.innerHTML = `
            <strong>Sliver</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    };

    cleanup = () => {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.close();
        }
        if (this.reconnectInterval) {
            clearInterval(this.reconnectInterval);
        }
        window.removeEventListener('beforeunload', this.cleanup);
    };

    handleSearch = (event) => {
        this.setState({ searchTerm: event.target.value });
    };

    handleStatusFilter = (status) => {
        this.setState({ statusFilter: status });
    };

    refreshSessions = async () => {
        try {
            const response = await fetch('/sliver/refresh-sessions/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                }
            });

            if (response.ok) {
                this.showNotification('Session refresh initiated', 'info');
            } else {
                throw new Error('Failed to refresh sessions');
            }
        } catch (error) {
            console.error('Error refreshing sessions:', error);
            this.showNotification('Failed to refresh sessions', 'danger');
        }
    };

    getCSRFToken = () => {
        // Get CSRF token from cookie
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrftoken') {
                return value;
            }
        }
        return '';
    };

    executeCommand = (sessionId, sessionName) => {
        // This would open a command modal or redirect to command execution page
        window.location.href = `/sliver/sessions/${sessionId}/`;
    };

    getFilteredSessions = () => {
        return this.state.sessions.filter(session => {
            // Search filter
            const matchesSearch = !this.state.searchTerm ||
                session.name?.toLowerCase().includes(this.state.searchTerm.toLowerCase()) ||
                session.session_id?.toLowerCase().includes(this.state.searchTerm.toLowerCase()) ||
                session.hostname?.toLowerCase().includes(this.state.searchTerm.toLowerCase());

            // Status filter
            const matchesStatus = this.state.statusFilter === 'all' ||
                (this.state.statusFilter === 'online' && session.is_online) ||
                (this.state.statusFilter === 'offline' && !session.is_online) ||
                session.status.toLowerCase() === this.state.statusFilter.toLowerCase();

            return matchesSearch && matchesStatus;
        });
    };

    render() {
        const filteredSessions = this.getFilteredSessions();
        const { isConnected, isLoading, lastUpdate, searchTerm, statusFilter } = this.state;

        return React.createElement('div', { className: 'container-fluid p-4' }, [
            // Header Section
            React.createElement('div', { key: 'header', className: 'row mb-4' }, [
                React.createElement('div', { className: 'col-12 d-flex justify-content-between align-items-center' }, [
                    React.createElement('div', {}, [
                        React.createElement('h2', { className: 'mb-0' }, [
                            React.createElement('i', { className: 'bi bi-robot me-2' }),
                            'Active Sessions'
                        ]),
                        React.createElement('p', { className: 'text-muted mb-0' }, 'Real-time beacon monitoring'),
                        React.createElement('small', { className: 'text-muted' }, [
                            'Last updated: ',
                            lastUpdate ? lastUpdate.toLocaleTimeString() : 'Never'
                        ])
                    ]),
                    React.createElement('div', { className: 'd-flex gap-2' }, [
                        React.createElement('div', {
                            className: `badge ${isConnected ? 'bg-success' : 'bg-danger'}`
                        }, isConnected ? '🟢 Live' : '🔴 Offline'),
                        React.createElement('button', {
                            type: 'button',
                            className: 'btn btn-outline-primary btn-sm',
                            onClick: this.refreshSessions,
                            disabled: isLoading
                        }, [
                            React.createElement('i', { className: 'bi bi-arrow-clockwise me-1' }),
                            'Refresh'
                        ])
                    ])
                ])
            ]),

            // Controls Section
            React.createElement('div', { key: 'controls', className: 'row mb-4' }, [
                React.createElement('div', { className: 'col-12' }, [
                    React.createElement('div', { className: 'card' }, [
                        React.createElement('div', { className: 'card-body' }, [
                            React.createElement('div', { className: 'row g-3 align-items-end' }, [
                                // Search Input
                                React.createElement('div', { className: 'col-md-4' }, [
                                    React.createElement('label', { className: 'form-label' }, 'Search Sessions'),
                                    React.createElement('input', {
                                        type: 'text',
                                        className: 'form-control',
                                        placeholder: 'Search by name, ID, or hostname...',
                                        value: searchTerm,
                                        onChange: this.handleSearch
                                    })
                                ]),
                                // Status Filter
                                React.createElement('div', { className: 'col-md-3' }, [
                                    React.createElement('label', { className: 'form-label' }, 'Status Filter'),
                                    React.createElement('select', {
                                        className: 'form-select',
                                        value: statusFilter,
                                        onChange: (e) => this.handleStatusFilter(e.target.value)
                                    }, [
                                        React.createElement('option', { value: 'all' }, 'All Sessions'),
                                        React.createElement('option', { value: 'online' }, 'Online Only'),
                                        React.createElement('option', { value: 'offline' }, 'Offline Only'),
                                        React.createElement('option', { value: 'active' }, 'Active'),
                                        React.createElement('option', { value: 'dead' }, 'Dead'),
                                        React.createElement('option', { value: 'disconnected' }, 'Disconnected'),
                                    ])
                                ]),
                                // Stats
                                React.createElement('div', { className: 'col-md-5' }, [
                                    React.createElement('div', { className: 'row g-2' }, [
                                        React.createElement('div', { className: 'col-4' }, [
                                            React.createElement('div', { className: 'text-center' }, [
                                                React.createElement('div', { className: 'h5 mb-0 text-primary' },
                                                    this.state.sessions.filter(s => s.is_online).length
                                                ),
                                                React.createElement('small', { className: 'text-muted' }, 'Online')
                                            ])
                                        ]),
                                        React.createElement('div', { className: 'col-4' }, [
                                            React.createElement('div', { className: 'text-center' }, [
                                                React.createElement('div', { className: 'h5 mb-0 text-info' },
                                                    this.state.sessions.length
                                                ),
                                                React.createElement('small', { className: 'text-muted' }, 'Total')
                                            ])
                                        ]),
                                        React.createElement('div', { className: 'col-4' }, [
                                            React.createElement('div', { className: 'text-center' }, [
                                                React.createElement('div', { className: 'h5 mb-0 text-success' },
                                                    filteredSessions.length
                                                ),
                                                React.createElement('small', { className: 'text-muted' }, 'Showing')
                                            ])
                                        ])
                                    ])
                                ])
                            ])
                        ])
                    ])
                ])
            ]),

            // Sessions Table
            React.createElement('div', { key: 'table', className: 'row' }, [
                React.createElement('div', { className: 'col-12' }, [
                    React.createElement('div', { className: 'card shadow-sm' }, [
                        React.createElement('div', { className: 'card-header d-flex justify-content-between align-items-center' }, [
                            React.createElement('h5', { className: 'mb-0' }, 'Sessions'),
                            isLoading && React.createElement('div', { className: 'spinner-border spinner-border-sm' })
                        ]),
                        React.createElement('div', { className: 'card-body p-0' }, [
                            React.createElement('div', { className: 'table-responsive' }, [
                                React.createElement('table', { className: 'table table-hover mb-0' }, [
                                    React.createElement('thead', { className: 'table-light' }, [
                                        React.createElement('tr', {}, [
                                            React.createElement('th', {}, 'Name/ID'),
                                            React.createElement('th', {}, 'Engagement'),
                                            React.createElement('th', {}, 'Status'),
                                            React.createElement('th', {}, 'Type'),
                                            React.createElement('th', {}, 'Host'),
                                            React.createElement('th', {}, 'OS/Arch'),
                                            React.createElement('th', {}, 'Last Check-in'),
                                            React.createElement('th', {}, 'Transport'),
                                            React.createElement('th', {}, 'Actions')
                                        ])
                                    ]),
                                    React.createElement('tbody', {}, [
                                        filteredSessions.length === 0
                                            ? React.createElement('tr', {}, [
                                                React.createElement('td', { colSpan: 9, className: 'text-center py-5' }, [
                                                    React.createElement('i', { className: 'bi bi-robot-x h1 text-muted' }),
                                                    React.createElement('h4', { className: 'text-muted' }, 'No Sessions Found'),
                                                    React.createElement('p', { className: 'text-muted' }, 'No sessions match your current filters.')
                                                ])
                                            ])
                                            : filteredSessions.map(session => this.renderSessionRow(session))
                                    ])
                                ])
                            ])
                        ])
                    ])
                ])
            ])
        ]);
    }

    renderSessionRow = (session) => {
        const sessionName = session.name || session.session_id;
        const isOnline = session.is_online;

        return React.createElement('tr', {
            key: session.session_id,
            className: isOnline ? 'table-info' : ''
        }, [
            React.createElement('td', {}, [
                React.createElement('div', {}, [
                    React.createElement('strong', {}, sessionName.substring(0, 20)),
                    session.is_privileged && React.createElement('span', {
                        className: 'badge bg-warning ms-1'
                    }, 'PRIV')
                ]),
                React.createElement('small', { className: 'text-muted' }, session.session_id)
            ]),

            React.createElement('td', {}, [
                React.createElement('span', { className: 'badge bg-secondary' }, session.engagement)
            ]),

            React.createElement('td', {}, [
                React.createElement('span', { className: `badge bg-${session.status === 'ACTIVE' ? 'success' : session.status === 'DEAD' ? 'danger' : 'warning'}` },
                    session.status
                ),
                isOnline && React.createElement('small', { className: 'text-success d-block' }, 'Online')
            ]),

            React.createElement('td', {}, [
                React.createElement('span', { className: `badge bg-${session.session_type === 'BEACON' ? 'info' : 'primary'}` },
                    session.session_type
                )
            ]),

            React.createElement('td', {}, [
                React.createElement('div', {}, session.hostname || 'Unknown'),
                React.createElement('small', { className: 'text-muted' }, `${session.username || '?'}@${session.remote_address || '?'}`)
            ]),

            React.createElement('td', {}, [
                React.createElement('code', {}, `${session.os || '?'} / ${session.arch || '?'}`)
            ]),

            React.createElement('td', {}, [
                session.last_checkin
                    ? React.createElement('span', {
                        title: new Date(session.last_checkin).toLocaleString()
                    }, this.getRelativeTime(session.last_checkin))
                    : 'Never',
                session.session_type === 'BEACON' && session.reconfigure_interval && [
                    React.createElement('br', { key: 'br' }),
                    React.createElement('small', { key: 'small', className: 'text-muted' }, `${session.reconfigure_interval}s interval`)
                ]
            ]),

            React.createElement('td', {}, [
                React.createElement('code', {}, session.transport || '?')
            ]),

            React.createElement('td', {}, [
                React.createElement('div', { className: 'btn-group btn-group-sm' }, [
                    React.createElement('a', {
                        href: `/sliver/sessions/${session.session_id}/`,
                        className: 'btn btn-outline-primary',
                        title: 'View Details'
                    }, React.createElement('i', { className: 'bi bi-eye' })),

                    React.createElement('button', {
                        type: 'button',
                        className: 'btn btn-outline-secondary',
                        onClick: () => this.executeCommand(session.session_id, sessionName),
                        title: 'Execute Command'
                    }, React.createElement('i', { className: 'bi bi-terminal' }))
                ])
            ])
        ]);
    };

    getRelativeTime = (dateString) => {
        if (!dateString) return 'Never';

        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;

        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours}h ago`;

        const diffDays = Math.floor(diffHours / 24);
        return `${diffDays}d ago`;
    };
}

// Make SessionMonitor available globally for use in Django templates
window.SessionMonitor = SessionMonitor;

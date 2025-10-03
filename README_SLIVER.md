# Sliver C2 Dashboard Integration

A comprehensive Django dashboard plugin for managing Sliver C2 operations, providing a web interface for command and control of red team implants and beacons.

## 🎯 **Overview**

The Sliver C2 Dashboard Plugin integrates Sliver teamserver with a Django web application, enabling red team operators to:

- ✅ Manage multiple teamserver connections
- ✅ Control red team engagements and campaigns
- ✅ Monitor beacon and interactive session status
- ✅ Execute commands and task templates asynchronously
- ✅ Generate and deploy custom implants/stagers
- ✅ Collect and manage loot/results
- ✅ Audit all operations with comprehensive logging

## 🏗️ **Architecture**

### **Models**
- **Teamserver**: Connection configurations for Sliver teamservers
- **Engagement**: Red team campaigns with scope and metadata
- **SliverSession**: Beacon and interactive implant tracking
- **SliverJob**: Async command execution and task management
- **Loot**: Collected data (files, credentials, system info)
- **TaskTemplate**: Pre-built command templates
- **ImplantTemplate**: Reusable stager configurations
- **AuditLog**: Security audit trail

### **Async Processing**
- Celery tasks for long-running operations
- Command execution with status tracking
- Implant generation and deployment
- Automated loot collection
- Event monitoring and watch automation

### **Views & UI**
- Main dashboard with operational metrics
- Engagement management interface
- Session monitoring with real-time status
- Interactive command execution
- Loot management and download

## 🚀 **Installation & Setup**

### **Prerequisites**
```bash
# Install Sliver Python client
pip install sliver-py

# Ensure Redis is running for Celery
# macOS: brew install redis && brew services start redis
# Linux: sudo systemctl start redis-server
# Windows: Download and start Redis server
```

### **Quick Setup**
```bash
# 1. Install the plugin
pip install -r requirements.txt

# 2. Run the automated setup
python setup_sliver.py

# 3. Start Celery worker (in separate terminal)
celery -A cyber_pen_test worker --loglevel=info

# 4. Start Django server
cd cyber_pen_test && python manage.py runserver

# 5. Access the Sliver dashboard
open http://localhost:8000/sliver/
```

### **Manual Setup**
```bash
# Add sliver app to INSTALLED_APPS in settings.py
INSTALLED_APPS = [
    ...
    'sliver',
]

# Include URLs
from django.urls import path, include  # Already added

urlpatterns = [
    ...
    path('sliver/', include('sliver.urls', namespace='sliver')),
]

# Run migrations
python cyber_pen_test/manage.py makemigrations sliver
python cyber_pen_test/manage.py migrate sliver

# Create default templates
python cyber_pen_test/manage.py create_default_templates
```

## 📊 **Usage Guide**

### **1. Configure Teamserver**
1. Access Django admin at `/admin/`
2. Create `Teamserver` instance with:
   - Host/address of your Sliver teamserver
   - Port (default: 31337)
   - Optional TLS certificates

### **2. Create Engagement**
1. Navigate to `/sliver/engagements/`
2. Click "Create New Engagement"
3. Fill in campaign details:
   - Name and description
   - Select teamserver
   - Define target scope

### **3. Monitor Sessions**
1. Go to `/sliver/sessions/`
2. View all active beacons and sessions
3. Filter by engagement or status
4. Check online/offline status

### **4. Execute Commands**
1. Click session name for details
2. Use "Quick Actions" to run commands
3. Or select from predefined templates
4. Monitor job status in real-time

### **5. Deploy Implants**
1. Go to `/sliver/generate-implant/`
2. Select engagement and template
3. Generate and deploy to targets

### **6. Collect Loot**
1. View collected data at `/sliver/loot/`
2. Download files and credentials
3. Automatic collection triggers

## 🎨 **Web Interface**

### **Dashboard (`/sliver/`)**
- Operational metrics and statistics
- Recent engagements and activities
- Quick action buttons
- Real-time status indicators

### **Engagements (`/sliver/engagements/`)**
- Card-based layout of campaigns
- Active session counts and status
- Start/stop engagement lifecycle
- Teamserver association display

### **Sessions (`/sliver/sessions/`)**
- Comprehensive session table
- Online/offline status with timestamps
- Multi-engagement filtering
- Real-time search functionality

### **Jobs (`/sliver/jobs/`)**
- All executed commands and results
- Status tracking (pending, running, completed, failed)
- Job duration and output display
- Template usage tracking

### **Loot (`/sliver/loot/`)**
- Collected files and credentials
- Download functionality
- Session and engagement grouping
- Automatic timestamp tracking

## 🛠️ **API Endpoints**

### **REST APIs**
- `/sliver/api/sessions/` - Session data feed
- `/sliver/api/jobs/` - Job status and results
- `/sliver/api/events/` - Real-time event monitoring
- `/sliver/api/teamserver-status/` - Connection health check

### **WebSocket** (Planned)
- `/sliver/events/stream/` - Live updates via Server-Sent Events

## ⚡ **Async Operations**

### **Celery Tasks**
- `sync_sessions_task` - Refresh session data from teamserver
- `execute_sliver_command_task` - Run commands asynchronously
- `generate_implant_task` - Build deployable implants
- `collect_loot_task` - Automated data harvesting
- `monitor_events_task` - Stream teamserver events

### **Job Processing**
- Persistent storage of command results
- Error handling and retry logic
- Status updates and notifications
- Audit logging for all operations

## 🔒 **Security & Auditing**

### **Audit Trail**
- Complete logging of all user actions
- IP address and user agent tracking
- Session association for accountability
- Searchable audit history

### **Access Control**
- Django user authentication
- Per-user operation isolation
- Engagement ownership verification
- Role-based permissions support

### **TLS Security**
- Teamserver TLS/mTLS authentication
- Secure certificate management
- Connection validation
- Error handling for failed auth

## 📝 **Command Templates**

### **Pre-built Templates**
- **Recon**: System info, network scans, process lists
- **Execution**: PowerShell, shell commands, file transfers
- **Loot**: Credential dumps, browser data, clipboard
- **Monitoring**: Screenshots, keylogging, network sniffing

### **Custom Templates**
- Parameterized command execution
- Reusable operation workflows
- Team-specific customization
- Category organization

## 🎖️ **Default Templates**

### **Implant Templates**
- Windows x64 Beacon & Session
- Linux x64 Beacon & Session
- macOS x64/ARM64 Beacon
- Configurable obfuscation and debugging

### **Task Templates**
- 15+ built-in templates for common operations
- Cross-platform compatibility
- Parameter substitution
- Error handling and status reporting

## 🐳 **Docker Deployment**

### **Using Docker Compose**
```yaml
# docker-compose.yml (already configured)
services:
  web:
    # Django app with Sliver integration
  celery:
    # Celery worker for async tasks
  redis:
    # Result backend for Celery
  db:
    # PostgreSQL database
```

### **Container Commands**
```bash
# Start all services
docker compose up -d --build

# Run setup script in container
docker compose exec web python ../setup_sliver.py

# Access application
open http://localhost:8000/sliver/
```

## 🔧 **Advanced Configuration**

### **Settings**
```python
# In Django settings.py
CELERY_BROKER_URL = 'redis://redis:6379/0'
CELERY_RESULT_BACKEND = 'redis://redis:6379/0'
CELERY_TIMEZONE = 'UTC'

# Sliver-specific settings
SLIVER_CACHE_TTL = 300  # seconds
SLIVER_MAX_COMMAND_TIMEOUT = 60  # seconds
SLIVER_DEFAULT_BEACON_INTERVAL = 60  # seconds
```

### **Custom Templates**
Create `sliver/templates/sliver/your_template.html` and extend functionality as needed.

### **Event Watchers**
Configure automated responses to Sliver events:
```python
# In Django admin or via API
watcher = Watcher.objects.create(
    engagement=engagement,
    event_filter={'event_type': 'session_opened'},
    action_config={'actions': [{'type': 'command', 'command': 'sysinfo'}]}
)
```

## 🚨 **Troubleshooting**

### **Common Issues**
- **Module not found**: Ensure `PYTHONPATH` includes project root
- **Database errors**: Check PostgreSQL connection settings
- **Redis connection**: Verify Redis service is running
- **Sliver connection**: Check teamserver TLS certificates
- **Permission denied**: Ensure proper user permissions

### **Logs & Debugging**
```bash
# Django logs
tail -f logs/django.log

# Celery logs
tail -f logs/celery.log

# Database logs
tail -f logs/postgres.log
```

## 📖 **API Reference**

### **View Classes**
- `SliverDashboard` - Main dashboard view
- `EngagementManagement` - CRUD operations for engagements
- `SessionMonitor` - Real-time session tracking
- `JobQueueView` - Async operation monitoring

### **Model Reference**
See `sliver/models.py` for complete field definitions and relationships.

### **Task Reference**
See `sliver/tasks.py` for available Celery tasks and parameters.

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure code follows Django conventions
5. Submit pull request with documentation

## 📋 **TODO & Roadmap**

- [ ] WebSocket real-time updates
- [ ] React.js frontend components
- [ ] Advanced event watchers
- [ ] Implant signing/verification
- [ ] Team collaboration features
- [ ] Report generation
- [ ] API rate limiting
- [ ] Advanced loot parsing
- [ ] Custom protocol support

## 📄 **License**

This Sliver Dashboard Plugin is part of the CyberPenTest framework and follows the same licensing terms.

## 🆘 **Support**

For issues and questions:
1. Check troubleshooting guides above
2. Review Django and Sliver documentation
3. Open GitHub issue with logs and configuration
4. Join the community Discord/Slack

---

**🎯 Ready to conduct red team operations? Your Sliver C2 controller is now integrated with your CyberPenTest dashboard!**

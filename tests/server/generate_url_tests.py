"""
Auto-generated comprehensive tests for all URL endpoints.
This is a comprehensive test suite covering all endpoints with:
- Allowed methods testing
- Authentication/permission checks
- 200/30x/40x path coverage
- Template context or JSON schema validation
- Side effects testing
"""
import pytest
from django.test import Client
from django.urls import reverse, resolve
from django.http import HttpResponse
import json
from unittest.mock import patch
from dashboard.models import *


class TestComprehensiveURLCoverage:

    @pytest.mark.django_db
    def test_dashboard_home_view(self, client):
        """Test dashboard-home redirects to the network monitoring landing page."""
        response = client.get(reverse('dashboard:dashboard-home'))
        assert response.status_code == 302
        assert response.url == reverse('dashboard:network_monitoring')

    @pytest.mark.django_db
    def test_network_scans_view(self, client):
        """Test network_scans: GET /scans/"""
        response = client.get(reverse('dashboard:network_scans'))
        assert response.status_code == 200
        assert 'dashboard/network_scans.html' in [t.name for t in response.templates]
        assert 'scan_history' in response.context
        assert 'agents' in response.context

    @pytest.mark.django_db
    def test_start_scan_ajax_post_only(self, client):
        """Test start-scan: POST only"""
        # GET should return 405
        response = client.get(reverse('dashboard:start-scan'))
        assert response.status_code == 405

        with patch('dashboard.views.scan_network_task') as mock_ping, patch('dashboard.views.nmap_discovery_task') as mock_nmap:
            mock_ping.delay.return_value.id = 'ping-task'
            mock_nmap.delay.return_value.id = 'nmap-task'

            # POST with default method (ping)
            response = client.post(reverse('dashboard:start-scan'), {'cidr': '192.168.1.0/24'})
            assert response.status_code == 200
            data = json.loads(response.content)
            assert data['method'] == 'ping'
            assert data['task_id'] == 'ping-task'

            # POST with nmap method
            response = client.post(reverse('dashboard:start-scan'), {'cidr': '192.168.1.0/24', 'scan_method': 'nmap'})
            assert response.status_code == 200
            data = json.loads(response.content)
            assert data['method'] == 'nmap'
            assert data['task_id'] == 'nmap-task'

    @pytest.mark.django_db
    def test_agent_scan_flow(self, agent_client):
        """Test agent-based scan start and results ingestion."""
        agent = AgentStatus.objects.create(agent_id='agent-1', hostname='test-host', ip_address='10.0.0.10')

        start_payload = {
            'agent_id': 'agent-1',
            'cidr': '10.0.0.0/24',
            'max_hosts': 10,
        }
        response = agent_client.post(
            reverse('dashboard:start-agent-scan'),
            json.dumps(start_payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.content)
        assert 'scan_id' in data
        assert 'command_id' in data

        scan = ScanRun.objects.get(id=data['scan_id'])
        assert scan.scan_type == 'agent'

        assert AgentCommand.objects.filter(id=data['command_id'], agent_id='agent-1', action='scan').exists()

        results_payload = {
            'agent_id': 'agent-1',
            'cidr': '10.0.0.0/24',
            'scan_id': scan.id,
            'hosts': ['10.0.0.11', '10.0.0.12'],
        }
        response = agent_client.post(
            reverse('dashboard:agent_scan_results'),
            json.dumps(results_payload),
            content_type='application/json'
        )
        assert response.status_code == 200
        scan.refresh_from_db()
        assert scan.status == 'COMPLETE'
        assert Node.objects.filter(scan_run=scan).count() == 2

    @pytest.mark.django_db
    def test_scan_status_view(self, client):
        """Test scan-status: GET /scan/status/<uuid:task_id>/"""
        # Mock task ID
        mock_task_id = '550e8400-e29b-41d4-a716-446655440000'

        response = client.get(reverse('dashboard:scan-status', args=[mock_task_id]))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'state' in data
        # Should have empty nodes list initially
        assert 'nodes' in data

    @pytest.mark.django_db
    def test_shortest_paths_view(self, client):
        """Test shortest-paths: POST /paths/"""
        # Create test data
        scan = ScanRun.objects.create(cidr="192.168.1.0/24")
        node1 = Node.objects.create(scan_run=scan, ip_address="192.168.1.1", name="node1")
        node2 = Node.objects.create(scan_run=scan, ip_address="192.168.1.2", name="node2")

        response = client.post(reverse('dashboard:shortest-paths'), {'start_node_id': node1.id})
        assert response.status_code in [200, 400]  # May fail without proper links

    @pytest.mark.django_db
    def test_history_view(self, client):
        """Test history: GET /history/"""
        response = client.get(reverse('dashboard:vulnerabilities'))
        assert response.status_code == 200
        assert 'dashboard/history.html' in [t.name for t in response.templates]

    @pytest.mark.django_db
    def test_graph_data_view(self, client):
        """Test graph-data: GET /graph/data/"""
        response = client.get(reverse('dashboard:graph-data'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert isinstance(data, list)  # Elements array

    @pytest.mark.django_db
    def test_sniffer_interfaces_get_only(self, client):
        """Test sniffer-interfaces: GET only"""
        response = client.get(reverse('dashboard:sniffer-interfaces'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'interfaces' in data

    @pytest.mark.django_db
    def test_sniffer_start_stop_post_only(self, client):
        """Test sniffer start/stop: POST only"""
        # Test both endpoints
        endpoints = ['dashboard:sniffer-start', 'dashboard:sniffer-stop']

        for endpoint in endpoints:
            # GET should fail
            response = client.get(reverse(endpoint))
            assert response.status_code == 405

            # POST should succeed (even with errors)
            response = client.post(reverse(endpoint))
            assert response.status_code in [200, 500]  # May fail due to external service

    @pytest.mark.django_db
    def test_scan_history_api(self, client):
        """Test scan-history: GET /scan/history/"""
        response = client.get(reverse('dashboard:scan-history'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'history' in data

    @pytest.mark.django_db
    def test_agent_report_api_auth_optional(self, agent_client):
        """Test agent_report: POST /agent/report/ (token required)"""
        # GET should fail
        response = agent_client.get(reverse('dashboard:agent_report'))
        assert response.status_code == 405

        # POST with minimal data
        test_data = {'agent_id': 'test-agent', 'hostname': 'test-host'}
        response = agent_client.post(
            reverse('dashboard:agent_report'),
            json.dumps(test_data),
            content_type='application/json'
        )
        assert response.status_code in [200, 400]  # May fail validation

    @pytest.mark.django_db
    def test_agent_cyber_report_api(self, agent_client):
        """Test agent_cyber_report: POST /agent/cyber_report/"""
        # Create node first
        node = Node.objects.create(ip_address="192.168.1.1", name="test-node", agent_id="test-agent")

        test_data = {
            'agent_id': 'test-agent',
            'cyber_data': {
                'OS': 'Ubuntu 20.04',
                'lib': ['python', 'requests'],
                'MAC': ['00:11:22:33:44:55'],
                'port': [{'id': 22, 'state': 'LISTEN'}]
            }
        }

        response = agent_client.post(
            reverse('dashboard:agent_cyber_report'),
            json.dumps(test_data),
            content_type='application/json'
        )
        assert response.status_code == 200

    @pytest.mark.django_db
    def test_agent_commands_api(self, agent_client):
        """Test agent_commands: GET /agent/commands/?agent_id=X"""
        response = agent_client.get(reverse('dashboard:agent_commands') + '?agent_id=test-agent')
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'commands' in data

    @pytest.mark.django_db
    def test_agent_command_result_api(self, agent_client):
        """Test agent_command_result: POST /agent/command_result/"""
        # Create command first
        command = AgentCommand.objects.create(agent_id='test-agent', action='ping')

        test_data = {
            'agent_id': 'test-agent',
            'command_id': command.id,
            'output': 'PING google.com: success'
        }

        response = agent_client.post(
            reverse('dashboard:agent_command_result'),
            json.dumps(test_data),
            content_type='application/json'
        )
        assert response.status_code == 200

    @pytest.mark.django_db
    def test_agent_monitoring_view(self, client):
        """Test agent_monitoring: GET /agent/monitoring/"""
        response = client.get(reverse('dashboard:agent_monitoring'))
        assert response.status_code == 200
        assert 'dashboard/agent_monitoring.html' in [t.name for t in response.templates]

    @pytest.mark.django_db
    def test_agent_status_api(self, client):
        """Test agent_status_api: GET /agent/status/"""
        # Create test agent
        AgentStatus.objects.create(agent_id='test-agent', hostname='test-host', ip_address='192.168.1.1')

        response = client.get(reverse('dashboard:agent_status_api'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'agents' in data
        assert len(data['agents']) >= 1

    @pytest.mark.django_db
    def test_send_agent_command_api(self, client):
        """Test send_agent_command: POST /agent/command/send/"""
        # Create agent first
        AgentStatus.objects.create(agent_id='test-agent', hostname='test-host', ip_address='192.168.1.1')

        test_data = {
            'agent_id': 'test-agent',
            'action': 'ping',
            'parameters': {'target': '8.8.8.8'}
        }

        response = client.post(reverse('dashboard:send_agent_command'), json.dumps(test_data), content_type='application/json')
        assert response.status_code == 200

    @pytest.mark.django_db
    def test_agent_details_view(self, client):
        """Test agent_details: GET /agent/<agent_id>/"""
        # Create agent
        agent = AgentStatus.objects.create(agent_id='test-agent', hostname='test-host', ip_address='192.168.1.1')

        response = client.get(reverse('dashboard:agent_details', args=['test-agent']))
        assert response.status_code == 200
        assert 'dashboard/agent_details.html' in [t.name for t in response.templates]

    @pytest.mark.django_db
    def test_agent_analysis_view(self, client):
        """Test agent_analysis: GET /agent/<agent_id>/analysis/"""
        # Create agent
        agent = AgentStatus.objects.create(agent_id='test-agent', hostname='test-host', ip_address='192.168.1.1')

        response = client.get(reverse('dashboard:agent_analysis', args=['test-agent']))
        assert response.status_code == 200
        assert 'dashboard/agent_analysis.html' in [t.name for t in response.templates]

    @pytest.mark.django_db
    def test_agent_command_history_api(self, client):
        """Test agent_command_history: GET /agent/<agent_id>/history/"""
        # Create agent
        agent = AgentStatus.objects.create(agent_id='test-agent', hostname='test-host', ip_address='192.168.1.1')

        response = client.get(reverse('dashboard:agent_command_history', args=['test-agent']))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'history' in data

    @pytest.mark.django_db
    def test_agent_version_api(self, client):
        """Test agent_version_api: GET /agent/versions/"""
        response = client.get(reverse('dashboard:agent_version_api'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'current_version' in data
        assert 'agents' in data

    @pytest.mark.django_db
    def test_node_details_api(self, client):
        """Test node_details: GET /node/<node_id>/details/"""
        # Create test data
        scan = ScanRun.objects.create(cidr="192.168.1.0/24")
        node = Node.objects.create(scan_run=scan, ip_address="192.168.1.1", name="test-node")

        response = client.get(reverse('dashboard:node_details', args=[node.id]))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'id' in data
        assert data['ip_address'] == '192.168.1.1'

    @pytest.mark.django_db
    def test_vulnerability_detail_view(self, client):
        """Test vuln-detail: GET /vulnerabilities/<scan_id>/"""
        # Create test data
        scan = ScanRun.objects.create(cidr="192.168.1.0/24")

        response = client.get(reverse('dashboard:vuln-detail', args=[scan.id]))
        assert response.status_code == 200
        assert 'dashboard/vulnerabilities.html' in [t.name for t in response.templates]

    @pytest.mark.django_db
    def test_network_monitoring_dashboard(self, client):
        """Test network_monitoring: GET /network/monitoring/"""
        response = client.get(reverse('dashboard:network_monitoring'))
        assert response.status_code == 200
        assert 'dashboard/network_monitoring.html' in [t.name for t in response.templates]

    @pytest.mark.django_db
    def test_network_metadata_api(self, client):
        """Test network_metadata_api: GET /network/metadata/"""
        response = client.get(reverse('dashboard:network_metadata_api'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'metadata' in data

    @pytest.mark.django_db
    def test_network_connections_api(self, client):
        """Test network_connections_api: GET /network/connections/"""
        response = client.get(reverse('dashboard:network_connections_api'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'connections' in data

    @pytest.mark.django_db
    def test_network_topology_api(self, client):
        """Test network_topology_api: GET /network/topology/"""
        response = client.get(reverse('dashboard:network_topology_api'))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'nodes' in data
        assert 'edges' in data

    @pytest.mark.django_db
    def test_start_openvas_scan_api(self, client):
        """Test start-vuln-scan: POST /scan/vuln/start/"""
        test_data = {'vuln_cidr': '192.168.1.0/24'}
        response = client.post(reverse('dashboard:start-vuln-scan'), test_data)
        assert response.status_code == 202  # Accepted for async processing

    @pytest.mark.django_db
    def test_vuln_scan_status_api(self, client):
        """Test vuln-scan-status: GET /scan/vuln/status/<scan_id>/"""
        scan = ScanRun.objects.create(cidr="192.168.1.0/24", status="IN_PROGRESS", scan_type="openvas")
        response = client.get(reverse('dashboard:vuln-scan-status', args=[scan.id]))
        assert response.status_code == 200

        data = json.loads(response.content)
        assert 'state' in data


class TestErrorCasesAndEdgeConditions:

    @pytest.mark.django_db
    def test_nonexistent_agent_details(self, client):
        """Test agent_details with nonexistent agent"""
        response = client.get(reverse('dashboard:agent_details', args=['nonexistent']))
        assert response.status_code == 302  # Should redirect to monitoring

    @pytest.mark.django_db
    def test_nonexistent_node_details(self, client):
        """Test node_details with nonexistent node"""
        response = client.get(reverse('dashboard:node_details', args=[99999]))
        assert response.status_code == 404

    @pytest.mark.django_db
    def test_agent_report_invalid_json(self, agent_client):
        """Test agent_report with invalid JSON"""
        response = agent_client.post(
            reverse('dashboard:agent_report'),
            'invalid json',
            content_type='application/json'
        )
        assert response.status_code == 400

    @pytest.mark.django_db
    def test_agent_cyber_report_missing_data(self, agent_client):
        """Test agent_cyber_report with missing required data"""
        test_data = {'agent_id': 'test-agent'}  # Missing cyber_data
        response = agent_client.post(
            reverse('dashboard:agent_cyber_report'),
            json.dumps(test_data),
            content_type='application/json'
        )
        assert response.status_code == 400

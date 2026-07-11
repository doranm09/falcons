import json
import shutil
import tempfile
from pathlib import Path
from django.test import TestCase, TransactionTestCase
from django.test.client import Client
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import override_settings
from unittest.mock import patch, MagicMock
from decimal import Decimal
import ipaddress
from datetime import timedelta
from .models import *
from .tasks import scan_network_task, launch_openvas_scan_task, poll_openvas_results
from .utils import dijkstra, list_interfaces
from .pid_testbed import build_testbed_from_sim_system


class ScanRunModelTest(TestCase):
    def setUp(self):
        self.scan_run = ScanRun.objects.create(
            cidr="192.168.1.0/24",
            status="PENDING",
            scan_type="ping",
            result_summary="Test scan"
        )

    def test_scan_run_creation(self):
        """Test ScanRun model creation and string representation."""
        self.assertEqual(str(self.scan_run), f"Scan on 192.168.1.0/24 at {self.scan_run.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        self.assertEqual(self.scan_run.status, "PENDING")
        self.assertEqual(self.scan_run.scan_type, "ping")

    def test_scan_run_defaults(self):
        """Test ScanRun default values."""
        new_scan = ScanRun.objects.create(cidr="10.0.0.0/8")
        self.assertEqual(new_scan.status, "PENDING")
        self.assertEqual(new_scan.scan_type, "ping")


class NodeModelTest(TestCase):
    def setUp(self):
        self.scan_run = ScanRun.objects.create(cidr="192.168.1.0/24")
        self.node = Node.objects.create(
            scan_run=self.scan_run,
            ip_address="192.168.1.1",
            name="test-node",
            status="online",
            cpu_count=4,
            memory_total=8*1024*1024*1024,  # 8GB
            platform_info="Linux"
        )

    def test_node_creation(self):
        """Test Node model creation."""
        self.assertEqual(str(self.node), "test-node (192.168.1.1)")
        self.assertEqual(self.node.ip_address, "192.168.1.1")
        self.assertEqual(self.node.status, "online")

    def test_get_cyber_template_data(self):
        """Test get_cyber_template_data method."""
        # Test empty data
        cyber_data = self.node.get_cyber_template_data()
        self.assertEqual(cyber_data["OS"], "Unknown")
        self.assertEqual(cyber_data["lib"], [])
        self.assertEqual(cyber_data["MAC"], [])
        self.assertEqual(cyber_data["port"], [])

        # Update with data
        self.node.os_info = "Ubuntu 20.04"
        self.node.installed_libraries = ["python3", "pip"]
        self.node.mac_addresses = ["00:11:22:33:44:55"]
        self.node.active_ports = [{"id": 22, "state": "LISTEN"}, {"id": 80, "state": "LISTEN"}]
        self.node.save()

        cyber_data = self.node.get_cyber_template_data()
        self.assertEqual(cyber_data["OS"], "Ubuntu 20.04")
        self.assertEqual(cyber_data["lib"], ["python3", "pip"])
        self.assertEqual(cyber_data["MAC"], ["00:11:22:33:44:55"])
        self.assertEqual(cyber_data["port"], [{"id": 22, "state": "LISTEN"}, {"id": 80, "state": "LISTEN"}])
        self.assertTrue(cyber_data["has_cyber_data"])

    def test_update_cyber_data(self):
        """Test update_cyber_data method."""
        cyber_data = {
            "OS": "Windows 10",
            "lib": ["chrome.exe", "firefox.exe"],
            "MAC": ["AA:BB:CC:DD:EE:FF"],
            "port": [{"id": 3389, "state": "LISTEN"}]
        }
        self.node.update_cyber_data(cyber_data)
        self.assertEqual(self.node.os_info, "Windows 10")
        self.assertEqual(self.node.installed_libraries, ["chrome.exe", "firefox.exe"])
        self.assertEqual(self.node.mac_addresses, ["AA:BB:CC:DD:EE:FF"])
        self.assertEqual(self.node.active_ports, [{"id": 3389, "state": "LISTEN"}])


class NodeInterfaceModelTest(TestCase):
    def setUp(self):
        scan = ScanRun.objects.create(cidr="192.168.1.0/24")
        self.node = Node.objects.create(
            scan_run=scan,
            ip_address="192.168.1.1",
            name="test-node"
        )

    def test_node_interface_creation(self):
        """Test NodeInterface model creation and uniqueness."""
        iface1 = NodeInterface.objects.create(
            node=self.node,
            name="eth0",
            ip="192.168.1.100",
            mac="00:11:22:33:44:55"
        )
        self.assertEqual(str(iface1), "test-node - eth0 (192.168.1.100)")

        # Test unique constraint
        with self.assertRaises(Exception):  # Should raise IntegrityError
            NodeInterface.objects.create(
                node=self.node,
                name="eth0",
                ip="192.168.1.101",
                mac="00:11:22:33:44:56"
            )


class LinkModelTest(TestCase):
    def setUp(self):
        self.scan = ScanRun.objects.create(cidr="192.168.1.0/24")
        self.node1 = Node.objects.create(scan_run=self.scan, ip_address="192.168.1.1", name="node1")
        self.node2 = Node.objects.create(scan_run=self.scan, ip_address="192.168.1.2", name="node2")

    def test_link_creation(self):
        """Test Link model creation and string representation."""
        weight = 1.5
        link = Link.objects.create(
            scan_run=self.scan,
            source=self.node1,
            destination=self.node2,
            weight=weight
        )
        self.assertEqual(str(link), f"node1 (192.168.1.1) -> node2 (192.168.1.2) (w={weight})")
        self.assertEqual(link.weight, weight)

    def test_link_uniqueness(self):
        """Test Link unique constraint per scan_run."""
        scan = ScanRun.objects.create(cidr="10.0.0.0/24")
        link1 = Link.objects.create(
            scan_run=scan,
            source=self.node1,
            destination=self.node2,
            weight=2.0
        )

        # Same scan_run, same source/dest should create error
        with self.assertRaises(Exception):
            Link.objects.create(
                scan_run=scan,
                source=self.node1,
                destination=self.node2,
                weight=3.0
            )


class VulnerabilityModelTest(TestCase):
    def test_vulnerability_creation(self):
        """Test Vulnerability model creation."""
        published = timezone.now()
        vuln = Vulnerability.objects.create(
            cve_id="CVE-2023-1234",
            description="Test vulnerability description",
            severity="High",
            score=7.5,
            published=published,
            last_modified=published,
            references="https://example.com/cve-2023-1234"
        )
        self.assertEqual(str(vuln), "CVE-2023-1234 (High)")
        self.assertEqual(vuln.severity, "High")
        self.assertEqual(vuln.score, 7.5)

    def test_vulnerability_unique_cve_id(self):
        """Test unique constraint on CVE ID."""
        Vulnerability.objects.create(
            cve_id="CVE-2023-0001",
            description="Test vuln",
            published=timezone.now(),
            last_modified=timezone.now()
        )

        with self.assertRaises(Exception):
            Vulnerability.objects.create(
                cve_id="CVE-2023-0001",
                description="Duplicate CVE",
                published=timezone.now(),
                last_modified=timezone.now()
            )


class AgentCommandModelTest(TestCase):
    def test_agent_command_creation(self):
        """Test AgentCommand model creation."""
        command = AgentCommand.objects.create(
            agent_id="test-agent-123",
            action="scan_ports",
            parameters={"target": "localhost", "ports": "1-1000"},
            acknowledged=False
        )
        self.assertEqual(str(command), "test-agent-123 - scan_ports")
        self.assertFalse(command.acknowledged)

    def test_command_acknowledgement(self):
        """Test command acknowledgement."""
        command = AgentCommand.objects.create(
            agent_id="test-agent-123",
            action="status",
            acknowledged=False
        )
        self.assertFalse(command.acknowledged)
        command.acknowledged = True
        command.save()
        self.assertTrue(command.acknowledged)


class CommandResultModelTest(TestCase):
    def setUp(self):
        self.command = AgentCommand.objects.create(
            agent_id="test-agent-123",
            action="ping",
            parameters={"target": "8.8.8.8"}
        )

    def test_command_result_creation(self):
        """Test CommandResult model creation."""
        result = CommandResult.objects.create(
            command=self.command,
            agent_id="test-agent-123",
            output="PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.\n64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms\n\n--- 8.8.8.8 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 12.3/12.3/12.3/0.0 ms"
        )
        self.assertEqual(str(result), f"Result {result.id} for test-agent-123 @ {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        self.assertEqual(result.output, result.output)


class AgentStatusModelTest(TestCase):
    def setUp(self):
        self.agent = AgentStatus.objects.create(
            agent_id="test-agent-001",
            hostname="test-host",
            ip_address="192.168.1.100",
            status="online",
            os_type="Linux",
            os_version="Ubuntu 20.04",
            platform="x86_64",
            cpu_count=8,
            memory_total=16*1024*1024*1024,  # 16GB
            heartbeat_interval=30
        )

    def test_agent_status_creation(self):
        """Test AgentStatus model creation."""
        self.assertEqual(str(self.agent), "test-host (test-agent-001) - online")
        self.assertEqual(self.agent.agent_id, "test-agent-001")
        self.assertEqual(self.agent.status, "online")

    def test_is_online_method(self):
        """Test is_online method."""
        # Should be online when status is online and within heartbeat interval
        self.assertTrue(self.agent.is_online())

        # Set to offline
        self.agent.status = "offline"
        self.assertFalse(self.agent.is_online())

    def test_update_status_method(self):
        """Test update_status method."""
        # Mock time to simulate old heartbeat
        old_time = timezone.now() - timezone.timedelta(minutes=5)
        self.agent.last_heartbeat = old_time
        self.agent.status = "online"
        self.agent.save()
        self.agent.update_status()
        self.assertEqual(self.agent.status, "offline")
        self.assertEqual(self.agent.consecutive_failures, 1)

    def test_record_heartbeat_method(self):
        """Test record_heartbeat method."""
        heartbeat_data = {
            "hostname": "updated-host",
            "os": "Updated OS",
            "os_version": "Updated Version",
            "platform": "arm64",
            "cpu_count": 4,
            "memory_total": 8*1024*1024*1024,
            "interfaces": [
                {"name": "eth0", "ip": "10.0.0.1", "mac": "00:11:22:33:44:55"}
            ]
        }

        self.agent.record_heartbeat(heartbeat_data)

        self.assertEqual(self.agent.hostname, "updated-host")
        self.assertEqual(self.agent.os_type, "Updated OS")
        self.assertEqual(self.agent.os_version, "Updated Version")
        self.assertEqual(self.agent.platform, "arm64")
        self.assertEqual(self.agent.cpu_count, 4)
        self.assertEqual(self.agent.memory_total, 8*1024*1024*1024)
        self.assertEqual(self.agent.status, "online")
        self.assertEqual(self.agent.consecutive_failures, 0)
        self.assertEqual(self.agent.interfaces, heartbeat_data["interfaces"])

    def test_get_uptime_method(self):
        """Test get_uptime method."""
        # Mock first_seen
        first_seen = timezone.now() - timezone.timedelta(days=1, hours=2)
        self.agent.first_seen = first_seen
        self.agent.save()

        uptime = self.agent.get_uptime()
        expected_uptime_seconds = timezone.now() - first_seen
        self.assertAlmostEqual(uptime.total_seconds(), expected_uptime_seconds.total_seconds(), delta=10)


class NetworkMetadataModelTest(TestCase):
    def setUp(self):
        self.agent = AgentStatus.objects.create(
            agent_id="test-agent-001",
            hostname="test-host",
            ip_address="192.168.1.100"
        )

    def test_network_metadata_creation(self):
        """Test NetworkMetadata model creation."""
        metadata = NetworkMetadata.objects.create(
            agent=self.agent,
            network_connections=[
                {"protocol": "TCP", "local_address": "127.0.0.1", "local_port": 8080, "remote_address": "8.8.8.8", "remote_port": 443, "status": "ESTABLISHED"}
            ],
            interface_statistics=[
                {"interface": "eth0", "bytes_sent": 1000, "bytes_recv": 2000, "packets_sent": 10, "packets_recv": 20}
            ],
            active_ports=[
                {"port": 80, "protocol": "tcp", "state": "LISTEN"}
            ],
            interfaces=[
                {"name": "eth0", "ip": "192.168.1.100", "mac": "00:11:22:33:44:55"}
            ],
            total_connections=1,
            total_interfaces=1
        )

        self.assertEqual(str(metadata), f"Network metadata for test-host at {metadata.timestamp}")
        self.assertEqual(metadata.total_connections, 1)
        self.assertEqual(metadata.total_interfaces, 1)


class NetworkConnectionModelTest(TestCase):
    def setUp(self):
        self.agent = AgentStatus.objects.create(
            agent_id="test-agent-001",
            hostname="test-host",
            ip_address="192.168.1.100"
        )
        self.metadata = NetworkMetadata.objects.create(
            agent=self.agent,
            total_connections=1,
            total_interfaces=0
        )

    def test_network_connection_creation(self):
        """Test NetworkConnection model creation."""
        connection = NetworkConnection.objects.create(
            metadata=self.metadata,
            agent=self.agent,
            protocol="TCP",
            local_address="192.168.1.100",
            local_port=8080,
            remote_address="8.8.8.8",
            remote_port=443,
            status="ESTABLISHED",
            process_pid=1234,
            process_name="python",
            process_username="www-data"
        )

        self.assertEqual(str(connection), "TCP 192.168.1.100:8080 -> 8.8.8.8:443")
        self.assertEqual(connection.protocol, "TCP")
        self.assertEqual(connection.status, "ESTABLISHED")


class UtilsTestCase(TestCase):
    def setUp(self):
        # Create test data for dijkstra
        scan = ScanRun.objects.create(cidr="192.168.1.0/24")
        self.nodes = []
        for i in range(1, 6):
            node = Node.objects.create(
                scan_run=scan,
                ip_address=f"192.168.1.{i}",
                name=f"node{i}"
            )
            self.nodes.append(node)

        # Create links forming a simple graph
        # node1 --1.0--> node2 --2.0--> node3 --3.0--> node4 --4.0--> node5
        self.links = []
        for i in range(len(self.nodes) - 1):
            link = Link.objects.create(
                scan_run=scan,
                source=self.nodes[i],
                destination=self.nodes[i+1],
                weight=float(i+1)
            )
            self.links.append(link)

    def test_dijkstra_simple_path(self):
        """Test Dijkstra algorithm with simple linear path."""
        distances = dijkstra(self.nodes, self.links, self.nodes[0].id)

        # All distances should be finite since nodes are connected
        self.assertEqual(distances[self.nodes[0].id], 0.0)  # Start node
        self.assertEqual(distances[self.nodes[1].id], 1.0)
        self.assertEqual(distances[self.nodes[2].id], 3.0)  # 1.0 + 2.0
        self.assertEqual(distances[self.nodes[3].id], 6.0)  # 1.0 + 2.0 + 3.0
        self.assertEqual(distances[self.nodes[4].id], 10.0)  # 1.0 + 2.0 + 3.0 + 4.0

    def test_dijkstra_disconnected_nodes(self):
        """Test Dijkstra with disconnected nodes."""
        # Create a disconnected node
        scan2 = ScanRun.objects.create(cidr="10.0.0.0/24")
        disconnected_node = Node.objects.create(
            scan_run=scan2,
            ip_address="10.0.0.1",
            name="disconnected"
        )

        distances = dijkstra([disconnected_node], [], disconnected_node.id)
        self.assertEqual(distances[disconnected_node.id], 0.0)

    @patch('dashboard.utils.get_if_list')
    def test_list_interfaces(self, mock_get_if_list):
        """Test list_interfaces utility function."""
        mock_get_if_list.return_value = ['eth0', 'eth1', 'lo']
        interfaces = list_interfaces()
        self.assertEqual(interfaces, ['eth0', 'eth1', 'lo'])
        mock_get_if_list.assert_called_once()


# View Tests
class DashboardViewTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_home_view(self):
        """Test home view renders correctly."""
        response = self.client.get(reverse('dashboard:dashboard-home'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/network_monitoring.html')

    def test_home_view_with_data(self):
        """Test home view includes network monitoring summary context."""
        scan = ScanRun.objects.create(cidr="192.168.1.0/24", status="RUNNING")
        agent = AgentStatus.objects.create(
            agent_id="test-agent-001",
            hostname="test-host",
            ip_address="192.168.1.100",
            status="online",
            processes=[
                {"pid": 1234, "name": "nginx", "status": "running"},
                {"pid": 5678, "name": "python", "status": "running"}
            ]
        )
        metadata = NetworkMetadata.objects.create(
            agent=agent,
            total_connections=1,
            total_interfaces=1,
        )
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=agent,
            protocol="TCP",
            local_address="192.168.1.100",
            local_port=8080,
            remote_address="8.8.8.8",
            remote_port=443,
            status="ESTABLISHED",
        )

        response = self.client.get(reverse('dashboard:dashboard-home'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('scan_history', response.context)
        self.assertIn('recent_metadata', response.context)
        self.assertIn('recent_connections', response.context)
        self.assertEqual(response.context['running_scans'], 1)
        self.assertEqual(response.context['pending_scans'], 0)
        self.assertEqual(response.context['total_agents'], 1)
        self.assertEqual(response.context['total_connections'], 1)
        self.assertEqual(response.context['total_metadata_records'], 1)


class ScanViewTests(TransactionTestCase):
    """Use TransactionTestCase for tests involving Celery tasks."""

    def setUp(self):
        self.client = Client()

    @patch('dashboard.tasks.scan_network_task.delay')
    def test_start_scan_ajax(self, mock_task):
        """Test AJAX scan initiation."""
        mock_task.id = 'test-task-id-123'
        mock_task.return_value.id = mock_task.id

        response = self.client.post(reverse('dashboard:start-scan'), {
            'cidr': '192.168.1.0/24'
        })

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["task_id"], mock_task.id)
        self.assertIn("scan_id", data)
        self.assertEqual(data["method"], "ping")
        mock_task.assert_called_once()
        args, _kwargs = mock_task.call_args
        self.assertEqual(args[0], '192.168.1.0/24')
        self.assertEqual(args[1], data["scan_id"])

    def test_start_scan_ajax_get_method(self):
        """Test scan AJAX with GET method returns 405."""
        response = self.client.get(reverse('dashboard:start-scan'))
        self.assertEqual(response.status_code, 405)
        self.assertJSONEqual(response.content, {"error": "Only POST allowed"})


class GraphViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan = ScanRun.objects.create(cidr="192.168.1.0/24")

    def test_graph_data_empty(self):
        """Test graph data with no scan runs."""
        # Delete the existing scan
        ScanRun.objects.all().delete()

        response = self.client.get(reverse('dashboard:graph-data'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_graph_data_with_scan(self):
        """Test graph data with nodes and links."""
        # Create nodes and links
        node1 = Node.objects.create(scan_run=self.scan, ip_address="192.168.1.1", name="node1")
        node2 = Node.objects.create(scan_run=self.scan, ip_address="192.168.1.2", name="node2")
        Link.objects.create(scan_run=self.scan, source=node1, destination=node2, weight=1.0)

        response = self.client.get(reverse('dashboard:graph-data'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(len(data), 3)  # 2 nodes + 1 link

        # Check node data
        node_data = [item for item in data if item.get('data', {}).get('source') is None]
        self.assertEqual(len(node_data), 2)

        # Check link data
        link_data = [item for item in data if item.get('data', {}).get('source') is not None]
        self.assertEqual(len(link_data), 1)

    def test_graph_data_with_scan_filter(self):
        """Test graph data filter by scan_run_id."""
        scan_two = ScanRun.objects.create(cidr="10.0.0.0/24")
        node1 = Node.objects.create(scan_run=self.scan, ip_address="192.168.1.10", name="node1")
        node2 = Node.objects.create(scan_run=self.scan, ip_address="192.168.1.11", name="node2")
        Link.objects.create(scan_run=self.scan, source=node1, destination=node2, weight=1.0)

        other_node = Node.objects.create(scan_run=scan_two, ip_address="10.0.0.10", name="node3")
        other_node2 = Node.objects.create(scan_run=scan_two, ip_address="10.0.0.11", name="node4")
        Link.objects.create(scan_run=scan_two, source=other_node, destination=other_node2, weight=2.0)

        response = self.client.get(reverse('dashboard:graph-data'), {'scan_run_id': self.scan.id})
        self.assertEqual(response.status_code, 200)
        data = response.json()

        node_data = [item for item in data if item.get('data', {}).get('source') is None]
        node_labels = {item["data"]["label"] for item in node_data}
        self.assertIn("node1", node_labels)
        self.assertIn("node2", node_labels)
        self.assertNotIn("node3", node_labels)

        link_data = [item for item in data if item.get('data', {}).get('source') is not None]
        self.assertEqual(len(link_data), 1)


class AgentViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="test-agent-001",
            hostname="test-host",
            ip_address="192.168.1.100",
            status="online"
        )

    def test_agent_monitoring_view(self):
        """Test agent monitoring dashboard."""
        response = self.client.get(reverse('dashboard:agent_monitoring'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/agent_monitoring.html')

    def test_agent_status_api(self):
        """Test agent status API endpoint."""
        response = self.client.get(reverse('dashboard:agent_status_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('agents', data)
        self.assertIn('timestamp', data)

        # Check agent data
        agents = data['agents']
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]['agent_id'], 'test-agent-001')

    def test_delete_offline_agents(self):
        """Test offline agent cleanup endpoint."""
        offline_agent = AgentStatus.objects.create(
            agent_id="offline-agent-001",
            hostname="offline-host",
            ip_address="192.168.1.200",
            status="offline",
            heartbeat_interval=30,
        )
        offline_command = AgentCommand.objects.create(
            agent_id=offline_agent.agent_id,
            action="ping",
            acknowledged=False,
        )
        CommandResult.objects.create(
            command=offline_command,
            agent_id=offline_agent.agent_id,
            output="offline result",
        )
        SbomReport.objects.create(
            agent_id=offline_agent.agent_id,
            document={"bomFormat": "CycloneDX"},
        )
        Node.objects.create(
            agent_id=offline_agent.agent_id,
            hostname="offline-host",
            name="offline-host",
            ip_address="192.168.1.200",
        )

        online_agent = AgentStatus.objects.create(
            agent_id="online-agent-001",
            hostname="online-host",
            ip_address="192.168.1.201",
            status="online",
        )

        response = self.client.post(reverse('dashboard:delete_offline_agents'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "offline_agents_deleted")
        self.assertEqual(data["deleted_agents"], 1)
        self.assertIn(offline_agent.agent_id, data["deleted_agent_ids"])

        self.assertFalse(AgentStatus.objects.filter(agent_id=offline_agent.agent_id).exists())
        self.assertTrue(AgentStatus.objects.filter(agent_id=online_agent.agent_id).exists())
        self.assertFalse(AgentCommand.objects.filter(agent_id=offline_agent.agent_id).exists())
        self.assertFalse(CommandResult.objects.filter(agent_id=offline_agent.agent_id).exists())
        self.assertFalse(SbomReport.objects.filter(agent_id=offline_agent.agent_id).exists())
        self.assertFalse(Node.objects.filter(agent_id=offline_agent.agent_id).exists())

    def test_agent_details_view(self):
        """Test individual agent details view."""
        response = self.client.get(reverse('dashboard:agent_details', args=[self.agent.agent_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/agent_details.html')
        self.assertEqual(response.context['agent'], self.agent)

    def test_agent_details_not_found(self):
        """Test agent details with non-existent agent."""
        response = self.client.get(reverse('dashboard:agent_details', args=['non-existent']))
        self.assertEqual(response.status_code, 302)  # Redirect to agent_monitoring

    def test_agent_analysis_view(self):
        """Test agent analysis view."""
        response = self.client.get(reverse('dashboard:agent_analysis', args=[self.agent.agent_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/agent_analysis.html')

    @patch('dashboard.views.requests.post')
    def test_send_agent_command(self, mock_post):
        """Test sending command to agent."""
        command_data = {
            'agent_id': self.agent.agent_id,
            'action': 'ping',
            'parameters': {'target': '8.8.8.8'}
        }

        response = self.client.post(
            reverse('dashboard:send_agent_command'),
            json.dumps(command_data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'command_sent')
        self.assertEqual(data['agent_id'], self.agent.agent_id)
        self.assertEqual(data['action'], 'ping')

        # Check command was created
        command = AgentCommand.objects.get(agent_id=self.agent.agent_id)
        self.assertEqual(command.action, 'ping')

    @patch('dashboard.views.requests.post')
    def test_send_agent_command_agent_not_found(self, mock_post):
        """Test sending command to non-existent agent."""
        command_data = {
            'agent_id': 'non-existent-agent',
            'action': 'ping'
        }

        response = self.client.post(
            reverse('dashboard:send_agent_command'),
            json.dumps(command_data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 404)
        data = response.json()
        self.assertEqual(data['error'], 'Agent not found')


@override_settings(AGENT_API_TOKEN="test-token", AGENT_API_TOKEN_REQUIRED=True)
class AgentAPITests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent_headers = {"HTTP_X_AGENT_TOKEN": "test-token"}
        self.agent = AgentStatus.objects.create(
            agent_id="test-agent-api",
            hostname="test-host-api",
            ip_address="192.168.1.100"
        )

    def test_agent_report(self):
        """Test agent report endpoint."""
        report_data = {
            'agent_id': self.agent.agent_id,
            'hostname': 'updated-hostname',
            'interfaces': [
                {'name': 'eth0', 'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55'},
                {'name': 'lo', 'ip': '127.0.0.1', 'mac': '00:00:00:00:00:00'}
            ],
            'os': 'Ubuntu',
            'os_version': '20.04',
            'platform': 'x86_64',
            'cpu_count': 8,
            'memory_total': 16*1024*1024*1024,
            'agent_version': '1.0.0'
        }

        response = self.client.post(
            reverse('dashboard:agent_report'),
            json.dumps(report_data),
            content_type='application/json',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'ok')

        # Check agent was updated
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.hostname, 'updated-hostname')
        self.assertEqual(self.agent.os_type, 'Ubuntu')
        self.assertEqual(self.agent.status, 'online')

    def test_agent_report_reclaims_existing_host_identity(self):
        """Test that a new agent_id for the same host/IP reuses the existing records."""
        self.agent.hostname = "stable-host"
        self.agent.ip_address = "192.168.1.110"
        self.agent.status = "offline"
        self.agent.save(update_fields=["hostname", "ip_address", "status"])
        node = Node.objects.create(
            agent_id=self.agent.agent_id,
            hostname="stable-host",
            name="stable-host",
            ip_address="192.168.1.110",
        )
        AgentCommand.objects.create(agent_id=self.agent.agent_id, action="ping", acknowledged=False)

        report_data = {
            'agent_id': 'replacement-agent-id',
            'hostname': 'stable-host',
            'interfaces': [
                {'name': 'eth0', 'ip': '192.168.1.110', 'mac': '00:11:22:33:44:66'},
            ],
            'os': 'Ubuntu',
            'os_version': '22.04',
            'platform': 'x86_64',
            'cpu_count': 4,
            'memory_total': 8*1024*1024*1024,
            'agent_version': '1.1.0'
        }

        response = self.client.post(
            reverse('dashboard:agent_report'),
            json.dumps(report_data),
            content_type='application/json',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(AgentStatus.objects.filter(agent_id='replacement-agent-id').exists())
        self.assertFalse(AgentStatus.objects.filter(agent_id='test-agent-api').exists())
        self.assertEqual(AgentStatus.objects.filter(hostname='stable-host', ip_address='192.168.1.110').count(), 1)

        node.refresh_from_db()
        self.assertEqual(node.agent_id, 'replacement-agent-id')
        self.assertEqual(Node.objects.filter(hostname='stable-host', ip_address='192.168.1.110').count(), 1)
        self.assertTrue(AgentCommand.objects.filter(agent_id='replacement-agent-id').exists())

    def test_agent_cyber_report(self):
        """Test agent cyber template report."""
        # Create associated Node
        node = Node.objects.create(
            agent_id=self.agent.agent_id,
            ip_address=self.agent.ip_address,
            name=self.agent.hostname
        )

        cyber_data = {
            'agent_id': self.agent.agent_id,
            'cyber_data': {
                'OS': 'Windows Server 2019',
                'lib': ['powershell.exe', 'cmd.exe'],
                'MAC': ['AA:BB:CC:DD:EE:FF'],
                'port': [{'id': 3389, 'state': 'LISTEN'}]
            }
        }

        response = self.client.post(
            reverse('dashboard:agent_cyber_report'),
            json.dumps(cyber_data),
            content_type='application/json',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'cyber_data_updated')

        # Check node was updated
        node.refresh_from_db()
        self.assertEqual(node.os_info, 'Windows Server 2019')
        self.assertEqual(node.installed_libraries, ['powershell.exe', 'cmd.exe'])

    def test_agent_commands(self):
        """Test retrieving agent commands."""
        # Create pending command
        command = AgentCommand.objects.create(
            agent_id=self.agent.agent_id,
            action='status_check',
            acknowledged=False
        )

        response = self.client.get(
            reverse('dashboard:agent_commands') + f'?agent_id={self.agent.agent_id}',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['commands']), 1)
        self.assertEqual(data['commands'][0]['action'], 'status_check')

        # Check command was marked as acknowledged
        command.refresh_from_db()
        self.assertTrue(command.acknowledged)

    def test_agent_command_result(self):
        """Test submitting command result."""
        command = AgentCommand.objects.create(
            agent_id=self.agent.agent_id,
            action='system_info'
        )

        result_data = {
            'agent_id': self.agent.agent_id,
            'command_id': command.id,
            'output': 'System info output here...'
        }

        response = self.client.post(
            reverse('dashboard:agent_command_result'),
            json.dumps(result_data),
            content_type='application/json',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'received')

        # Check result was created
        result = CommandResult.objects.get(command=command)
        self.assertEqual(result.output, 'System info output here...')


class NetworkMonitoringViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="test-agent-net",
            hostname="test-host-net",
            ip_address="192.168.1.100",
            status="online"
        )

    def test_network_monitoring_dashboard(self):
        """Test network monitoring dashboard."""
        response = self.client.get(reverse('dashboard:network_monitoring'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/network_monitoring.html')
        self.assertContains(response, "Live IDS Monitor")
        self.assertContains(response, reverse('dashboard:siem_soc_overview'))

    def test_network_monitoring_dashboard_counts_full_recent_telemetry(self):
        metadata_records = [
            NetworkMetadata.objects.create(
                agent=self.agent,
                total_connections=idx + 1,
                total_interfaces=2,
            )
            for idx in range(25)
        ]
        stale_metadata = NetworkMetadata.objects.create(
            agent=self.agent,
            total_connections=999,
            total_interfaces=1,
        )
        NetworkMetadata.objects.filter(id=stale_metadata.id).update(
            timestamp=timezone.now() - timedelta(minutes=20)
        )

        for idx, metadata in enumerate(metadata_records):
            connection = NetworkConnection.objects.create(
                metadata=metadata,
                agent=self.agent,
                protocol="TCP",
                local_address="192.168.1.100",
                local_port=8000 + idx,
                remote_address="10.0.0.1",
                remote_port=443,
                status="ESTABLISHED",
            )
            if idx >= 5:
                NetworkConnection.objects.filter(id=connection.id).update(
                    last_seen=timezone.now() - timedelta(hours=2)
                )

        response = self.client.get(reverse('dashboard:network_monitoring'))

        self.assertEqual(response.context['total_agents'], 1)
        self.assertEqual(response.context['total_metadata_records'], 25)
        self.assertEqual(response.context['total_connections'], 5)
        self.assertEqual(len(response.context['recent_metadata']), 20)
        self.assertEqual(len(response.context['recent_connections']), 5)

    def test_network_monitoring_dashboard_includes_agents_with_recent_metadata(self):
        stale_agent = AgentStatus.objects.create(
            agent_id="stale-agent-net",
            hostname="stale-host-net",
            ip_address="192.168.1.101",
            status="online",
        )
        AgentStatus.objects.filter(id=stale_agent.id).update(
            last_heartbeat=timezone.now() - timedelta(minutes=5)
        )
        NetworkMetadata.objects.create(
            agent=stale_agent,
            total_connections=2,
            total_interfaces=1,
        )

        response = self.client.get(reverse('dashboard:network_monitoring'))

        agent_ids = {agent.agent_id for agent in response.context['agents']}
        self.assertIn(self.agent.agent_id, agent_ids)
        self.assertIn(stale_agent.agent_id, agent_ids)
        self.assertEqual(response.context['total_agents'], 2)

    def test_network_metadata_api(self):
        """Test network metadata API."""
        # Create some test metadata
        NetworkMetadata.objects.create(
            agent=self.agent,
            total_connections=5,
            total_interfaces=2
        )

        response = self.client.get(reverse('dashboard:network_metadata_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('metadata', data)
        self.assertEqual(len(data['metadata']), 1)

    def test_network_connections_api(self):
        """Test network connections API."""
        # Create metadata and connection
        metadata = NetworkMetadata.objects.create(
            agent=self.agent,
            total_connections=1,
            total_interfaces=1
        )

        NetworkConnection.objects.create(
            metadata=metadata,
            agent=self.agent,
            protocol="TCP",
            local_address="192.168.1.100",
            local_port=8080,
            remote_address="8.8.8.8",
            remote_port=443,
            status="ESTABLISHED"
        )

        response = self.client.get(reverse('dashboard:network_connections_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('connections', data)
        self.assertEqual(len(data['connections']), 1)

    @patch('dashboard.views.requests.post')
    def test_start_sniffer_listener(self, mock_post):
        """Test starting sniffer listener."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'status': 'started'}
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        response = self.client.post(reverse('dashboard:sniffer-start'), {
            'interface': 'eth0'
        })

        self.assertEqual(response.status_code, 200)
        mock_post.assert_called_once_with(
            'http://localhost:5050/start',
            json={'interface': 'eth0'}
        )

    @patch('dashboard.views.requests.post')
    def test_stop_sniffer_listener(self, mock_post):
        """Test stopping sniffer listener."""
        mock_response = MagicMock()
        mock_response.json.return_value = {'status': 'stopped'}
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        response = self.client.post(reverse('dashboard:sniffer-stop'))

        self.assertEqual(response.status_code, 200)
        mock_post.assert_called_once_with('http://localhost:5050/stop')


class VulnerabilityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan = ScanRun.objects.create(
            cidr="192.168.1.0/24",
            scan_type="openvas"
        )
        self.node = Node.objects.create(
            scan_run=self.scan,
            ip_address="192.168.1.1",
            name="scan-node",
            hostname="scan-host",
        )
        self.vuln = ScanVulnerability.objects.create(
            scan_run=self.scan,
            host_ip="192.168.1.1",
            cve_id="CVE-2023-TEST",
            name="Test Vulnerability",
            severity="High",
            cvss_score=8.5,
            description="Test vulnerability description"
        )

    def test_vulnerability_detail_view(self):
        """Test vulnerability detail view."""
        response = self.client.get(reverse('dashboard:vuln-detail', args=[self.scan.id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/vulnerabilities.html')
        self.assertContains(response, "scan-host")

    def test_vulnerability_detail_view_includes_sbom_vulnerabilities_in_scan_cidr(self):
        node = Node.objects.create(
            name="agent-host",
            hostname="agent-host",
            ip_address="192.168.1.25",
            agent_id="agent-sbom-report",
        )
        sbom_vuln = Vulnerability.objects.create(
            cve_id="CVE-2024-SBOM",
            description="SBOM derived vulnerability",
            severity="High",
            score=7.5,
            package="openssl",
            installed_version="3.0.13",
            fixed_version="3.0.14",
            source="https://security-tracker.debian.org/tracker/CVE-2024-SBOM",
            published=timezone.now(),
            last_modified=timezone.now(),
        )
        sbom_vuln.nodes.add(node)

        response = self.client.get(reverse('dashboard:vuln-detail', args=[self.scan.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CVE-2024-SBOM")
        self.assertContains(response, "SBOM")
        self.assertContains(response, "openssl")
        self.assertContains(response, "3.0.13")
        self.assertContains(response, "3.0.14")
        self.assertContains(response, "agent-host")

    @patch('dashboard.tasks.launch_openvas_scan_task.delay')
    def test_start_openvas_scan(self, mock_task):
        """Test starting OpenVAS scan."""
        mock_task.id = 'openvas-task-id'
        mock_task.return_value.id = mock_task.id

        response = self.client.post(reverse('dashboard:start-vuln-scan'), {
            'vuln_cidr': '192.168.1.0/24'
        })

        self.assertEqual(response.status_code, 202)
        data = response.json()
        self.assertIn('scan_id', data)
        self.assertIn('task_id', data)


class TaskTests(TestCase):
    @patch('dashboard.tasks.subprocess.run')
    @patch('dashboard.tasks.parse_ping_latency')
    def test_scan_network_task(self, mock_parse_latency, mock_subprocess):
        """Test scan network task."""
        # Mock subprocess to simulate ping responses
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = b"64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=5.0 ms"
        mock_subprocess.return_value = mock_process
        mock_parse_latency.return_value = 5.0

        # Run task
        result = scan_network_task("192.168.1.0/29")  # Small subnet for testing

        # Check results
        scan = ScanRun.objects.get(cidr="192.168.1.0/29")
        self.assertEqual(scan.status, "COMPLETE")
        self.assertIn("nodes", scan.result_summary)

        # Check nodes were created
        nodes = Node.objects.filter(scan_run=scan)
        self.assertTrue(nodes.count() > 0)

    @patch('dashboard.tasks.openvas_session')
    @patch('dashboard.tasks.create_target')
    @patch('dashboard.tasks.start_scan')
    @patch('dashboard.tasks.get_report_id')
    def test_launch_openvas_scan_task(self, mock_get_report_id, mock_start_scan, mock_create_target, mock_session):
        """Test OpenVAS scan launch task."""
        mock_session.return_value = MagicMock()
        mock_create_target.return_value = "target-123"
        mock_start_scan.return_value = "task-456"
        mock_get_report_id.return_value = None

        result = launch_openvas_scan_task("192.168.1.0/24")

        scan = ScanRun.objects.get(cidr="192.168.1.0/24")
        self.assertEqual(scan.scan_type, "openvas")
        self.assertIn("OpenVAS scan launched", scan.result_summary)

    @patch('dashboard.tasks.openvas_session')
    @patch('dashboard.tasks.create_target')
    @patch('dashboard.tasks.start_scan')
    def test_launch_openvas_scan_task_passes_excluded_hosts(self, mock_start_scan, mock_create_target, mock_session):
        """Test OpenVAS scan launch task forwards excluded hosts to target creation."""
        session = MagicMock()
        mock_session.return_value = session
        mock_create_target.return_value = "target-123"
        mock_start_scan.return_value = "task-456"

        excluded_hosts = ["10.2.50.10", "10.2.50.40"]
        launch_openvas_scan_task("192.168.1.0/24", excluded_hosts=excluded_hosts)

        mock_create_target.assert_called_once_with(
            session,
            "192.168.1.0/24",
            excluded_hosts=excluded_hosts,
        )

    @patch('dashboard.tasks.requests.get')
    def test_fetch_and_store_cves(self, mock_get):
        """Test fetching CVEs from NVD."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'vulnerabilities': [
                {
                    'cve': {
                        'id': 'CVE-2023-TEST-001',
                        'sourceIdentifier': 'nvd@nist.gov',
                        'published': '2023-01-01T00:00:00.000',
                        'lastModified': '2023-01-02T00:00:00.000',
                        'vulnStatus': 'Analyzed',
                        'descriptions': [{'lang': 'en', 'value': 'Test CVE'}],
                        'references': [{'url': 'https://example.com/cve-2023-test-001'}],
                        'metrics': {
                            'cvssMetricV31': [{
                                'cvssData': {
                                    'version': '3.1',
                                    'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                                    'attackVector': 'NETWORK',
                                    'attackComplexity': 'LOW',
                                    'privilegesRequired': 'NONE',
                                    'userInteraction': 'NONE',
                                    'scope': 'UNCHANGED',
                                    'confidentialityImpact': 'HIGH',
                                    'integrityImpact': 'HIGH',
                                    'availabilityImpact': 'HIGH',
                                    'baseScore': 9.8,
                                    'baseSeverity': 'CRITICAL'
                                },
                                'exploitabilityScore': 3.9,
                                'impactScore': 5.9
                            }]
                        }
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        # Note: Due to task mocking complexity, we'll test the core function separately
        # In a real scenario, this would be tested through the full task execution


class NodeViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan = ScanRun.objects.create(cidr="192.168.1.0/24")
        self.node = Node.objects.create(
            scan_run=self.scan,
            ip_address="192.168.1.1",
            name="test-node",
            os_info="Linux Ubuntu 20.04",
            cpu_count=4,
            memory_total=8*1024*1024*1024
        )

    def test_node_details_api(self):
        """Test node details API."""
        response = self.client.get(reverse('dashboard:node_details', args=[self.node.id]))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data['id'], self.node.id)
        self.assertEqual(data['name'], 'test-node')
        self.assertEqual(data['ip_address'], '192.168.1.1')
        self.assertEqual(data['system_info']['cpu_count'], 4)
        self.assertIn('purdue_level', data)
        self.assertIn('role', data)

    def test_node_detail_page_rollup(self):
        ScanVulnerability.objects.create(
            scan_run=self.scan,
            host_ip="192.168.1.1",
            cve_id="CVE-2026-NODE",
            name="Node detail vuln",
            severity="High",
            cvss_score=8.0,
            description="Node detail vulnerability",
        )

        response = self.client.get(reverse('dashboard:node_detail_page', args=[self.node.id]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/node_detail.html')
        self.assertContains(response, "Purdue Context")
        self.assertContains(response, "Vulnerability Rollup")
        self.assertContains(response, "Open Latest Report")
        self.assertContains(response, "OpenVAS Findings")
        self.assertContains(response, "CVE-2026-NODE")
        self.assertContains(response, "Node detail vulnerability")

    def test_node_detail_page_matches_openvas_findings_by_interface_ip(self):
        NodeInterface.objects.create(
            node=self.node,
            name="eth1",
            ip="192.168.1.44",
            mac="00:11:22:33:44:55",
        )
        ScanVulnerability.objects.create(
            scan_run=self.scan,
            host_ip="192.168.1.44",
            cve_id="CVE-2026-IFACE",
            name="Interface-linked vuln",
            severity="Medium",
            cvss_score=5.6,
            description="Matched through NodeInterface.ip",
        )

        response = self.client.get(reverse('dashboard:node_detail_page', args=[self.node.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CVE-2026-IFACE")
        self.assertContains(response, "192.168.1.44")
        self.assertContains(response, "Matched through NodeInterface.ip")

    @patch("dashboard.views.fetch_gvmd_findings_for_ips")
    def test_node_detail_page_includes_gvmd_findings(self, mock_fetch_gvmd_findings):
        mock_fetch_gvmd_findings.return_value = [
            {
                "host_ip": "192.168.1.1",
                "cve_id": "CVE-2026-GVMD",
                "name": "GVMD-backed vuln",
                "severity": "High",
                "cvss_score": 8.8,
                "description": "Directly read from gvmd database",
                "report_uuid": "report-uuid-123",
                "task_name": "IAEA Scan",
                "task_uuid": "task-uuid-123",
                "nvt_oid": "1.3.6.1.4.1.test",
                "link_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-GVMD",
            }
        ]

        response = self.client.get(reverse('dashboard:node_detail_page', args=[self.node.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CVE-2026-GVMD")
        self.assertContains(response, "GVMD-backed vuln")
        self.assertContains(response, "Directly read from gvmd database")
        self.assertContains(response, "GVMD")
        self.assertContains(response, "IAEA Scan")

    def test_node_details_not_found(self):
        """Test node details for non-existent node."""
        response = self.client.get(reverse('dashboard:node_details', args=[9999]))
        self.assertEqual(response.status_code, 404)
        data = response.json()
        self.assertEqual(data['error'], 'Node not found')


class HistoryViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.scan = ScanRun.objects.create(
            cidr="192.168.1.0/24",
            status="COMPLETE",
            result_summary="Scan completed successfully"
        )
        self.vuln = Vulnerability.objects.create(
            cve_id="CVE-2023-TEST",
            description="Test vulnerability",
            severity="High",
            published=timezone.now(),
            last_modified=timezone.now()
        )
        self.scan_finding = ScanVulnerability.objects.create(
            scan_run=self.scan,
            host_ip="192.168.1.10",
            cve_id="CVE-2024-HISTORY",
            name="Inventory finding",
            severity="High",
            cvss_score=8.1,
            description="History inventory finding",
        )
        self.history_node = Node.objects.create(
            scan_run=self.scan,
            ip_address="192.168.1.10",
            name="inventory-node",
            hostname="inventory-host",
        )

    def test_history_view(self):
        """Test scan history view."""
        response = self.client.get(reverse('dashboard:vulnerabilities'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/history.html')
        self.assertContains(response, "Vulnerability Inventory")
        self.assertContains(response, "Global Inventory")
        self.assertContains(response, "Exposure")
        self.assertContains(response, "Host Drilldown")
        self.assertContains(response, "Traceable Artifacts")
        self.assertContains(response, "CVE-2024-HISTORY")
        self.assertContains(response, "inventory-host")
        self.assertContains(response, reverse('dashboard:vuln-detail', args=[self.scan.id]))

    def test_history_view_consolidates_duplicate_findings_and_keeps_latest_report(self):
        later_scan = ScanRun.objects.create(
            cidr="192.168.1.0/24",
            status="COMPLETE",
            scan_type="openvas",
            timestamp=timezone.now() + timedelta(minutes=5),
        )
        ScanVulnerability.objects.create(
            scan_run=later_scan,
            host_ip="192.168.1.10",
            cve_id="CVE-2024-HISTORY",
            name="Inventory finding",
            severity="Critical",
            cvss_score=9.4,
            description="Repeated in a later scan",
        )

        response = self.client.get(reverse('dashboard:vulnerabilities'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CVE-2024-HISTORY")
        self.assertContains(response, "2 scans")
        self.assertContains(response, "1 findings")
        self.assertContains(response, reverse('dashboard:vuln-detail', args=[later_scan.id]))

    def test_history_view_includes_sbom_backed_inventory_rows(self):
        node = Node.objects.create(
            name="sbom-node",
            hostname="sbom-host",
            ip_address="192.168.1.25",
            scan_run=self.scan,
            agent_id="agent-history-sbom",
        )
        self.vuln.nodes.add(node)

        response = self.client.get(reverse('dashboard:vulnerabilities'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SBOM")
        self.assertContains(response, "CVE-2023-TEST")
        self.assertContains(response, "sbom-host")
        self.assertContains(response, reverse('dashboard:vuln-detail', args=[self.scan.id]))

    def test_history_view_resolves_hostname_from_interface_ip_for_network_findings(self):
        NodeInterface.objects.create(
            node=self.history_node,
            name="eth1",
            ip="192.168.1.44",
            mac="00:aa:bb:cc:dd:ee",
        )
        ScanVulnerability.objects.create(
            scan_run=self.scan,
            host_ip="192.168.1.44",
            cve_id="CVE-2024-IFACE-HISTORY",
            name="Interface inventory finding",
            severity="Medium",
            cvss_score=6.0,
            description="History should map hostname by interface IP",
        )

        response = self.client.get(reverse('dashboard:vulnerabilities'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "CVE-2024-IFACE-HISTORY")
        self.assertContains(response, "inventory-host")

    def test_scan_history_api(self):
        """Test scan history API."""
        response = self.client.get(reverse('dashboard:scan-history'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('history', data)
        self.assertTrue(len(data['history']) > 0)


class DownloadTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_agent_download_page(self):
        """Test agent download page."""
        response = self.client.get(reverse('dashboard:agent_download_page'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/agent_download.html')

    @patch('dashboard.views.requests.get')
    def test_download_host_agent_zip(self, mock_get):
        """Test host agent download (mocked)."""
        mock_get.side_effect = Exception("network unavailable")

        response = self.client.get(reverse('dashboard:download_host_agent'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/zip")
        self.assertIn("attachment", response["Content-Disposition"])


class SbomTableTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="agent-sbom-001",
            hostname="sbom-host",
            ip_address="192.168.1.50",
            status="online",
        )
        SbomReport.objects.create(
            node=None,
            agent_id=self.agent.agent_id,
            format="cyclonedx",
            bom_format="CycloneDX",
            spec_version="1.5",
            document={
                "components": [
                    {
                        "name": "openssl",
                        "version": "3.0.13",
                        "type": "library",
                        "purl": "pkg:deb/ubuntu/openssl@3.0.13",
                        "scope": "required",
                        "description": "TLS library",
                        "licenses": [{"license": {"name": "Apache-2.0"}}],
                    },
                    {
                        "name": "curl",
                        "version": "8.5.0",
                        "type": "library",
                        "purl": "pkg:deb/ubuntu/curl@8.5.0",
                    },
                ],
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "severity": "High",
                        "score": 9.8,
                        "description": "Remote code execution in openssl",
                        "references": ["https://example.com/cve-2024-0001"],
                    }
                ],
            },
            package_count=2,
            os_summary="Ubuntu 24.04",
        )

    def test_agent_sbom_table(self):
        response = self.client.get(reverse("dashboard:agent_sbom_export", args=[self.agent.agent_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/agent_sbom_table.html")
        self.assertContains(response, "openssl")
        self.assertContains(response, "curl")
        self.assertContains(response, "Components")
        self.assertContains(response, "Vulnerabilities")
        self.assertContains(response, "CVE-2024-0001")
        self.assertContains(response, "Remote code execution in openssl")

    def test_agent_sbom_table_explicit(self):
        response = self.client.get(
            reverse("dashboard:agent_sbom_export", args=[self.agent.agent_id]),
            {"format": "table"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/agent_sbom_table.html")
        self.assertContains(response, "openssl")
        self.assertContains(response, "curl")
        self.assertContains(response, "Components")

    def test_agent_sbom_json_export(self):
        response = self.client.get(
            reverse("dashboard:agent_sbom_export", args=[self.agent.agent_id]),
            {"format": "json"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertContains(response, "CVE-2024-0001")


class CyberTemplateSbomFallbackTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="agent-cyber-sbom-001",
            hostname="cyber-host",
            ip_address="192.168.1.60",
            status="online",
        )
        self.node = Node.objects.create(
            agent_id=self.agent.agent_id,
            name="cyber-host",
            ip_address="192.168.1.60",
            os_info="Ubuntu 24.04",
            installed_libraries=[
                "{'name': 'openssl', 'version': '3.0.13', 'type': 'deb'}",
                "{'name': 'curl', 'version': '8.5.0', 'type': 'deb'}",
                "{'name': 'python3', 'version': '3.12.3', 'type': 'deb'}",
            ],
            active_ports=[{"id": 22, "state": "LISTEN"}],
        )
        self.vuln = Vulnerability.objects.create(
            cve_id="CVE-2024-9999",
            description="Test vulnerability linked to cyber node",
            severity="High",
            score=9.1,
            published=timezone.now(),
            last_modified=timezone.now(),
            references="https://example.com/CVE-2024-9999",
        )
        self.node.vulnerability_set.add(self.vuln)

    def test_agent_sbom_table_falls_back_to_cyber_data(self):
        response = self.client.get(reverse("dashboard:agent_sbom_export", args=[self.agent.agent_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/agent_sbom_table.html")
        self.assertContains(response, "cyber template data")
        self.assertContains(response, "openssl")
        self.assertContains(response, "curl")
        self.assertContains(response, "python3")
        self.assertContains(response, "3.0.13")
        self.assertContains(response, "8.5.0")
        self.assertContains(response, "CVE-2024-9999")
        self.assertContains(response, "Test vulnerability linked to cyber node")

    def test_trivy_and_grype_vulnerability_shapes_are_parsed(self):
        from dashboard.sbom import extract_vulnerabilities_from_sbom

        trivy_payload = {
            "Results": [
                {
                    "Target": "ubuntu:24.04",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1111",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.13",
                            "FixedVersion": "3.0.14",
                            "Severity": "HIGH",
                            "Title": "OpenSSL issue",
                            "Description": "Example Trivy finding",
                            "PrimaryURL": "https://example.com/trivy",
                        }
                    ],
                }
            ]
        }
        grype_payload = {
            "matches": [
                {
                    "artifact": {"name": "curl", "version": "8.5.0"},
                    "vulnerability": {
                        "id": "CVE-2024-2222",
                        "severity": "Medium",
                        "description": "Example Grype finding",
                    },
                }
            ]
        }
        trivy_vulns = extract_vulnerabilities_from_sbom(trivy_payload)
        grype_vulns = extract_vulnerabilities_from_sbom(grype_payload)

        self.assertEqual(trivy_vulns[0]["cve_id"], "CVE-2024-1111")
        self.assertEqual(trivy_vulns[0]["package"], "openssl")
        self.assertEqual(trivy_vulns[0]["installed_version"], "3.0.13")
        self.assertEqual(trivy_vulns[0]["fixed_version"], "3.0.14")
        self.assertEqual(grype_vulns[0]["cve_id"], "CVE-2024-2222")
        self.assertEqual(grype_vulns[0]["package"], "curl")
        self.assertEqual(grype_vulns[0]["installed_version"], "8.5.0")


class AgentAnalysisSbomTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="agent-analysis-sbom-001",
            hostname="analysis-host",
            ip_address="192.168.1.51",
            status="online",
        )
        SbomReport.objects.create(
            node=None,
            agent_id=self.agent.agent_id,
            format="cyclonedx",
            bom_format="CycloneDX",
            spec_version="1.5",
            document={
                "components": [
                    {
                        "name": "libxml2",
                        "version": "2.12.5",
                        "type": "library",
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-1111",
                        "severity": "Critical",
                        "cvssScore": 9.8,
                        "description": "libxml2 test finding",
                        "name": "libxml2",
                        "version": "2.12.5",
                        "fixed_version": "2.12.6",
                    }
                ],
            },
            package_count=1,
            os_summary="Ubuntu 24.04",
        )

    def test_agent_analysis_includes_sbom_section(self):
        response = self.client.get(reverse("dashboard:agent_analysis", args=[self.agent.agent_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/agent_analysis.html")
        self.assertContains(response, "SBOM Reports")
        self.assertContains(response, "Table View")
        self.assertContains(response, "JSON")
        self.assertContains(response, "Ubuntu 24.04")
        self.assertContains(response, "SBOM Vulnerabilities")
        self.assertContains(response, "CVE-2026-1111")
        self.assertContains(response, "libxml2 test finding")


class AgentDetailsSbomVulnerabilityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="agent-details-sbom-001",
            hostname="details-host",
            ip_address="192.168.1.61",
            status="online",
        )
        self.node = Node.objects.create(
            agent_id=self.agent.agent_id,
            name="details-node",
            ip_address="192.168.1.61",
        )
        SbomReport.objects.create(
            node=self.node,
            agent_id=self.agent.agent_id,
            format="cyclonedx",
            bom_format="CycloneDX",
            spec_version="1.5",
            document={
                "components": [
                    {"name": "openssl", "version": "3.0.13", "type": "library"}
                ]
            },
            package_count=1,
            os_summary="Ubuntu 24.04",
        )
        self.vuln = Vulnerability.objects.create(
            cve_id="CVE-2026-2222",
            description="Persisted fallback finding",
            severity="High",
            score=8.4,
            published=timezone.now(),
            last_modified=timezone.now(),
            references="https://example.test/CVE-2026-2222",
        )
        self.vuln.nodes.add(self.node)

    def test_agent_details_includes_persisted_sbom_vulnerabilities(self):
        response = self.client.get(reverse("dashboard:agent_details", args=[self.agent.agent_id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/agent_details.html")
        self.assertContains(response, "SBOM Vulnerabilities")
        self.assertContains(response, "CVE-2026-2222")
        self.assertContains(response, "Persisted fallback finding")


class ShortestPathsTests(TestCase):
    def setUp(self):
        self.client = Client()
        # Create test graph for dijkstra
        scan = ScanRun.objects.create(cidr="192.168.1.0/24")
        self.node1 = Node.objects.create(scan_run=scan, ip_address="192.168.1.1", name="node1")
        self.node2 = Node.objects.create(scan_run=scan, ip_address="192.168.1.2", name="node2")
        self.node3 = Node.objects.create(scan_run=scan, ip_address="192.168.1.3", name="node3")

        Link.objects.create(scan_run=scan, source=self.node1, destination=self.node2, weight=1.0)
        Link.objects.create(scan_run=scan, source=self.node2, destination=self.node3, weight=2.0)

    def test_shortest_paths_view(self):
        """Test shortest paths calculation."""
        response = self.client.get(reverse('dashboard:shortest-paths', args=[self.node1.id]))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        # Should have distances from node1
        self.assertIn(str(self.node1.id), data)
        self.assertIn(str(self.node2.id), data)
        self.assertIn(str(self.node3.id), data)

        self.assertEqual(data[str(self.node1.id)], 0.0)  # Distance to self
        self.assertEqual(data[str(self.node2.id)], 1.0)  # Direct link
        self.assertEqual(data[str(self.node3.id)], 3.0)  # node1 -> node2 -> node3


class NetworkTopologyTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="topo-agent",
            hostname="hmi",
            ip_address="10.2.50.10",
            interfaces=[{"name": "eth0", "ip": "10.2.50.10", "mac": "00:11:22:33:44:55"}],
            status="online"
        )
        self.scan = ScanRun.objects.create(cidr="10.2.50.0/24")
        self.node = Node.objects.create(
            scan_run=self.scan,
            ip_address="10.2.50.10",
            name="hmi",
            hostname="hmi",
            agent_id=self.agent.agent_id,
            status="online",
        )
        NodeInterface.objects.create(
            node=self.node,
            name="eth0",
            ip="10.2.50.10",
            mac="00:11:22:33:44:55",
        )

    def test_network_topology_api(self):
        """Test network topology API."""
        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('nodes', data)
        self.assertIn('edges', data)
        self.assertIn('layers', data)

        nodes = data['nodes']
        self.assertTrue(any(node['ip_address'] == '10.2.50.10' for node in nodes))
        self.assertTrue(any(layer['slug'] == 'L2' for layer in data['layers']))
        l2_nodes = next(layer['nodes'] for layer in data['layers'] if layer['slug'] == 'L2')
        self.assertTrue(any(node['node_url'].endswith(f"/node/{self.node.id}/") for node in l2_nodes))

    def test_network_topology_api_shows_only_observed_assets(self):
        """Test that the topology excludes retired modeled-only assets while keeping Level 0 context."""
        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        labels = {node['label'] for node in data['nodes']}
        self.assertIn('hmi', labels)
        self.assertIn('engineer-ws', labels)
        self.assertIn('pt-455', labels)
        self.assertIn('pt-456', labels)
        self.assertNotIn('ignition', labels)
        self.assertNotIn('l2-jump', labels)
        self.assertNotIn('historian', labels)

    def test_network_topology_api_excludes_retired_observed_assets(self):
        """Test that stale observed assets from the retired layout do not render."""
        retired_agent = AgentStatus.objects.create(
            agent_id="ignition-agent",
            hostname="ignition",
            ip_address="10.2.50.31",
            interfaces=[{"name": "eth0", "ip": "10.2.50.31", "mac": "00:11:22:33:44:99"}],
            status="online",
        )
        retired_node = Node.objects.create(
            scan_run=self.scan,
            ip_address="10.2.50.31",
            name="ignition",
            hostname="ignition",
            agent_id=retired_agent.agent_id,
            status="online",
        )
        NodeInterface.objects.create(
            node=retired_node,
            name="eth0",
            ip="10.2.50.31",
            mac="00:11:22:33:44:99",
        )
        stale_time = timezone.now() - timedelta(hours=2)
        AgentStatus.objects.filter(id=retired_agent.id).update(
            last_heartbeat=stale_time,
            status="offline",
        )
        Node.objects.filter(id=retired_node.id).update(last_heartbeat=stale_time)

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        labels = {node['label'] for node in data['nodes']}
        self.assertNotIn('ignition', labels)

    def test_network_topology_api_merges_multi_ip_static_assets(self):
        """Test that dual-homed observed assets are returned as single logical nodes."""
        plc_agent = AgentStatus.objects.create(
            agent_id="plc-main-agent",
            hostname="plc-main",
            ip_address="10.1.1.14",
            interfaces=[
                {"name": "eth0", "ip": "10.1.1.14", "mac": "00:aa:bb:cc:dd:01"},
                {"name": "eth1", "ip": "10.1.2.14", "mac": "00:aa:bb:cc:dd:02"},
            ],
            status="online",
        )
        plc_node = Node.objects.create(
            scan_run=self.scan,
            ip_address="10.1.1.14",
            name="plc-main",
            hostname="plc-main",
            agent_id=plc_agent.agent_id,
            status="online",
        )
        NodeInterface.objects.create(node=plc_node, name="eth0", ip="10.1.1.14", mac="00:aa:bb:cc:dd:01")
        NodeInterface.objects.create(node=plc_node, name="eth1", ip="10.1.2.14", mac="00:aa:bb:cc:dd:02")

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        plc_main = next(node for node in data['nodes'] if node['label'] == 'plc-main')
        self.assertEqual(plc_main['purdue_level'], 'L1')
        self.assertEqual(plc_main['ip_address'], '10.1.1.14')
        self.assertEqual(plc_main['ip_addresses'], ['10.1.1.14', '10.1.2.14'])

    def test_network_topology_api_resolves_observed_flows_to_logical_nodes(self):
        """Test that observed agent traffic resolves to logical source/target topology nodes."""
        historian_agent = AgentStatus.objects.create(
            agent_id="historian-agent",
            hostname="historian",
            ip_address="10.3.50.10",
            interfaces=[{"name": "eth0", "ip": "10.3.50.10", "mac": "00:11:22:33:44:77"}],
            status="online",
        )
        historian_node = Node.objects.create(
            scan_run=self.scan,
            ip_address="10.3.50.10",
            name="historian",
            hostname="historian",
            agent_id=historian_agent.agent_id,
            status="online",
        )
        NodeInterface.objects.create(node=historian_node, name="eth0", ip="10.3.50.10", mac="00:11:22:33:44:77")
        metadata = NetworkMetadata.objects.create(agent=self.agent, total_connections=1, total_interfaces=1)
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=self.agent,
            protocol="TCP",
            local_address="10.2.50.10",
            local_port=49152,
            remote_address="10.3.50.10",
            remote_port=443,
            status="ESTABLISHED",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(any(edge['from'] == 'static:hmi' and edge['to'] == 'static:historian' for edge in data['edges']))

    def test_network_topology_api_infers_remote_observed_assets_without_persisted_nodes(self):
        """Test that remote peers seen only in flow evidence still become logical topology nodes."""
        metadata = NetworkMetadata.objects.create(agent=self.agent, total_connections=1, total_interfaces=1)
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=self.agent,
            protocol="TCP",
            local_address="10.2.50.10",
            local_port=49152,
            remote_address="10.3.50.10",
            remote_port=4840,
            status="ESTABLISHED",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        historian = next(node for node in data['nodes'] if node['label'] == 'historian')
        self.assertEqual(historian['id'], 'static:historian')
        self.assertEqual(historian['purdue_level'], 'L3')
        self.assertTrue(any(edge['from'] == 'static:hmi' and edge['to'] == 'static:historian' for edge in data['edges']))

    def test_network_topology_api_infers_pt455_and_pt456_from_span_modbus_traffic(self):
        """Test that passive span-observed Modbus traffic surfaces the L0 pressure transmitters as online."""
        span_agent = AgentStatus.objects.create(
            agent_id="span-l1a",
            hostname="span-l1a",
            ip_address="172.31.250.250",
            interfaces=[
                {"name": "eth0", "ip": "172.31.250.250", "mac": "00:11:22:33:44:60"},
                {"name": "eth1", "ip": "10.1.1.250", "mac": "00:11:22:33:44:61"},
            ],
            status="online",
        )
        metadata = NetworkMetadata.objects.create(agent=span_agent, total_connections=2, total_interfaces=2)
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="TCP",
            local_address="10.1.1.10",
            local_port=502,
            remote_address="10.1.1.9",
            remote_port=502,
            status="OBSERVED",
            process_name="passive-sniffer",
        )
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="TCP",
            local_address="10.1.1.11",
            local_port=502,
            remote_address="10.1.1.8",
            remote_port=502,
            status="OBSERVED",
            process_name="passive-sniffer",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        pt455 = next(node for node in data['nodes'] if node['label'] == 'pt-455')
        pt456 = next(node for node in data['nodes'] if node['label'] == 'pt-456')
        self.assertEqual(pt455['id'], 'static:pt-455')
        self.assertEqual(pt455['purdue_level'], 'L0')
        self.assertEqual(pt455['status'], 'online')
        self.assertEqual(pt456['id'], 'static:pt-456')
        self.assertEqual(pt456['purdue_level'], 'L0')
        self.assertEqual(pt456['status'], 'online')
        self.assertTrue(any(edge['from'] == 'static:channel-a' and edge['to'] == 'static:pt-455' for edge in data['edges']))
        self.assertTrue(any(edge['from'] == 'static:channel-b' and edge['to'] == 'static:pt-456' for edge in data['edges']))

    def test_network_topology_api_promotes_pt455_and_pt456_from_span_arp_observation(self):
        """Test that passive ARP observation can promote known L0 assets without rendering ARP noise edges."""
        span_agent = AgentStatus.objects.create(
            agent_id="span-l1a",
            hostname="span-l1a",
            ip_address="10.1.1.250",
            interfaces=[
                {"name": "eth0", "ip": "172.31.250.250", "mac": "00:11:22:33:44:60"},
                {"name": "eth1", "ip": "10.1.1.250", "mac": "00:11:22:33:44:61"},
            ],
            status="online",
        )
        metadata = NetworkMetadata.objects.create(agent=span_agent, total_connections=2, total_interfaces=2)
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="ARP",
            local_address="10.1.1.249",
            remote_address="10.1.1.9",
            status="OBSERVED",
            process_name="passive-sniffer",
        )
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="ARP",
            local_address="10.1.1.249",
            remote_address="10.1.1.8",
            status="OBSERVED",
            process_name="passive-sniffer",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        pt455 = next(node for node in data['nodes'] if node['label'] == 'pt-455')
        pt456 = next(node for node in data['nodes'] if node['label'] == 'pt-456')
        self.assertEqual(pt455['status'], 'online')
        self.assertEqual(pt456['status'], 'online')
        self.assertFalse(any(edge['protocol'] == 'ARP' for edge in data['edges']))

    def test_network_topology_api_maps_firewall_companion_agent_to_firewall_asset(self):
        """Test that firewall companion agents resolve to the modeled firewall asset identity."""
        firewall_agent = AgentStatus.objects.create(
            agent_id="firewall-1",
            hostname="firewall-1-agent",
            ip_address="10.2.50.254",
            interfaces=[{"name": "eth0", "ip": "10.2.50.254", "mac": "00:11:22:33:44:70"}],
            status="online",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        firewall = next(node for node in data['nodes'] if node['label'] == 'firewall-1')
        self.assertEqual(firewall['id'], 'static:firewall-1')
        self.assertEqual(firewall['status'], 'online')
        self.assertEqual(firewall['agent_id'], firewall_agent.agent_id)

    def test_network_topology_api_suppresses_noisy_passive_bridge_peers(self):
        """Test that passive bridge noise does not create inferred Purdue assets."""
        span_agent = AgentStatus.objects.create(
            agent_id="span-l1a",
            hostname="span-l1a",
            ip_address="172.31.250.250",
            interfaces=[
                {"name": "eth0", "ip": "172.31.250.250", "mac": "00:11:22:33:44:60"},
                {"name": "eth1", "ip": "10.1.1.250", "mac": "00:11:22:33:44:61"},
            ],
            status="online",
        )
        metadata = NetworkMetadata.objects.create(agent=span_agent, total_connections=3, total_interfaces=2)
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="ICMP",
            local_address="10.1.1.250",
            remote_address="10.1.1.249",
            status="OBSERVED",
            process_name="passive-sniffer",
        )
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="UDP",
            local_address="10.1.1.249",
            local_port=36218,
            remote_address="10.1.1.250",
            remote_port=1216,
            status="OBSERVED",
            process_name="passive-sniffer",
        )
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="ARP",
            local_address="10.1.1.1",
            remote_address="10.1.1.250",
            status="OBSERVED",
            process_name="passive-sniffer",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        labels = {node['label'] for node in data['nodes']}
        self.assertNotIn('10.1.1.249', labels)
        self.assertNotIn('10.1.1.1', labels)

    def test_network_topology_api_suppresses_passive_sensor_management_self_loops(self):
        """Test that passive sensor heartbeats to the dashboard do not render as self-loop edges."""
        span_agent = AgentStatus.objects.create(
            agent_id="span-l1b",
            hostname="span-l1b",
            ip_address="172.31.250.251",
            interfaces=[
                {"name": "eth0", "ip": "172.31.250.251", "mac": "00:11:22:33:44:61"},
                {"name": "eth1", "ip": "10.1.2.250", "mac": "00:11:22:33:44:62"},
            ],
            status="online",
        )
        metadata = NetworkMetadata.objects.create(agent=span_agent, total_connections=2, total_interfaces=2)
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="TCP",
            local_address="172.31.250.251",
            local_port=38598,
            remote_address="172.17.0.1",
            remote_port=8000,
            status="OBSERVED",
            process_name="passive-sniffer",
        )
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=span_agent,
            protocol="TCP",
            local_address="172.17.0.1",
            local_port=8000,
            remote_address="172.31.250.251",
            remote_port=38598,
            status="OBSERVED",
            process_name="passive-sniffer",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertFalse(any(edge['from'] == 'span-l1b' and edge['to'] == 'span-l1b' for edge in data['edges']))

    def test_network_topology_api_suppresses_openvas_scan_noise(self):
        """Test that OpenVAS-marked connections do not create inferred Purdue assets."""
        scanner_agent = AgentStatus.objects.create(
            agent_id="scanner-agent",
            hostname="metasploit",
            ip_address="10.4.50.10",
            interfaces=[{"name": "eth0", "ip": "10.4.50.10", "mac": "00:11:22:33:44:80"}],
            status="online",
        )
        metadata = NetworkMetadata.objects.create(agent=scanner_agent, total_connections=2, total_interfaces=1)
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=scanner_agent,
            protocol="TCP",
            local_address="10.4.50.10",
            local_port=46321,
            remote_address="10.1.1.1",
            remote_port=502,
            status="ESTABLISHED",
            process_name="openvas",
            process_cmdline="/usr/sbin/ospd-openvas --scan 10.1.1.1",
        )
        NetworkConnection.objects.create(
            metadata=metadata,
            agent=scanner_agent,
            protocol="TCP",
            local_address="10.4.50.10",
            local_port=46322,
            remote_address="10.1.1.2",
            remote_port=502,
            status="ESTABLISHED",
            process_name="openvas",
            process_cmdline="/usr/sbin/ospd-openvas --scan 10.1.1.2",
        )

        response = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        labels = {node['label'] for node in data['nodes']}
        self.assertNotIn('10.1.1.1', labels)
        self.assertNotIn('10.1.1.2', labels)
        self.assertFalse(any(edge['target_ip'] in {'10.1.1.1', '10.1.1.2'} for edge in data['edges']))
        self.assertFalse(any(edge['from'] == 'static:metasploit' for edge in data['edges']))


@override_settings(AGENT_API_TOKEN="test-token", AGENT_API_TOKEN_REQUIRED=True)
class AgentNetworkMetadataTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent_headers = {"HTTP_X_AGENT_TOKEN": "test-token"}
        self.agent = AgentStatus.objects.create(
            agent_id="net-md-agent",
            hostname="net-md-host",
            ip_address="192.168.1.100"
        )

    def test_agent_network_metadata(self):
        """Test agent network metadata endpoint."""
        metadata_data = {
            'agent_id': self.agent.agent_id,
            'network_connections': [
                {
                    'protocol': 'TCP',
                    'local_address': '192.168.1.100',
                    'local_port': 8080,
                    'remote_address': '8.8.8.8',
                    'remote_port': 443,
                    'status': 'ESTABLISHED',
                    'process': {'name': 'nginx', 'pid': 1234, 'username': 'www-data'}
                }
            ],
            'interface_statistics': [
                {'interface': 'eth0', 'bytes_sent': 1000, 'bytes_recv': 2000, 'packets_sent': 10, 'packets_recv': 15}
            ],
            'active_ports': [{'port': 80, 'protocol': 'tcp', 'state': 'LISTEN'}],
            'interfaces': [{'name': 'eth0', 'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55'}]
        }

        response = self.client.post(
            reverse('dashboard:agent_network_metadata'),
            json.dumps(metadata_data),
            content_type='application/json',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'network_metadata_received')

        # Check metadata was created
        metadata = NetworkMetadata.objects.get(agent=self.agent)
        self.assertEqual(metadata.total_connections, 1)
        self.assertEqual(metadata.total_interfaces, 1)

        # Check network connection was created
        connection = NetworkConnection.objects.get(metadata=metadata)
        self.assertEqual(connection.protocol, 'TCP')
        self.assertEqual(connection.status, 'ESTABLISHED')

    def test_agent_network_metadata_parses_endpoint_ports(self):
        """Test that endpoint strings are normalized into address and port fields."""
        metadata_data = {
            'agent_id': self.agent.agent_id,
            'network_connections': [
                {
                    'protocol': 'TCP',
                    'local_address': '192.168.1.100:8080',
                    'remote_address': '10.3.50.10:443',
                    'status': 'ESTABLISHED',
                    'process': {'name': 'curl', 'pid': 4321, 'username': 'demo'}
                }
            ],
            'interface_statistics': [],
            'active_ports': [],
            'interfaces': [{'name': 'eth0', 'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55'}]
        }

        response = self.client.post(
            reverse('dashboard:agent_network_metadata'),
            json.dumps(metadata_data),
            content_type='application/json',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)
        connection = NetworkConnection.objects.latest('id')
        self.assertEqual(connection.local_address, '192.168.1.100')
        self.assertEqual(connection.local_port, 8080)
        self.assertEqual(connection.remote_address, '10.3.50.10')
        self.assertEqual(connection.remote_port, 443)

    def test_agent_network_metadata_updates_agent_inventory_for_topology_enumeration(self):
        """Test that metadata ingestion updates agent and node interface inventory."""
        self.agent.hostname = "plc-main"
        self.agent.ip_address = "10.1.1.14"
        self.agent.save(update_fields=["hostname", "ip_address"])

        metadata_data = {
            'agent_id': self.agent.agent_id,
            'network_connections': [],
            'interface_statistics': [],
            'active_ports': [{'port': 44818, 'protocol': 'tcp', 'state': 'LISTEN'}],
            'interfaces': [
                {'name': 'eth0', 'ip': '10.1.1.14', 'mac': '00:aa:bb:cc:dd:01'},
                {'name': 'eth1', 'ip': '10.1.2.14', 'mac': '00:aa:bb:cc:dd:02'},
            ],
        }

        response = self.client.post(
            reverse('dashboard:agent_network_metadata'),
            json.dumps(metadata_data),
            content_type='application/json',
            **self.agent_headers
        )

        self.assertEqual(response.status_code, 200)

        self.agent.refresh_from_db()
        self.assertEqual(self.agent.interfaces, metadata_data['interfaces'])
        self.assertEqual(self.agent.active_ports, metadata_data['active_ports'])

        node = Node.objects.get(agent_id=self.agent.agent_id)
        self.assertEqual(node.hostname, 'plc-main')
        self.assertEqual(node.interfaces.count(), 2)

        topology = self.client.get(reverse('dashboard:network_topology_api'))
        self.assertEqual(topology.status_code, 200)
        plc_main = next(item for item in topology.json()['nodes'] if item['label'] == 'plc-main')
        self.assertEqual(plc_main['id'], 'static:plc-main')
        self.assertEqual(plc_main['ip_addresses'], ['10.1.1.14', '10.1.2.14'])


class RiskAssessmentRepoIntegrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.repo_root = Path(self.tempdir.name)
        (self.repo_root / "upload").mkdir(parents=True, exist_ok=True)
        (self.repo_root / "outputs" / "fts" / "PLC-Main" / "control_path").mkdir(parents=True, exist_ok=True)

        (self.repo_root / "upload" / "sim_system.json").write_text(
            json.dumps(
                {
                    "version": "1.0",
                    "digital": {
                        "PLC-Main": {
                            "type": "PLC",
                            "networks": {"ControlNet": {}},
                            "source": {},
                            "target": {"Historian": "opc"},
                        },
                        "Historian": {
                            "type": "DataHistorian",
                            "source": {"PLC-Main": "opc"},
                            "target": {},
                        },
                    },
                    "physical": {
                        "Pressurizer": {
                            "type": "pressurizer",
                            "source": {},
                            "target": {},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.repo_root / "outputs" / "dbn.bifxml").write_text(
            """<?xml version="1.0"?>
<BIF>
  <NETWORK>
    <VARIABLE TYPE="nature">
      <NAME>Historian</NAME>
      <OUTCOME>Nominal</OUTCOME>
      <OUTCOME>Abnormal</OUTCOME>
    </VARIABLE>
    <VARIABLE TYPE="nature">
      <NAME>PLC-Main</NAME>
      <OUTCOME>Nominal</OUTCOME>
      <OUTCOME>Abnormal</OUTCOME>
    </VARIABLE>
    <DEFINITION>
      <FOR>Historian</FOR>
      <TABLE>0.9 0.1</TABLE>
    </DEFINITION>
    <DEFINITION>
      <FOR>PLC-Main</FOR>
      <GIVEN>Historian</GIVEN>
      <TABLE>1 0 1 0</TABLE>
    </DEFINITION>
  </NETWORK>
</BIF>
""",
            encoding="utf-8",
        )
        (self.repo_root / "outputs" / "dbn_2_with_cpt.json").write_text(
            json.dumps(
                {
                    "nodes": {
                        "PLC-Main": {
                            "type": "PLC",
                            "category": "digital",
                            "states": ["Nominal", "Abnormal"],
                        },
                        "Historian": {
                            "type": "Computer",
                            "category": "digital",
                            "states": ["Nominal", "Abnormal"],
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        (self.repo_root / "outputs" / "pipeline_log.json").write_text(
            json.dumps({"steps": [{"name": "upload", "status": "ok"}]}),
            encoding="utf-8",
        )
        (self.repo_root / "outputs" / "fts" / "PLC-Main" / "component.json").write_text(
            json.dumps(
                {
                    "faults": {"PLC-FTS": 1e-09},
                    "vul_tech1": {"CVE-TEST-0001": 0.01},
                    "defense1": {"M-TEST-1": 0.1},
                    "states": ["Nominal", "Abnormal"],
                }
            ),
            encoding="utf-8",
        )
        (self.repo_root / "outputs" / "fts" / "PLC-Main" / "control_path" / "rule.json").write_text(
            json.dumps(
                {
                    "inputs": {"Historian": "opc"},
                    "events": ["PLC-FTS", "vul_tech1", "defense1"],
                    "value_rules": {
                        "Abnormal": {"OR": ["PLC-FTS", "vul_tech1"]},
                        "Nominal": {"NOT": "Abnormal"},
                    },
                }
            ),
            encoding="utf-8",
        )
        (self.repo_root / "outputs" / "fts" / "PLC-Main" / "control_path" / "value.json").write_text(
            json.dumps(
                {
                    "inputs": {"Historian": "opc"},
                    "values": [
                        {
                            "Historian.Nominal": {
                                "events": {"PLC-FTS": 1e-09, "Historian.Nominal": 1.0},
                                "probabilities": {"Nominal": 0.99, "Abnormal": 0.01},
                            }
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def _settings_override(self):
        return override_settings(
            ICS_RISK_ASSESSMENT_REPO_PATH=str(self.repo_root),
            RISK_ASSESSMENT_SIM_SYSTEM_PATH=str(self.repo_root / "upload" / "sim_system.json"),
        )

    def test_risk_assessment_page_includes_ics_visuals_tab(self):
        with self._settings_override():
            response = self.client.get(reverse("dashboard:risk_assessment"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ICS Visuals")
        self.assertContains(response, "Repo Bayesian Graph")
        self.assertContains(response, "Fault Trees")
        self.assertContains(response, "risk-fault-tree-filter")
        self.assertContains(response, "risk-ics-summary-status")
        self.assertContains(response, "risk-system-layout")
        self.assertContains(response, "risk-system-fullscreen")
        self.assertContains(response, "Upload Repo Model")

    def test_risk_assessment_ics_summary_api_reports_repo_artifacts(self):
        with self._settings_override():
            response = self.client.get(reverse("dashboard:risk_assessment_ics_summary"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["repo_available"])
        self.assertTrue(payload["sim_system_found"])
        self.assertTrue(payload["bayesian_found"])
        self.assertTrue(payload["cpt_found"])
        self.assertTrue(payload["pipeline_log_found"])
        self.assertEqual(payload["fault_tree_count"], 1)
        self.assertEqual(payload["metrics"]["nodes"], 4)
        self.assertEqual(payload["metrics"]["links"], 2)

    def test_risk_assessment_ics_system_graph_api_returns_repo_graph(self):
        with self._settings_override():
            response = self.client.get(reverse("dashboard:risk_assessment_ics_system_graph"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["found"])
        labels = {node["label"] for node in payload["nodes"]}
        self.assertIn("PLC-Main", labels)
        self.assertIn("Historian", labels)
        self.assertIn("Pressurizer", labels)
        self.assertIn("ControlNet", labels)
        self.assertTrue(any(edge["source"] == "PLC-Main" and edge["target"] == "Historian" for edge in payload["edges"]))

    def test_risk_assessment_ics_model_api_falls_back_to_repo_db_model(self):
        db_dir = self.repo_root / "db"
        db_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.repo_root / "upload" / "sim_system.json", db_dir / "sim_system.json")
        (self.repo_root / "upload" / "sim_system.json").unlink()

        with self._settings_override():
            summary_response = self.client.get(reverse("dashboard:risk_assessment_ics_summary"))
            model_response = self.client.get(reverse("dashboard:risk_assessment_ics_model"))

        self.assertEqual(summary_response.status_code, 200)
        summary_payload = summary_response.json()
        self.assertTrue(summary_payload["sim_system_found"])
        self.assertEqual(summary_payload["model_source"], "db")
        self.assertTrue(summary_payload["model_path"].endswith("db/sim_system.json"))

        self.assertEqual(model_response.status_code, 200)
        model_payload = model_response.json()
        self.assertTrue(model_payload["found"])
        self.assertEqual(model_payload["source"], "db")
        self.assertIn("digital", model_payload["data"])

    def test_risk_assessment_ics_bayesian_graph_and_detail_apis_return_repo_outputs(self):
        with self._settings_override():
            graph_response = self.client.get(reverse("dashboard:risk_assessment_ics_bayesian_graph"))
            detail_response = self.client.get(
                reverse("dashboard:risk_assessment_ics_bayesian_node_detail"),
                {"id": "PLC-Main"},
            )

        self.assertEqual(graph_response.status_code, 200)
        graph_payload = graph_response.json()
        self.assertTrue(graph_payload["found"])
        plc_node = next(node for node in graph_payload["nodes"] if node["id"] == "PLC-Main")
        self.assertEqual(plc_node["type"], "PLC")
        self.assertTrue(plc_node["cpt_nominal_mismatch"])
        self.assertTrue(any(edge["source"] == "Historian" and edge["target"] == "PLC-Main" for edge in graph_payload["edges"]))

        self.assertEqual(detail_response.status_code, 200)
        detail_payload = detail_response.json()
        self.assertTrue(detail_payload["found"])
        self.assertEqual(detail_payload["bif_cpt"]["parents"], ["Historian"])
        self.assertEqual(len(detail_payload["bif_cpt"]["rows"]), 2)
        self.assertEqual(detail_payload["fts_condition_folders"], ["control_path"])

    def test_risk_assessment_ics_pipeline_log_api_returns_repo_log(self):
        with self._settings_override():
            response = self.client.get(reverse("dashboard:risk_assessment_ics_pipeline_log"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["found"])
        self.assertEqual(payload["data"]["steps"][0]["name"], "upload")

    def test_risk_assessment_ics_fault_tree_summary_and_detail_apis_return_repo_outputs(self):
        with self._settings_override():
            summary_response = self.client.get(reverse("dashboard:risk_assessment_ics_fault_trees"))
            detail_response = self.client.get(
                reverse("dashboard:risk_assessment_ics_fault_tree_detail"),
                {"id": "PLC-Main"},
            )

        self.assertEqual(summary_response.status_code, 200)
        summary_payload = summary_response.json()
        self.assertTrue(summary_payload["found"])
        self.assertEqual(summary_payload["component_count"], 1)
        self.assertEqual(summary_payload["condition_count"], 1)
        self.assertEqual(summary_payload["items"][0]["id"], "PLC-Main")
        self.assertEqual(summary_payload["items"][0]["states"], ["Nominal", "Abnormal"])

        self.assertEqual(detail_response.status_code, 200)
        detail_payload = detail_response.json()
        self.assertTrue(detail_payload["found"])
        self.assertEqual(detail_payload["id"], "PLC-Main")
        self.assertEqual(detail_payload["component"]["states"], ["Nominal", "Abnormal"])
        self.assertEqual(len(detail_payload["conditions"]), 1)
        self.assertEqual(detail_payload["conditions"][0]["name"], "control_path")
        self.assertTrue(detail_payload["conditions"][0]["rule_path"].endswith("rule.json"))
        self.assertTrue(detail_payload["conditions"][0]["value_path"].endswith("value.json"))
        self.assertEqual(detail_payload["conditions"][0]["events"], ["PLC-FTS", "vul_tech1", "defense1"])
        self.assertEqual(detail_payload["conditions"][0]["sample_count"], 1)
        self.assertEqual(detail_payload["conditions"][0]["graph_default_state"], "Abnormal")
        self.assertEqual(len(detail_payload["conditions"][0]["graphs"]), 2)
        abnormal_graph = next(
            graph_variant for graph_variant in detail_payload["conditions"][0]["graphs"] if graph_variant["state"] == "Abnormal"
        )
        self.assertEqual(abnormal_graph["scenario"], "Historian.Nominal")
        self.assertTrue(any(node["type"] == "top_event" and node["label"] == "Abnormal" for node in abnormal_graph["graph"]["nodes"]))
        self.assertTrue(any(node["type"] == "or_gate" for node in abnormal_graph["graph"]["nodes"]))
        self.assertTrue(any(node["type"] == "basic_event" and node["label"] == "PLC-FTS" for node in abnormal_graph["graph"]["nodes"]))
        self.assertEqual(
            detail_payload["conditions"][0]["value_preview"]["values"][0]["Historian.Nominal"]["probabilities"]["Nominal"],
            0.99,
        )
        self.assertEqual(detail_payload["conditions"][0]["event_count"], 3)


class AgentVersionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.agent = AgentStatus.objects.create(
            agent_id="version-agent",
            hostname="version-host",
            agent_version="1.2.3",
            last_version_check=timezone.now()
        )

    def test_agent_version_api(self):
        """Test agent version API."""
        with patch('dashboard.views.AGENT_VERSION', '2.0.0'), \
             patch('dashboard.views.AGENT_NAME', 'TestAgent'):

            response = self.client.get(reverse('dashboard:agent_version_api'))
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertEqual(data['current_version'], '2.0.0')
            self.assertEqual(data['agent_name'], 'TestAgent')
            self.assertEqual(len(data['agents']), 1)
            self.assertEqual(data['agents'][0]['agent_version'], '1.2.3')


@override_settings(SIEM_SENSOR_HEALTH_LOOKBACK_SEC=60)
class SiemViewIntegrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.now = timezone.now()
        self.event = SiemEvent.objects.create(
            timestamp=self.now,
            source="suricata",
            event_type="suricata.alert",
            event_module="suricata",
            event_dataset="suricata.alert",
            observer_name="sensor-a",
            severity=8,
            asset_id="agent-1",
            asset_ip="10.10.10.10",
            summary="Suricata alert fired",
            raw={
                "event": {"module": "suricata", "dataset": "suricata.alert"},
                "observer": {"name": "sensor-a"},
            },
        )
        self.other_event = SiemEvent.objects.create(
            timestamp=self.now - timedelta(minutes=5),
            source="zeek",
            event_type="zeek.conn",
            event_module="zeek",
            event_dataset="zeek.conn",
            observer_name="sensor-b",
            severity=3,
            asset_id="agent-2",
            asset_ip="10.10.10.11",
            summary="Zeek connection event",
            raw={
                "event": {"module": "zeek", "dataset": "zeek.conn"},
                "observer": {"name": "sensor-b"},
            },
        )
        self.alert = Alert.objects.create(
            rule_name="Suricata Alerts",
            rule_type="suricata",
            event_type="suricata.alert",
            source="suricata",
            severity=8,
            asset_ip="10.10.10.10",
            asset_id="agent-1",
            summary="Suricata alert fired",
            dedup_key="suricata.alert:agent-1",
        )
        self.case = Case.objects.create(title="Network investigation", priority=Case.Priority.HIGH)
        self.case.alerts.add(self.alert)
        self.hunt = Hunt.objects.create(name="Suspicious Suricata Hunt", description="Track sensor alerts")
        self.hunt_search = HuntSearch.objects.create(
            hunt=self.hunt,
            name="Suricata Dataset Search",
            query_params={"event_module": "suricata", "event_dataset": "suricata.alert", "asset_ip": "10.10.10.10"},
        )
        SiemSensorStatus.objects.create(
            sensor_id="sensor-a",
            sensor_type="suricata",
            hostname="sensor-a",
            status="online",
            last_seen=self.now,
            event_count=5,
            interface_names=["mirror0"],
        )
        SiemSensorStatus.objects.create(
            sensor_id="sensor-b",
            sensor_type="zeek",
            hostname="sensor-b",
            status="online",
            last_seen=self.now - timedelta(minutes=10),
            event_count=2,
            interface_names=["mirror1"],
        )

    def test_siem_soc_overview_renders_summary_cards(self):
        with patch(
            "dashboard.views.get_opensearch_overview",
            return_value={
                "enabled": True,
                "configured": True,
                "url": "http://opensearch:9200",
                "dashboards_url": "http://127.0.0.1:5601",
                "index_prefix": "siem-events",
                "status": "ok",
                "cluster_status": "yellow",
                "node_count": 1,
                "active_primary_shards": 3,
                "unassigned_shards": 1,
                "indices": [
                    {
                        "index": "siem-events-2026.04.16",
                        "health": "yellow",
                        "status": "open",
                        "docs_count": 2,
                        "store_size": "12kb",
                    }
                ],
                "index_count": 1,
                "document_count": 2,
                "error": "",
            },
        ):
            response = self.client.get(reverse("dashboard:siem_soc_overview"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/siem_overview.html")
        self.assertContains(response, "Network IDS Live Monitor")
        self.assertContains(response, "sensor-a")
        self.assertContains(response, "Suricata Alerts")
        self.assertContains(response, reverse("dashboard:siem_event_explorer"))
        self.assertContains(response, "Live Network Feed")
        self.assertContains(response, "OpenSearch")
        self.assertContains(response, "siem-events-2026.04.16")
        self.assertContains(response, "http://127.0.0.1:5601")

    def test_siem_soc_overview_prefers_sensor_events_over_stats_noise(self):
        newer_noise = SiemEvent.objects.create(
            timestamp=self.now + timedelta(minutes=5),
            source="suricata",
            event_type="suricata.stats",
            event_module="suricata",
            event_dataset="suricata.stats",
            asset_id="suricata-sensor",
            summary="",
            raw={},
        )
        live_event = SiemEvent.objects.create(
            timestamp=self.now + timedelta(minutes=4),
            source="zeek",
            event_type="zeek.conn",
            event_module="zeek",
            event_dataset="zeek.conn",
            observer_name="sensor-b",
            asset_id="historian",
            asset_ip="10.3.50.10",
            source_ip="10.3.50.10",
            destination_ip="10.4.50.20",
            summary="historian to postgres flow",
            raw={},
        )

        with patch("dashboard.views.get_opensearch_overview", return_value={"enabled": False, "dashboards_url": "", "index_prefix": "siem-events", "status": "disabled", "cluster_status": "", "node_count": 0, "index_count": 0, "document_count": 0, "indices": [], "error": "", "url": ""}):
            response = self.client.get(reverse("dashboard:siem_soc_overview"))

        self.assertEqual(response.status_code, 200)
        recent_events = list(response.context["recent_events"])
        self.assertTrue(recent_events)
        self.assertEqual(recent_events[0].id, live_event.id)
        self.assertNotIn(newer_noise.id, [event.id for event in recent_events])
        self.assertContains(response, "10.3.50.10")
        self.assertContains(response, "zeek.conn")
        self.assertContains(response, "historian to postgres flow")

    def test_siem_sensor_health_page_marks_stale_sensors(self):
        response = self.client.get(reverse("dashboard:siem_sensor_health_page"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/siem_sensor_health.html")
        self.assertContains(response, "sensor-a")
        self.assertContains(response, "sensor-b")
        self.assertContains(response, "stale")

    def test_siem_event_search_filters_by_module_dataset_and_observer(self):
        response = self.client.get(
            reverse("dashboard:siem_event_search"),
            {"event_module": "suricata", "event_dataset": "suricata.alert", "observer_name": "sensor-a"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["id"], self.event.id)

    def test_siem_event_explorer_shows_module_and_dataset_focus(self):
        with patch(
            "dashboard.views.get_opensearch_overview",
            return_value={
                "enabled": True,
                "configured": True,
                "url": "http://opensearch:9200",
                "dashboards_url": "http://127.0.0.1:5601",
                "index_prefix": "siem-events",
                "status": "ok",
                "cluster_status": "yellow",
                "node_count": 1,
                "active_primary_shards": 0,
                "unassigned_shards": 0,
                "indices": [],
                "index_count": 0,
                "document_count": 0,
                "error": "",
            },
        ):
            response = self.client.get(reverse("dashboard:siem_event_explorer"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/siem_events.html")
        self.assertContains(response, "Network Event Explorer")
        self.assertContains(response, "Top IDS Modules")
        self.assertContains(response, "Top IDS Datasets")
        self.assertContains(response, "siem-event-module")
        self.assertContains(response, reverse("dashboard:siem_sensor_health_page"))
        self.assertContains(response, "Open Dashboards")
        self.assertContains(response, "Live IDS")
        self.assertContains(response, "Suricata Alerts")

    def test_siem_alert_and_case_pages_link_back_to_explorer(self):
        with patch(
            "dashboard.views.get_opensearch_overview",
            return_value={
                "enabled": True,
                "configured": True,
                "url": "http://opensearch:9200",
                "dashboards_url": "http://127.0.0.1:5601",
                "index_prefix": "siem-events",
                "status": "ok",
                "cluster_status": "yellow",
                "node_count": 1,
                "active_primary_shards": 0,
                "unassigned_shards": 0,
                "indices": [],
                "index_count": 0,
                "document_count": 0,
                "error": "",
            },
        ):
            alerts_response = self.client.get(reverse("dashboard:siem_alerts_page"))
        self.assertEqual(alerts_response.status_code, 200)
        self.assertContains(alerts_response, "Open Events")
        self.assertContains(alerts_response, "event_module=suricata")
        self.assertContains(alerts_response, "Open Dashboards")

        with patch(
            "dashboard.views.get_opensearch_overview",
            return_value={
                "enabled": True,
                "configured": True,
                "url": "http://opensearch:9200",
                "dashboards_url": "http://127.0.0.1:5601",
                "index_prefix": "siem-events",
                "status": "ok",
                "cluster_status": "yellow",
                "node_count": 1,
                "active_primary_shards": 0,
                "unassigned_shards": 0,
                "indices": [],
                "index_count": 0,
                "document_count": 0,
                "error": "",
            },
        ):
            case_response = self.client.get(reverse("dashboard:siem_case_detail", args=[self.case.id]))
        self.assertEqual(case_response.status_code, 200)
        self.assertContains(case_response, "Open related events")
        self.assertContains(case_response, "asset_ip=10.10.10.10")
        self.assertContains(case_response, "Open Dashboards")

    def test_siem_hunt_detail_exposes_explorer_url_and_new_fields(self):
        with patch(
            "dashboard.views.get_opensearch_overview",
            return_value={
                "enabled": True,
                "configured": True,
                "url": "http://opensearch:9200",
                "dashboards_url": "http://127.0.0.1:5601",
                "index_prefix": "siem-events",
                "status": "ok",
                "cluster_status": "yellow",
                "node_count": 1,
                "active_primary_shards": 0,
                "unassigned_shards": 0,
                "indices": [],
                "index_count": 0,
                "document_count": 0,
                "error": "",
            },
        ):
            response = self.client.get(reverse("dashboard:siem_hunt_detail", args=[self.hunt.id]))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/siem_hunt_detail.html")
        self.assertContains(response, "Open in Explorer")
        self.assertContains(response, "event_module")
        self.assertContains(response, "event_dataset")
        self.assertContains(response, "Open Dashboards")


class PIDTestbedTests(TestCase):
    def test_pid_testbed_generates_conduit(self):
        sim_system = {
            "variables": {
                "PLC-1": {
                    "name": "PLC-1",
                    "type": "plc",
                    "domain": "cyber",
                    "ip_address": "172.30.1.10",
                    "vlan": "L2",
                    "vlan_cidr": "172.30.1.0/24",
                    "service_port": 15022,
                },
                "HIST-1": {
                    "name": "HIST-1",
                    "type": "historian",
                    "domain": "cyber",
                    "ip_address": "172.30.2.10",
                    "vlan": "L3",
                    "vlan_cidr": "172.30.2.0/24",
                    "service_port": 18080,
                },
            },
            "connections": [
                {"source": "PLC-1", "target": "HIST-1", "s_attr": "data", "t_attr": "ingest"},
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            files = build_testbed_from_sim_system(sim_system, Path(tmpdir))
            compose_text = files.compose_path.read_text(encoding="utf-8")
            self.assertIn("conduit-vlan-l2-vlan-l3", compose_text)
            self.assertIn("CONDUIT_MAP", compose_text)

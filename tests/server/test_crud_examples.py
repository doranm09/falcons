import pytest
from django.test import Client
from django.urls import reverse
from django.contrib.admin.sites import AdminSite
from dashboard.models import Node, ScanRun, AgentStatus
from dashboard.admin import NodeAdmin, ScanRunAdmin
from factories.user_factory import UserFactory

pytestmark = pytest.mark.django_db


class TestNodeCRUD:
    """CRUD tests for Node model using admin interface."""

    @pytest.fixture
    def admin_client_setup(self, admin_client):
        """Admin client with Node in database."""
        self.scan = ScanRun.objects.create(cidr="192.168.1.0/24", status="PENDING")
        return admin_client

    def test_create_node_via_admin(self, admin_client_setup):
        """Test creating a Node through admin interface."""
        client = admin_client_setup

        # Get the admin add page
        add_url = reverse('admin:dashboard_node_add')
        response = client.get(add_url)
        assert response.status_code == 200

        # Create node with valid data
        data = {
            'scan_run': str(self.scan.id),
            'ip_address': '192.168.1.100',
            'name': 'test-node-created',
            'description': 'Test node for CRUD',
            'status': 'online'
        }

        response = client.post(add_url, data, follow=True)
        assert response.status_code == 200

        # Verify node was created
        node = Node.objects.get(ip_address='192.168.1.100')
        assert node.name == 'test-node-created'
        assert node.description == 'Test node for CRUD'

    def test_list_nodes_via_admin(self, admin_client_setup):
        """Test listing nodes through admin interface."""
        client = admin_client_setup

        # Create some test nodes
        Node.objects.create(
            scan_run=self.scan,
            ip_address='192.168.1.1',
            name='node-1'
        )
        Node.objects.create(
            scan_run=self.scan,
            ip_address='192.168.1.2',
            name='node-2'
        )

        # Get admin changelist
        changelist_url = reverse('admin:dashboard_node_changelist')
        response = client.get(changelist_url)
        assert response.status_code == 200

        # Should contain both nodes
        assert b'node-1' in response.content
        assert b'node-2' in response.content

    def test_detail_node_via_admin(self, admin_client_setup):
        """Test viewing node detail through admin interface."""
        client = admin_client_setup

        # Create test node
        node = Node.objects.create(
            scan_run=self.scan,
            ip_address='192.168.1.50',
            name='detail-test-node',
            description='Node for detail view test'
        )

        # Get admin change page (detail/edit)
        change_url = reverse('admin:dashboard_node_change', args=[node.pk])
        response = client.get(change_url)
        assert response.status_code == 200

        # Should contain node data
        assert b'detail-test-node' in response.content
        assert b'192.168.1.50' in response.content

    def test_update_node_via_admin(self, admin_client_setup):
        """Test updating a node through admin interface."""
        client = admin_client_setup

        # Create test node
        node = Node.objects.create(
            scan_run=self.scan,
            ip_address='192.168.1.75',
            name='original-name',
            description='Original description'
        )

        # Get admin change page
        change_url = reverse('admin:dashboard_node_change', args=[node.pk])
        response = client.get(change_url)
        assert response.status_code == 200

        # Update with new data
        data = {
            'scan_run': str(self.scan.id),
            'ip_address': '192.168.1.75',  # Same IP
            'name': 'updated-name',
            'description': 'Updated description',
            'status': 'offline'  # Changed status
        }

        response = client.post(change_url, data, follow=True)
        assert response.status_code == 200

        # Refresh and verify
        node.refresh_from_db()
        assert node.name == 'updated-name'
        assert node.description == 'Updated description'
        assert node.status == 'offline'

    def test_delete_node_via_admin(self, admin_client_setup):
        """Test deleting a node through admin interface."""
        client = admin_client_setup

        # Create test node
        node = Node.objects.create(
            scan_run=self.scan,
            ip_address='192.168.1.99',
            name='node-to-delete'
        )

        initial_count = Node.objects.count()

        # Get admin delete confirmation page
        delete_url = reverse('admin:dashboard_node_delete', args=[node.pk])
        response = client.get(delete_url)
        assert response.status_code == 200

        # Confirm delete
        response = client.post(delete_url, {'post': 'yes'}, follow=True)
        assert response.status_code == 200

        # Verify node was deleted
        assert Node.objects.count() == initial_count - 1
        with pytest.raises(Node.DoesNotExist):
            Node.objects.get(ip_address='192.168.1.99')

    def test_create_node_form_validation_errors(self, admin_client_setup):
        """Test form validation errors when creating node."""
        client = admin_client_setup

        add_url = reverse('admin:dashboard_node_add')

        # Test with invalid IP address
        invalid_data = {
            'scan_run': str(self.scan.id),
            'ip_address': 'invalid-ip',
            'name': 'test-node',
            'description': 'Test node'
        }

        response = client.post(add_url, invalid_data)
        assert response.status_code == 200  # Form should re-display with errors

        # Should still be on the add page
        assert 'dashboard/node/' in response.request['PATH_INFO']
        assert 'add' in response.request['PATH_INFO']

        # Should contain error message about invalid IP
        assert b'Enter a valid IP address' in response.content or b'invalid' in response.content.lower()

    def test_create_node_unique_ip_constraint(self, admin_client_setup):
        """Test duplicate IP creation handling (not unique by default)."""
        client = admin_client_setup

        add_url = reverse('admin:dashboard_node_add')

        # Create first node
        data1 = {
            'scan_run': str(self.scan.id),
            'ip_address': '192.168.1.123',
            'name': 'first-node',
            'status': 'online',
        }
        response = client.post(add_url, data1, follow=True)
        assert response.status_code == 200

        # Try to create second node with same IP
        data2 = {
            'scan_run': str(self.scan.id),
            'ip_address': '192.168.1.123',  # Same IP
            'name': 'second-node',
            'status': 'online',
        }
        response = client.post(add_url, data2)
        assert response.status_code in [200, 302]

        # IP address is not unique by default; duplicate should be allowed.
        assert Node.objects.filter(ip_address='192.168.1.123').count() == 2

    def test_create_node_required_fields(self, admin_client_setup):
        """Test that required fields are enforced."""
        client = admin_client_setup

        add_url = reverse('admin:dashboard_node_add')

        # Try to create node without required fields
        incomplete_data = {
            'name': 'incomplete-node'
            # Missing ip_address and scan_run (required)
        }

        response = client.post(add_url, incomplete_data)
        assert response.status_code == 200

        # Should contain validation errors for missing required fields
        content = response.content.decode('utf-8')
        assert 'required' in content.lower() or 'field is required' in content.lower()


class TestAgentStatusCRUD:
    """CRUD tests for AgentStatus model - simplified version."""

    def test_create_agent_status_programmatically(self):
        """Test creating AgentStatus programmatically."""
        agent = AgentStatus.objects.create(
            agent_id='test-agent-crud',
            hostname='test-host-crud',
            ip_address='10.0.0.100',
            status='online'
        )

        assert agent.agent_id == 'test-agent-crud'
        assert agent.hostname == 'test-host-crud'
        assert agent.status == 'online'

    def test_update_agent_status(self):
        """Test updating AgentStatus."""
        agent = AgentStatus.objects.create(
            agent_id='test-agent-update',
            hostname='original-host',
            ip_address='10.0.0.200',
            status='offline'
        )

        agent.hostname = 'updated-host'
        agent.status = 'online'
        agent.save()

        agent.refresh_from_db()
        assert agent.hostname == 'updated-host'
        assert agent.status == 'online'

    def test_delete_agent_status(self):
        """Test deleting AgentStatus."""
        agent = AgentStatus.objects.create(
            agent_id='test-agent-delete',
            hostname='delete-me',
            ip_address='10.0.0.201'
        )

        initial_count = AgentStatus.objects.count()
        agent.delete()

        assert AgentStatus.objects.count() == initial_count - 1

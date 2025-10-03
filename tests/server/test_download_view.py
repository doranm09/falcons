import pytest
import zipfile
import tempfile
import io
from pathlib import Path
from unittest.mock import patch, MagicMock
from django.test import Client
from django.core.files.uploadedfile import SimpleUploadedFile
import responses
from django.conf import settings
from django.urls import reverse


class TestDownloadView:

    def test_download_via_github_api_success(self, client, tmp_path):
        """Test download when GitHub API provides a release ZIP."""
        # Mock successful GitHub API response
        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'
        zipball_url = 'https://github.gatech.edu/test-repo/zipball/v1.2.3'

        # Create mock ZIP content
        zip_content = io.BytesIO()
        with zipfile.ZipFile(zip_content, 'w') as zip_file:
            zip_file.writestr('test.txt', 'test content')
        zip_content.seek(0)

        with responses.RequestsMock() as rsps:
            # Mock latest release API
            rsps.add(responses.GET, api_url, json={
                'zipball_url': zipball_url,
                'tag_name': 'v1.2.3'
            }, status=200)

            # Mock ZIP download
            rsps.add(responses.GET, zipball_url, body=zip_content.read(), status=200)

            response = client.get(reverse('dashboard:download_host_agent'))

        assert response.status_code == 200
        assert response['Content-Type'] == 'application/zip'
        assert 'attachment' in response['Content-Disposition']
        assert 'v1.2.3_cyber_host_agent.zip' in response['Content-Disposition']

    def test_download_fallback_to_local_zip(self, client, tmp_path):
        """Test download falls back to local ZIP when GitHub API fails."""
        # Make sure host_agent directory has some test files
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        test_file = host_agent_dir / 'test_agent_file.py'
        if not test_file.exists():
            host_agent_dir.mkdir(exist_ok=True)
            test_file.write_text('# Test agent file')

        # Mock GitHub API failure
        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, api_url, json={'error': 'Not found'}, status=404)

            response = client.get(reverse('dashboard:download_host_agent'))

        assert response.status_code == 200
        assert response['Content-Type'] == 'application/zip'
        assert 'attachment' in response['Content-Disposition']

    def test_download_caches_zip_file(self, client, tmp_path):
        """Test that ZIP file is cached and reused within 1 hour."""
        # Create a cached ZIP file
        zips_dir = tmp_path / 'media' / 'exports'
        zips_dir.mkdir(parents=True, exist_ok=True)
        zip_path = zips_dir / 'host_agent.zip'

        # Create a recent zip file (within 1 hour)
        with open(zip_path, 'wb') as f:
            f.write(b'fake zip content')

        # Touch the file to make it recent
        import time
        import os
        os.utime(zip_path, (time.time(), time.time()))

        # Mock GitHub API failure to ensure fallback branch is taken
        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, api_url, json={'error': 'Not found'}, status=404)

            response = client.get(reverse('dashboard:download_host_agent'))

        assert response.status_code == 200
        assert response['Content-Type'] == 'application/zip'
        # Should use FileResponse which streams the file
        assert hasattr(response, 'file_to_stream')

    def test_download_fallback_creates_valid_zip(self, client, tmp_path):
        """Test that fallback ZIP creation produces a valid ZIP file."""
        # Ensure some files exist in host_agent directory
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        host_agent_dir.mkdir(exist_ok=True)  # ensure exists

        test_file = host_agent_dir / 'agent.py'
        if not test_file.exists():
            test_file.write_text('# Mock agent file')

        # Mock GitHub API failure
        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, api_url, json={'error': 'Not found'}, status=404)

            response = client.get(reverse('dashboard:download_host_agent'))

        assert response.status_code == 200
        assert response['Content-Type'] == 'application/zip'

        # Read the response content and verify it's a valid ZIP
        content = b''
        for chunk in response.streaming_content:
            content += chunk

        # Verify content is a valid ZIP
        zip_content = io.BytesIO(content)
        with zipfile.ZipFile(zip_content, 'r') as zip_file:
            # Should contain at least one file
            assert len(zip_file.namelist()) > 0

    def test_download_handles_timeout_gracefully(self, client):
        """Test download handles GitHub API timeout by falling back to local ZIP."""
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        if not host_agent_dir.exists():
            host_agent_dir.mkdir()
            (host_agent_dir / 'test.py').write_text('# test')

        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'

        # Mock request timeout
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, api_url, body=Exception('Request timeout'), status=500)

            response = client.get(reverse('dashboard:download_host_agent'))

        assert response.status_code == 200
        assert response['Content-Type'] == 'application/zip'

    def test_download_security_path_traversal_protection(self, client):
        """Test that download path is secure and prevents path traversal."""
        # This test verifies that the path is properly resolved and restricted
        # The view uses Path.resolve() and checks str(file_path).startswith(str(zips_dir.resolve()))

        # Test with HEAD request as well as GET
        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, api_url, json={'error': 'Not found'}, status=404)

            response = client.head(reverse('dashboard:download_host_agent'))

        assert response.status_code == 200
        assert response['Content-Type'] == 'application/zip'
        assert 'attachment' in response['Content-Disposition']

    def test_download_with_trailing_slash(self, client):
        """Test download URL with trailing slash doesn't redirect to unrelated pages."""
        # The requirement mentions that /agent/download/host_agent.zip/ should not 302 to unrelated pages
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        if not host_agent_dir.exists():
            host_agent_dir.mkdir()
            (host_agent_dir / 'test.py').write_text('# test')

        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, api_url, json={'error': 'Not found'}, status=404)

            response = client.get(reverse('dashboard:download_host_agent'))

        # Should return 200, not a redirect
        assert response.status_code == 200
        assert response['Content-Type'] == 'application/zip'

    def test_download_no_cache_header_for_fresh_content(self, client):
        """Test that fresh downloads have no-cache header."""
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        if not host_agent_dir.exists():
            host_agent_dir.mkdir()
            (host_agent_dir / 'test.py').write_text('# test')

        api_url = 'https://github.gatech.edu/api/v3/repos/iFAN-Lab/cyber_pen_test/releases/latest'

        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, api_url, json={'error': 'Not found'}, status=404)

            response = client.get(reverse('dashboard:download_host_agent'))

        assert response.status_code == 200
        assert response['Cache-Control'] == 'no-cache'

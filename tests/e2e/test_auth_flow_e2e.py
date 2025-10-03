import pytest
from pathlib import Path
from django.conf import settings


@pytest.mark.playwright
class TestAuthFlowE2E:

    def test_public_pages_accessible_without_login(self, page, live_server):
        """Test that public pages are accessible without authentication."""
        # Test main dashboard page
        page.goto(live_server.url)
        assert page.locator("h1").is_visible()  # Should show dashboard content

        # Test download page
        page.goto(f"{live_server.url}/agent/download/")
        assert page.locator("h2:has-text('Agent Download Center')").is_visible()

    def test_agent_download_accessible_without_auth(self, page, live_server):
        """Test that agent download works without authentication."""
        # Ensure test files exist
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        host_agent_dir.mkdir(exist_ok=True, exist_ok=True)

        test_file = host_agent_dir / 'agent.py'
        if not test_file.exists():
            test_file.write_text('# Test agent file')

        # Navigate to download page and attempt download
        page.goto(f"{live_server.url}/agent/download/")
        download_link = page.locator('[data-testid="download-agent"]')
        download_link.wait_for(state="visible")

        # Should be able to initiate download without login
        with page.expect_download() as download_info:
            download_link.click()

        download = download_info.value
        assert download is not None
        assert 'zip' in download.suggested_filename.lower()

    def test_no_login_redirects_on_public_pages(self, page, live_server):
        """Test that public pages don't redirect to login."""
        # Visit multiple public pages and ensure no redirects occur
        public_urls = [
            live_server.url,  # Home/dashboard
            f"{live_server.url}/agent/download/",  # Download page
            f"{live_server.url}/agent/monitoring/",  # Agent monitoring
        ]

        for url in public_urls:
            page.goto(url)
            # Should stay on the requested page, not redirect to login
            current_url = page.url
            assert url.rstrip('/') in current_url, f"Page {url} redirected to {current_url}"

    def test_agent_api_endpoints_accessible_in_e2e(self, page, live_server):
        """Test that agent API endpoints are accessible (though may return errors for bad data)."""
        # These are designed for programmatic access, so we just verify they're not blocked
        api_endpoints = [
            f"{live_server.url}/agent/versions/",
        ]

        for url in api_endpoints:
            # Use a new context for each request to avoid state issues
            response = page.request.get(url)
            # Should not return 403 Forbidden (auth blocked) or 405 (wrong method)
            assert response.status in [200, 400, 404, 500], f"Unexpected status {response.status} for {url}"

    def test_public_navigation_flow(self, page, live_server):
        """Test basic navigation flow through public pages."""
        # Start at home
        page.goto(live_server.url)
        assert page.locator("h1").is_visible()

        # Navigate to download page
        page.goto(f"{live_server.url}/agent/download/")
        assert page.locator("h2:has-text('Agent Download Center')").is_visible()

        # Navigate back to home
        page.goto(live_server.url)
        assert page.locator("h1").is_visible()

        # Navigate to agent monitoring
        page.goto(f"{live_server.url}/agent/monitoring/")
        assert page.locator("h3:has-text('Agent Monitoring')").is_visible() or page.locator("h2").is_visible()

    def test_download_page_interactive_elements(self, page, live_server):
        """Test interactive elements on download page work without auth."""
        page.goto(f"{live_server.url}/agent/download/")

        # Check dropdown menu works
        dropdown_button = page.locator("button:has-text('Download Host Agent (ZIP)')")
        assert dropdown_button.is_visible()

        # Check dropdown can be opened (basic interaction test)
        dropdown_button.click()

        # The dropdown menu should be visible now
        download_link = page.locator('[data-testid="download-agent"]')
        assert download_link.is_visible()

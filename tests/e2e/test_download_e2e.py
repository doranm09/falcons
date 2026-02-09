import pytest
import zipfile
import io
from pathlib import Path
from django.conf import settings


@pytest.mark.playwright
class TestDownloadE2E:

    def test_download_agent_zip_e2e(self, page, live_server):
        """E2E test for downloading agent ZIP file."""
        # Ensure host_agent directory exists with test files
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        host_agent_dir.mkdir(exist_ok=True)

        test_file = host_agent_dir / 'agent.py'
        if not test_file.exists():
            test_file.write_text('# Test agent file for E2E')

        # Navigate to the download page
        page.goto(f"{live_server.url}/agent/download/")

        # Wait for the page to load and find the download link by data-testid
        download_link = page.locator('[data-testid="download-agent"]')
        download_link.wait_for(state="visible")

        # Start waiting for the download
        with page.expect_download() as download_info:
            # Click the download link
            download_link.click()

        # Get the download object
        download = download_info.value

        # Verify download details
        assert download.suggested_filename.endswith('.zip') or 'host_agent' in download.suggested_filename

        # Save the download to memory and verify it's a valid ZIP
        content = download.save_as(None)  # Save to a temporary path, returns path

        # Read the downloaded file
        zip_content = io.BytesIO()
        with open(content, 'rb') as f:
            zip_content.write(f.read())

        zip_content.seek(0)

        # Verify the content is a valid ZIP file
        with zipfile.ZipFile(zip_content, 'r') as zip_file:
            # Should contain at least one file
            assert len(zip_file.namelist()) > 0

            # Check that it contains the expected files (basic check)
            filenames = zip_file.namelist()
            assert any('agent' in name.lower() for name in filenames)

    def test_download_page_renders_correctly(self, page, live_server):
        """Test that the download page renders with correct elements."""
        # Navigate to the download page
        page.goto(f"{live_server.url}/agent/download/")

        # Check page title and content
        assert page.locator("h2:has-text('Agent Download Center')").is_visible()

        # Check that download link exists with data-testid
        download_link = page.locator('[data-testid="download-agent"]')
        assert download_link.is_visible()

        # Check that the link has correct attributes
        href = download_link.get_attribute('href')
        assert '/agent/download/host_agent.zip' in href

        # Check that download attribute is present
        download_attr = download_link.get_attribute('download')
        assert download_attr is not None

        # Check for other page elements
        assert page.locator("text=Installation Instructions").is_visible()
        assert page.locator("text=Deployed Agents").is_visible()

    def test_download_dropdown_menu(self, page, live_server):
        """Test the download dropdown menu functionality."""
        page.goto(f"{live_server.url}/agent/download/")

        # Find the dropdown button
        dropdown_button = page.locator("button:has-text('Download Host Agent (ZIP)')")
        assert dropdown_button.is_visible()

        # The download link should be in the dropdown menu
        download_link = page.locator('[data-testid="download-agent"]')
        assert download_link.is_visible()

        # Check for other dropdown options
        assert page.locator("text=Open in New Tab").is_visible()
        assert page.locator("text=Copy Download Link").is_visible()

    def test_download_caching_behavior(self, page, live_server):
        """Test that downloads work correctly with caching."""
        # This test verifies the download still works even after caching
        # Setup test files
        host_agent_dir = Path(settings.BASE_DIR) / 'host_agent'
        host_agent_dir.mkdir(exist_ok=True)

        test_file = host_agent_dir / 'agent.py'
        if not test_file.exists():
            test_file.write_text('# Test agent file for caching test')

        page.goto(f"{live_server.url}/agent/download/")

        # First download
        with page.expect_download() as download_info:
            page.locator('[data-testid="download-agent"]').click()

        download1 = download_info.value
        assert download1

        # Second download (should also work, possibly from cache)
        page.reload()  # Refresh page
        page.locator('[data-testid="download-agent"]').wait_for(state="visible")

        with page.expect_download() as download_info:
            page.locator('[data-testid="download-agent"]').click()

        download2 = download_info.value
        assert download2

        # Both should be valid ZIPs
        for download in [download1, download2]:
            content_path = download.save_as(None)
            with open(content_path, 'rb') as f:
                zip_content = io.BytesIO(f.read())

            with zipfile.ZipFile(zip_content, 'r') as zip_file:
                assert len(zip_file.namelist()) > 0

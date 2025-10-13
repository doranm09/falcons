"""Template mapping logic for discovered hosts."""

from typing import Dict, Any, List, Optional
from ..planner.templates import DiscoveredHost


class TemplateMapper:
    """Maps discovered hosts to VM templates based on rules."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mapping_rules = config.get("mapping_rules", [])
        self.templates = config.get("templates", {})
        self.defaults = config.get("defaults", {})

    def resolve_template(self, host: DiscoveredHost) -> Optional[str]:
        """
        Resolve template name for a host based on mapping rules.
        Returns template name or None if no match.
        """
        # Rules are evaluated in order, first match wins
        for rule in self.mapping_rules:
            match = rule.get("match", {})
            if self._host_matches_rule(host, match):
                return rule.get("template")
        return None

    def _host_matches_rule(self, host: DiscoveredHost, match: Dict[str, Any]) -> bool:
        """Check if host matches a rule's criteria."""
        # Check os_family match
        if "os_family" in match:
            if host.os_family != match["os_family"]:
                return False

        # Check services_any (host has at least one of these services)
        if "services_any" in match:
            required_services = set(match["services_any"])
            host_services = set(host.services)
            if not required_services.intersection(host_services):
                return False

        # Check tags_any (host has at least one of these tags)
        if "tags_any" in match:
            required_tags = set(match["tags_any"])
            host_tags = set(host.tags)
            if not required_tags.intersection(host_tags):
                return False

        # Check services_all (host has all of these services)
        if "services_all" in match:
            required_services = set(match["services_all"])
            host_services = set(host.services)
            if not required_services.issubset(host_services):
                return False

        # Check tags_all (host has all of these tags)
        if "tags_all" in match:
            required_tags = set(match["tags_all"])
            host_tags = set(host.tags)
            if not required_tags.issubset(host_tags):
                return False

        return True

    def get_template_config(self, template_name: str) -> Dict[str, Any]:
        """Get template configuration, merged with defaults."""
        template = self.templates.get(template_name, {})

        # Merge defaults with template-specific settings
        merged = self.defaults.copy()
        merged.update(template)

        return merged

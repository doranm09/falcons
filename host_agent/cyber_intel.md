# Cyber Threat Intelligence Integration

This integration is planned but not yet implemented. This document captures the intended inputs and output shape so future work can link SBOM-derived package data to external threat intelligence.

## Intended Inputs
- SBOM package list (name, version, package type)
- Optional host metadata (OS, hostname, agent ID)
- Vulnerability feed metadata (source name, update timestamp)

## Intended Outputs
- Enriched package entries with CVE references and severity
- Mapping from packages to known exploited vulnerabilities
- Summary counts for dashboard display

## Proposed Integration Points
- `host_agent/extract_sbom_to_template.py`: add optional enrichment step after SBOM parsing
- Dashboard ingestion: display enriched fields in vulnerability views

## Status
- No code implementation yet; this is a placeholder for design notes.

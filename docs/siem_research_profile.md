# SIEM Research Mode Profile

Research Mode provides a pinned, versioned profile for deterministic SIEM runs.

## UI
- Navigate to `SIEM > Research Mode`.
- Activate a profile to lock pipeline, ruleset, and retention values.

## Profile Fields
- `version`: profile schema version
- `pipeline_version`: pipeline configuration version
- `ruleset_version`: ruleset version for alerting
- `retention_days`: expected retention window
- `max_batch`: ingest batch cap used by `/dashboard/siem/ingest/` and `/dashboard/siem/pipeline/ingest/`

A default profile named **Research Mode** is created via migration.

## Endpoints
- `GET /dashboard/siem/research/` list profiles
- `POST /dashboard/siem/research/<profile_id>/activate/` activate a profile

## Notes
- The active profile overrides the SIEM ingest batch limit for reproducibility.
- Use the profile version strings to annotate downstream experiments and exports.

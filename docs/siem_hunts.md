# SIEM Hunt Workflow

This feature adds saved searches, tags, and notebook entries to support threat hunting.

## UI
- Navigate to `SIEM > Hunts` in the sidebar.
- Create a hunt with a name, description, and optional tags.
- Open a hunt to add tags, notebook entries, and saved searches.
- Use **Replay** on a saved search to run it against current SIEM events.

## Endpoints
- `GET /dashboard/siem/hunts/` list hunts (filter with `?status=open|closed`)
- `POST /dashboard/siem/hunts/new/` create hunt
- `GET /dashboard/siem/hunts/<hunt_id>/` hunt detail
- `POST /dashboard/siem/hunts/<hunt_id>/status/` update status
- `POST /dashboard/siem/hunts/<hunt_id>/notes/` add notebook entry
- `POST /dashboard/siem/hunts/<hunt_id>/tags/` add tags (comma-separated)
- `POST /dashboard/siem/hunts/<hunt_id>/searches/` save a search
- `GET /dashboard/siem/hunts/<hunt_id>/replay/<search_id>/` replay a saved search

## Saved Search Fields
Saved searches accept the same parameters as `/dashboard/siem/events/`:
- `event_type`, `source`, `asset_id`, `asset_ip`, `q`, `severity`
- `start`, `end` (ISO8601 timestamps)
- `event_type_in`, `source_in` (comma-separated)
- `agg`, `agg_size`

## Notes
- Tags are deduplicated case-insensitively.
- Replay returns JSON with `count`, `results`, and optional `aggregations`.

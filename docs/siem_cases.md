# SIEM Case Management

Cases track investigations for alerts and incidents. Each case can include notes, evidence, and linked alerts, and can be exported for reporting.

## Features
- Promote alerts to cases from the alert queue
- Manual case creation
- Notes and evidence tracking
- Case export to JSON

## UI Workflow
1. Open `SIEM > Alert Queue` and click **Create Case** next to an alert.
2. Open `SIEM > Cases` to see all active cases.
3. Click a case to view details, add notes, add evidence, and update status.
4. Use **Export JSON** for reporting or research artifacts.

## Endpoints
- `GET /dashboard/siem/cases/` List cases
- `POST /dashboard/siem/cases/new/` Create a case
- `GET /dashboard/siem/cases/<case_id>/` Case detail
- `POST /dashboard/siem/cases/<case_id>/status/` Update case status
- `POST /dashboard/siem/cases/<case_id>/notes/` Add a note
- `POST /dashboard/siem/cases/<case_id>/evidence/` Add evidence
- `GET /dashboard/siem/cases/<case_id>/export/` Export JSON
- `POST /dashboard/siem/alerts/<alert_id>/case/` Promote alert to case

## Case Export
Exports include:
- Case metadata
- Linked alerts
- Notes
- Evidence

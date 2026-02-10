# P&ID Draw.io Pipeline

This project supports converting draw.io P&ID diagrams into `sim_system.json` (compatible with `ics-risk-assessment`) and back.

## Overview
- Author P&ID diagrams in draw.io (diagrams.net).
- Store node metadata using `Edit Data` (recommended).
- Convert diagram XML into `sim_system.json`.
- Feed `sim_system.json` into `ics-risk-assessment` for system graph analysis.

## Draw.io Conventions
**Nodes (variables)**
- Each diagram shape becomes a variable.
- `pid` is the variable id (recommended; stored via `Edit Data`).
- `type` and `module` map directly to `sim_system.json` fields.
- `domain` can be set to `cyber` or `physical` to control UI styling.
- Include `ip` or `ip_address` on cyber nodes to attach network edges (only cyber nodes are matched to network connections).
- Any extra attributes are copied into the variable info.
If `domain` is not set, the UI will infer cyber nodes from common keywords (PLC/HMI/SCADA/RTU/etc.) and default everything else to physical.

**Edges (connections)**
- Each connector becomes a connection with `source`, `target`, `s_attr`, `t_attr`.
- Set `s_attr` and `t_attr` via `Edit Data` on the connector.
- If unset, the connector label is parsed as `s_attr->t_attr`.

## Export From Draw.io
Use uncompressed XML for the easiest parsing:
1. File -> Export As -> XML
2. Uncheck "Compressed"
3. Save as `.xml`

## Convert Draw.io -> sim_system.json
```bash
python utils/scripts/knowledge_extraction_drawio.py \
  --input docs/examples/pid_drawio_example.xml \
  --output out/sim_system.json
```

## Convert sim_system.json -> Draw.io
```bash
python utils/scripts/knowledge_extraction_drawio.py \
  --to-drawio \
  --input docs/examples/sim_system_example.json \
  --output out/pid_drawio_example.xml
```

## Sync From ics-risk-assessment
```bash
python utils/scripts/sync_risk_sim_system.py \
  --source ../ics-risk-assessment/db/sim_system.json \
  --output-dir out/pid_drawio \
  --prefix risk
```

## Django Command (Orchestrated)
```bash
python manage.py pid_drawio \
  --input docs/examples/pid_drawio_example.xml \
  --output out/sim_system.json
```

```bash
python manage.py pid_drawio \
  --to-drawio \
  --input docs/examples/sim_system_example.json \
  --output out/pid_drawio_example.xml
```

## Example Files
- `docs/examples/sim_system_example.json`
- `docs/examples/pid_drawio_example.xml`

## Dashboard UI
1. Navigate to **Risk Assessment** -> **Overview**.
2. In **P&ID Draw.io Import**, choose a draw.io XML file.
3. Optional: enable **Upload to risk assessment workspace** (requires `RISK_ASSESSMENT_SIM_SYSTEM_PATH`).
4. Click **Convert & Upload** to generate `sim_system.json`.

## System View (UI)
1. Navigate to **Risk Assessment** -> **System**.
2. Choose the source (`Auto`, `Target`, or `Latest`) and enable **Network overlay** as needed.
3. Cyber nodes are highlighted in blue; physical nodes are gray.
4. Cyber nodes without network connectivity are outlined in red.
5. Network overlay uses recent connection data (last 60 minutes by default).

Environment variables:
- `PID_DRAWIO_OUTPUT_DIR`: override where conversion outputs are stored.
- `RISK_ASSESSMENT_SIM_SYSTEM_PATH`: optional filesystem target for uploading the generated `sim_system.json` into the risk assessment workspace.

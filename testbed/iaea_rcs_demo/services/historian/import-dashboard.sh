#!/bin/sh
set -eu

INFLUX_URL=${INFLUX_URL:-}
INFLUX_TOKEN=${INFLUX_TOKEN:-iaea-historian-token}
INFLUX_ORG=${INFLUX_ORG:-iaea}

if [ -z "$INFLUX_URL" ]; then
  echo "INFLUX_URL is required. The validated hybrid demo leaves historian persistence disabled by default." >&2
  exit 1
fi

JSON=$(cat <<'EOF'
{
  "meta": {
    "name": "IAEA RCS Overview"
  },
  "spec": {
    "name": "IAEA RCS Overview",
    "description": "Live OPC UA metrics pushed from the Layer 0 historian",
    "cells": [
      {
        "x": 0,
        "y": 0,
        "w": 6,
        "h": 4,
        "id": "main-pressure",
        "view": {
          "name": "Main Pressure",
          "type": "xy",
          "properties": {
            "queries": [
              {
                "name": "main_pressure",
                "text": "from(bucket:\"iaea_rcs\") |> range(start:-1h) |> filter(fn:(r) => r.profile == \"main\" and r._field == \"average_pressure\") |> yield(name:\"main_pressure\")",
                "type": "flux"
              }
            ],
            "axes": {
              "x": {
                "label": "Time",
                "prefix": "",
                "suffix": "",
                "base": 10,
                "scale": "linear"
              },
              "y": {
                "label": "Average Pressure",
                "prefix": "",
                "suffix": "",
                "base": 10,
                "scale": "linear"
              }
            }
          }
        }
      },
      {
        "x": 6,
        "y": 0,
        "w": 6,
        "h": 4,
        "id": "backup-pressure",
        "view": {
          "name": "Backup Pressure",
          "type": "xy",
          "properties": {
            "queries": [
              {
                "name": "backup_pressure",
                "text": "from(bucket:\"iaea_rcs\") |> range(start:-1h) |> filter(fn:(r) => r.profile == \"backup\" and r._field == \"average_pressure\") |> yield(name:\"backup_pressure\")",
                "type": "flux"
              }
            ],
            "axes": {
              "x": {
                "label": "Time",
                "base": 10,
                "scale": "linear"
              },
              "y": {
                "label": "Average Pressure",
                "base": 10,
                "scale": "linear"
              }
            }
          }
        }
      },
      {
        "x": 0,
        "y": 4,
        "w": 12,
        "h": 4,
        "id": "actuator-owner",
        "view": {
          "name": "Override Owners",
          "type": "xy",
          "properties": {
            "queries": [
              {
                "name": "owners",
                "text": "from(bucket:\"iaea_rcs\") |> range(start:-1h) |> filter(fn:(r) => contains(value: r._field, set: [\"hv_owner\", \"pvb_owner\", \"pvc_owner\", \"heat_owner\"])) |> yield(name:\"owners\")",
                "type": "flux"
              }
            ],
            "axes": {
              "x": {"label": "Time", "scale": "linear"},
              "y": {"label": "Owner ID", "scale": "linear"}
            }
          }
        }
      }
    ]
  }
}
EOF
)

curl -sSf \
  -X POST \
  -H "Authorization: Token ${INFLUX_TOKEN}" \
  -H "Content-Type: application/json" \
  "${INFLUX_URL}/api/v2/dashboards" \
  -d "${JSON}"

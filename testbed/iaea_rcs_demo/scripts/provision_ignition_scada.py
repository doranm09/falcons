#!/usr/bin/env python3
from __future__ import annotations

"""Legacy pre-hybrid Ignition helper retained for reference.

The current validated IAEA demo path does not include the `ignition` service.
Use `docker-compose-hybrid.yml` and the Django dashboard instead.
"""

import argparse
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


PROJECT_NAME = "iaea_rcs_scada"
IGNITION_SERVICE = "ignition"
IGNITION_DATA_DIR = "/usr/local/bin/ignition/data"
CONTAINER_DB_PATH = f"{IGNITION_DATA_DIR}/db/config.idb"
CONTAINER_PROJECTS_DIR = f"{IGNITION_DATA_DIR}/projects"

MAIN_SERVER_NAME = "PLC Main OPC"
BACKUP_SERVER_NAME = "PLC Backup OPC"


@dataclass(frozen=True)
class OpcServerConfig:
    name: str
    description: str
    endpoint: str


OPC_SERVERS = (
    OpcServerConfig(
        name=MAIN_SERVER_NAME,
        description="Main PLC OPC UA bridge",
        endpoint="opc.tcp://10.1.13.10:4840/main",
    ),
    OpcServerConfig(
        name=BACKUP_SERVER_NAME,
        description="Backup PLC OPC UA bridge",
        endpoint="opc.tcp://10.2.23.10:4840/backup",
    ),
)


COMMON_POINTS = (
    ("Actuators", "hv_owner"),
    ("Actuators", "hv_applied"),
    ("Actuators", "hv_last_writer"),
    ("Actuators", "hv_status"),
    ("Actuators", "pvb_owner"),
    ("Actuators", "pvb_applied"),
    ("Actuators", "pvb_last_writer"),
    ("Actuators", "pvb_status"),
    ("Actuators", "pvc_owner"),
    ("Actuators", "pvc_applied"),
    ("Actuators", "pvc_last_writer"),
    ("Actuators", "pvc_status"),
    ("Actuators", "heat_owner"),
    ("Actuators", "heat_applied"),
    ("Actuators", "heat_last_writer"),
    ("Actuators", "heat_status"),
    ("Summary", "average_pressure"),
    ("Summary", "health_code"),
    ("Summary", "exported_hv_owner"),
    ("Summary", "exported_hv_command"),
    ("Summary", "exported_pvb_owner"),
    ("Summary", "exported_pvb_command"),
    ("Summary", "exported_pvc_owner"),
    ("Summary", "exported_pvc_command"),
    ("Summary", "exported_heat_owner"),
    ("Summary", "exported_heat_command"),
    ("Commands", "hv_override_command"),
    ("Commands", "pvb_override_command"),
    ("Commands", "pvc_override_command"),
    ("Commands", "heat_override_command"),
    ("Commands", "override_controller_id"),
    ("Bridge", "bridge_online"),
    ("Bridge", "bridge_poll_errors"),
    ("Bridge", "bridge_last_success_epoch"),
    ("Bridge", "bridge_write_errors"),
    ("Bridge", "bridge_last_write_epoch"),
    ("Bridge", "bridge_active_overrides"),
)

PROFILE_POINTS = {
    "Main": (
        ("Sensors", "pt455_pv"),
        ("Sensors", "pt455_status"),
        ("Sensors", "pt456_pv"),
        ("Sensors", "pt456_status"),
        ("Sensors", "pt457_pv"),
        ("Sensors", "pt457_status"),
        ("Summary", "exported_pt455"),
        ("Summary", "exported_pt456"),
        ("Summary", "exported_pt457"),
    ),
    "Backup": (
        ("Sensors", "pt456_pv"),
        ("Sensors", "pt456_status"),
        ("Sensors", "pt457_pv"),
        ("Sensors", "pt457_status"),
        ("Sensors", "pt458_pv"),
        ("Sensors", "pt458_status"),
        ("Summary", "exported_pt456"),
        ("Summary", "exported_pt457"),
        ("Summary", "exported_pt458"),
    ),
}

PROFILE_STYLE = {
    "Main": {
        "accent": "#38bdf8",
        "accent_soft": "#0f2940",
        "accent_border": "#1d4f6d",
    },
    "Backup": {
        "accent": "#f59e0b",
        "accent_soft": "#34230b",
        "accent_border": "#6b4a15",
    },
}

SENSOR_TITLES = {
    "pt455": "PT-455",
    "pt456": "PT-456",
    "pt457": "PT-457",
    "pt458": "PT-458",
}

ACTUATOR_TITLES = {
    "hv": "HV-455A",
    "pvb": "PV-455B",
    "pvc": "PV-455C",
    "heat": "Heat Ctrl",
}


def run(cmd: list[str], *, cwd: Path | None = None, capture: bool = False) -> str | None:
    print("+", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=True,
        text=True,
        capture_output=capture,
    )
    return result.stdout if capture else None


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_for_files(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_resource_manifest(resource_dir: Path, files: list[str], *, scope: str = "G", version: int = 1) -> None:
    file_paths = [resource_dir / name for name in files]
    manifest = {
        "scope": scope,
        "version": version,
        "restricted": False,
        "overridable": True,
        "files": files,
        "attributes": {
            "lastModification": {
                "actor": "external",
                "timestamp": utc_timestamp(),
            },
            # Ignition computes its own signature internally. A deterministic
            # hash here is enough to keep disk resources self-describing.
            "lastModificationSignature": sha256_for_files(file_paths),
        },
    }
    write_json(resource_dir / "resource.json", manifest)


def label_component(
    name: str,
    *,
    text: str | None = None,
    tag_path: str | None = None,
    basis: str = "180px",
    grow: int = 0,
    shrink: int = 0,
    style: dict | None = None,
) -> dict:
    component = {
        "meta": {"name": name},
        "position": {"basis": basis, "grow": grow, "shrink": shrink},
        "props": {
            "style": style or {},
            "text": text if text is not None else "",
        },
        "type": "ia.display.label",
    }
    if tag_path:
        component["propConfig"] = {
            "props.text": {
                "binding": {
                    "config": {
                        "mode": "direct",
                        "tagPath": tag_path,
                    },
                    "type": "tag",
                }
            }
        }
    return component


def numeric_component(name: str, *, tag_path: str, basis: str = "140px") -> dict:
    return {
        "meta": {"name": name},
        "position": {"basis": basis, "grow": 0, "shrink": 0},
        "propConfig": {
            "props.value": {
                "binding": {
                    "config": {
                        "bidirectional": True,
                        "mode": "direct",
                        "tagPath": tag_path,
                    },
                    "type": "tag",
                }
            }
        },
        "props": {
            "align": "center",
            "format": "none",
            "style": {
                "backgroundColor": "#09111f",
                "border": "1px solid #31506a",
                "borderRadius": "10px",
                "color": "#f1f5f9",
                "fontSize": "17px",
                "fontWeight": 700,
                "padding": "10px 12px",
            },
        },
        "type": "ia.input.numeric-entry-field",
    }


def multi_state_override_component(name: str, *, tag_path: str, accent: str) -> dict:
    return {
        "meta": {"name": name},
        "position": {"basis": "100%", "grow": 0, "shrink": 0},
        "propConfig": {
            "props.controlValue": {
                "binding": {
                    "config": {
                        "bidirectional": True,
                        "mode": "direct",
                        "tagPath": tag_path,
                    },
                    "type": "tag",
                }
            },
            "props.indicatorValue": {
                "binding": {
                    "config": {
                        "mode": "direct",
                        "tagPath": tag_path,
                    },
                    "type": "tag",
                }
            },
        },
        "props": {
            "buttonGap": 6,
            "controlValue": -1,
            "defaultSelectedStyle": {
                "border": f"1px solid {accent}",
                "boxShadow": f"0 0 0 1px {accent} inset",
                "color": "#06101b",
                "fontWeight": 800,
            },
            "defaultUnselectedStyle": {
                "backgroundColor": "#0b1625",
                "border": "1px solid #2a3f55",
                "color": "#cbd5e1",
                "fontWeight": 700,
            },
            "enabled": True,
            "endButtonCornerRadius": 10,
            "indicatorValue": -1,
            "orientation": "row",
            "primary": False,
            "states": [
                {
                    "selectedStyle": {"backgroundColor": "#94a3b8"},
                    "text": "Release",
                    "tooltipText": "Write -1 and hand control back to PLC logic",
                    "unselectedStyle": {"minWidth": "84px", "padding": "10px 12px"},
                    "value": -1,
                },
                {
                    "selectedStyle": {"backgroundColor": accent},
                    "text": "0",
                    "tooltipText": "Write 0",
                    "unselectedStyle": {"minWidth": "52px", "padding": "10px 12px"},
                    "value": 0,
                },
                {
                    "selectedStyle": {"backgroundColor": accent},
                    "text": "25",
                    "tooltipText": "Write 25",
                    "unselectedStyle": {"minWidth": "52px", "padding": "10px 12px"},
                    "value": 25,
                },
                {
                    "selectedStyle": {"backgroundColor": accent},
                    "text": "50",
                    "tooltipText": "Write 50",
                    "unselectedStyle": {"minWidth": "52px", "padding": "10px 12px"},
                    "value": 50,
                },
                {
                    "selectedStyle": {"backgroundColor": accent},
                    "text": "75",
                    "tooltipText": "Write 75",
                    "unselectedStyle": {"minWidth": "52px", "padding": "10px 12px"},
                    "value": 75,
                },
                {
                    "selectedStyle": {"backgroundColor": accent},
                    "text": "100",
                    "tooltipText": "Write 100",
                    "unselectedStyle": {"minWidth": "60px", "padding": "10px 12px"},
                    "value": 100,
                },
            ],
            "style": {"marginTop": "2px"},
        },
        "type": "ia.input.multi-state-button",
    }


def flex_container(
    children: list[dict],
    *,
    name: str,
    direction: str,
    basis: str = "auto",
    grow: int = 0,
    shrink: int = 0,
    style: dict | None = None,
) -> dict:
    return {
        "children": children,
        "meta": {"name": name},
        "position": {"basis": basis, "grow": grow, "shrink": shrink},
        "props": {
            "direction": direction,
            "style": {
                **(style or {}),
            },
        },
        "type": "ia.container.flex",
    }


def row(
    children: list[dict],
    *,
    basis: str = "auto",
    grow: int = 0,
    shrink: int = 0,
    style: dict | None = None,
    name: str,
) -> dict:
    return flex_container(
        children,
        name=name,
        direction="row",
        basis=basis,
        grow=grow,
        shrink=shrink,
        style={
            "alignItems": "center",
            "gap": "10px",
            **(style or {}),
        },
    )


def column(
    children: list[dict],
    *,
    basis: str = "auto",
    grow: int = 0,
    shrink: int = 0,
    style: dict | None = None,
    name: str,
) -> dict:
    return flex_container(
        children,
        name=name,
        direction="column",
        basis=basis,
        grow=grow,
        shrink=shrink,
        style={
            "gap": "10px",
            **(style or {}),
        },
    )


def card(
    children: list[dict],
    *,
    name: str,
    basis: str = "auto",
    grow: int = 0,
    shrink: int = 0,
    style: dict | None = None,
) -> dict:
    return column(
        children,
        name=name,
        basis=basis,
        grow=grow,
        shrink=shrink,
        style={
            "backgroundColor": "#0b1625",
            "border": "1px solid #1f3347",
            "borderRadius": "16px",
            "boxShadow": "0 18px 40px rgba(2, 6, 23, 0.28)",
            "padding": "16px",
            **(style or {}),
        },
    )


def section_title(text: str, *, name: str) -> dict:
    return label_component(
        name,
        text=text,
        basis="30px",
        style={
            "color": "#e2e8f0",
            "fontSize": "17px",
            "fontWeight": 700,
            "letterSpacing": "0.04em",
            "textTransform": "uppercase",
        },
    )


def note_label(text: str, *, name: str, basis: str = "22px", style: dict | None = None) -> dict:
    return label_component(
        name,
        text=text,
        basis=basis,
        style={
            "color": "#94a3b8",
            "fontSize": "13px",
            "lineHeight": 1.45,
            **(style or {}),
        },
    )


def metric_tile(title: str, tag_path: str, *, name: str, accent: str, basis: str = "180px") -> dict:
    return card(
        [
            label_component(
                f"{name}_title",
                text=title,
                basis="18px",
                style={
                    "color": "#8ba3b9",
                    "fontSize": "11px",
                    "fontWeight": 700,
                    "letterSpacing": "0.08em",
                    "textTransform": "uppercase",
                },
            ),
            label_component(
                f"{name}_value",
                tag_path=tag_path,
                basis="42px",
                style={
                    "color": "#f8fafc",
                    "fontWeight": 800,
                    "fontSize": "30px",
                    "lineHeight": 1.0,
                },
            ),
        ],
        name=name,
        basis=basis,
        grow=1,
        style={
            "backgroundColor": "#08111d",
            "border": f"1px solid {accent}",
            "borderLeft": f"4px solid {accent}",
            "gap": "8px",
            "minWidth": "160px",
        },
    )


def sensor_tile(sensor: str, profile: str, *, name: str) -> dict:
    base = f"[default]RCS/{profile}"
    sensor_title = SENSOR_TITLES[sensor]
    accent = PROFILE_STYLE[profile]["accent"]
    return card(
        [
            label_component(
                f"{name}_title",
                text=sensor_title,
                basis="22px",
                style={"color": "#f8fafc", "fontSize": "18px", "fontWeight": 700},
            ),
            note_label("Live process value", name=f"{name}_pv_label", basis="18px"),
            label_component(
                f"{name}_pv",
                tag_path=f"{base}/Sensors/{sensor}_pv",
                basis="40px",
                style={"color": accent, "fontSize": "32px", "fontWeight": 800, "lineHeight": 1.0},
            ),
            row(
                [
                    note_label("Status", name=f"{name}_status_title", basis="18px"),
                    label_component(
                        f"{name}_status",
                        tag_path=f"{base}/Sensors/{sensor}_status",
                        basis="50px",
                        style={"color": "#e2e8f0", "fontWeight": 700, "fontSize": "18px"},
                    ),
                ],
                name=f"{name}_status_row",
                style={"justifyContent": "space-between"},
            ),
        ],
        name=name,
        basis="210px",
        grow=1,
        style={
            "backgroundColor": "#0a1422",
            "gap": "6px",
            "minWidth": "180px",
        },
    )


def stat_tile(title: str, tag_path: str, *, name: str, accent: str) -> dict:
    return card(
        [
            note_label(
                title,
                name=f"{name}_title",
                basis="18px",
                style={
                    "color": "#8ba3b9",
                    "fontSize": "11px",
                    "fontWeight": 700,
                    "letterSpacing": "0.08em",
                    "textTransform": "uppercase",
                },
            ),
            label_component(
                f"{name}_value",
                tag_path=tag_path,
                basis="34px",
                style={"color": accent, "fontSize": "24px", "fontWeight": 800, "lineHeight": 1.0},
            ),
        ],
        name=name,
        basis="120px",
        grow=1,
        style={
            "backgroundColor": "#08111d",
            "border": "1px solid #1d3246",
            "gap": "8px",
            "minWidth": "110px",
            "padding": "12px",
        },
    )


def actuator_row(prefix: str, profile: str, *, name: str) -> dict:
    base = f"[default]RCS/{profile}"
    accent = PROFILE_STYLE[profile]["accent"]
    return card(
        [
            label_component(
                f"{name}_title",
                text=ACTUATOR_TITLES[prefix],
                basis="24px",
                style={"color": "#f8fafc", "fontSize": "18px", "fontWeight": 700},
            ),
            note_label(
                "Use preset buttons to drive the override tag. Release writes -1 and returns authority to PLC logic.",
                name=f"{name}_note",
                basis="38px",
            ),
            row(
                [
                    stat_tile(
                        "Owner",
                        f"{base}/Actuators/{prefix}_owner",
                        name=f"{name}_owner_tile",
                        accent=accent,
                    ),
                    stat_tile(
                        "Applied",
                        f"{base}/Actuators/{prefix}_applied",
                        name=f"{name}_applied_tile",
                        accent="#f8fafc",
                    ),
                ],
                name=f"{name}_stats",
                style={"alignItems": "stretch", "flexWrap": "wrap"},
            ),
            note_label(
                "Override Presets",
                name=f"{name}_override_label",
                basis="18px",
                style={
                    "color": "#8ba3b9",
                    "fontSize": "11px",
                    "fontWeight": 700,
                    "letterSpacing": "0.08em",
                    "textTransform": "uppercase",
                },
            ),
            multi_state_override_component(
                f"{name}_override",
                tag_path=f"{base}/Commands/{prefix}_override_command",
                accent=accent,
            ),
        ],
        name=name,
        basis="260px",
        grow=1,
        style={
            "backgroundColor": "#0a1422",
            "gap": "10px",
            "minWidth": "240px",
        },
    )


def panel_for_profile(profile: str) -> dict:
    base = f"[default]RCS/{profile}"
    accent = PROFILE_STYLE[profile]["accent"]
    accent_soft = PROFILE_STYLE[profile]["accent_soft"]
    accent_border = PROFILE_STYLE[profile]["accent_border"]
    sensor_prefixes = ["pt455", "pt456", "pt457"] if profile == "Main" else ["pt456", "pt457", "pt458"]

    sensor_tiles = [sensor_tile(sensor, profile, name=f"{profile}_{sensor}_card") for sensor in sensor_prefixes]
    override_cards = [actuator_row(prefix, profile, name=f"{profile}_{prefix}") for prefix in ("hv", "pvb", "pvc", "heat")]

    return card(
        [
            row(
                [
                    column(
                        [
                            label_component(
                                f"{profile}_title",
                                text=f"{profile} Cell",
                                basis="34px",
                                style={"color": "#f8fafc", "fontSize": "28px", "fontWeight": 800},
                            ),
                            note_label(
                                "Owners: 1 = plc-main, 2 = plc-backup. All values below are bound live to Ignition tags.",
                                name=f"{profile}_owner_note",
                                basis="38px",
                            ),
                        ],
                        name=f"{profile}_headline",
                        grow=1,
                    ),
                    card(
                        [
                            note_label(
                                "Bridge Status",
                                name=f"{profile}_bridge_label",
                                basis="18px",
                                style={
                                    "color": "#8ba3b9",
                                    "fontSize": "11px",
                                    "fontWeight": 700,
                                    "letterSpacing": "0.08em",
                                    "textTransform": "uppercase",
                                },
                            ),
                            label_component(
                                f"{profile}_bridge_value",
                                tag_path=f"{base}/Bridge/bridge_online",
                                basis="34px",
                                style={"color": accent, "fontSize": "26px", "fontWeight": 800},
                            ),
                        ],
                        name=f"{profile}_bridge_status_card",
                        basis="170px",
                        style={
                            "backgroundColor": accent_soft,
                            "border": f"1px solid {accent_border}",
                            "gap": "8px",
                            "padding": "14px",
                        },
                    ),
                ],
                name=f"{profile}_header",
                style={"alignItems": "stretch", "flexWrap": "wrap"},
            ),
            section_title("Operating Picture", name=f"{profile}_summary_title"),
            row(
                [
                    metric_tile(
                        "Average Pressure",
                        f"{base}/Summary/average_pressure",
                        name=f"{profile}_avg_pressure",
                        accent=accent,
                    ),
                    metric_tile(
                        "Health Code",
                        f"{base}/Summary/health_code",
                        name=f"{profile}_health",
                        accent=accent,
                    ),
                    metric_tile(
                        "Active Overrides",
                        f"{base}/Bridge/bridge_active_overrides",
                        name=f"{profile}_bridge_active_overrides",
                        accent=accent,
                    ),
                    metric_tile(
                        "Write Errors",
                        f"{base}/Bridge/bridge_write_errors",
                        name=f"{profile}_bridge_write_errors",
                        accent="#ef4444",
                    ),
                ],
                basis="auto",
                name=f"{profile}_summary_metrics",
                style={"alignItems": "stretch", "flexWrap": "wrap"},
            ),
            row(
                [
                    metric_tile(
                        "Poll Errors",
                        f"{base}/Bridge/bridge_poll_errors",
                        name=f"{profile}_bridge_poll_errors",
                        accent="#94a3b8",
                        basis="220px",
                    ),
                ],
                name=f"{profile}_ops_detail",
                style={"alignItems": "stretch", "flexWrap": "wrap"},
            ),
            section_title("Sensors", name=f"{profile}_sensors_title"),
            row(sensor_tiles, basis="auto", name=f"{profile}_sensor_grid", style={"alignItems": "stretch", "flexWrap": "wrap"}),
            section_title("Overrides", name=f"{profile}_actuators_title"),
            note_label(
                "These write directly to the Layer 1 override command tags exposed through the PLC bridge path.",
                name=f"{profile}_override_note",
                basis="20px",
            ),
            row(
                override_cards,
                basis="auto",
                name=f"{profile}_override_grid",
                style={"alignItems": "stretch", "flexWrap": "wrap"},
            ),
        ],
        name=f"{profile}Panel",
        basis="560px",
        grow=1,
        style={
            "backgroundColor": "#101b2b",
            "border": f"1px solid {accent_border}",
            "borderTop": f"4px solid {accent}",
            "gap": "18px",
            "minWidth": "420px",
            "padding": "20px",
        },
    )


def build_view_json() -> dict:
    return {
        "custom": {},
        "params": {},
        "props": {"defaultSize": {"height": 1440, "width": 1760}},
        "root": {
            "children": [
                card(
                    [
                        row(
                            [
                                column(
                                    [
                                        note_label(
                                            "Ignition Perspective",
                                            name="Eyebrow",
                                            basis="18px",
                                            style={
                                                "color": "#7dd3fc",
                                                "fontSize": "12px",
                                                "fontWeight": 800,
                                                "letterSpacing": "0.12em",
                                                "textTransform": "uppercase",
                                            },
                                        ),
                                        label_component(
                                            "Header",
                                            text="IAEA RCS Live Control Surface",
                                            basis="50px",
                                            style={
                                                "color": "#f8fafc",
                                                "fontSize": "36px",
                                                "fontWeight": 800,
                                                "letterSpacing": "0.02em",
                                                "lineHeight": 1.0,
                                            },
                                        ),
                                        note_label(
                                            "Live OPC telemetry from both PLC bridges is surfaced below. Override writes target Layer 1 command tags and propagate back through the bridge path to the actuators.",
                                            name="Intro",
                                            basis="42px",
                                            style={"fontSize": "14px"},
                                        ),
                                    ],
                                    name="HeroText",
                                    grow=1,
                                    style={"gap": "6px"},
                                ),
                                card(
                                    [
                                        note_label(
                                            "Operator Notes",
                                            name="HeroNotesTitle",
                                            basis="18px",
                                            style={
                                                "color": "#8ba3b9",
                                                "fontSize": "11px",
                                                "fontWeight": 700,
                                                "letterSpacing": "0.08em",
                                                "textTransform": "uppercase",
                                            },
                                        ),
                                        note_label("0-100 forces an output immediately.", name="HeroNote1", basis="20px"),
                                        note_label("-1 releases an override back to PLC ownership.", name="HeroNote2", basis="20px"),
                                        note_label("Use the host browser for Perspective sessions.", name="HeroNote3", basis="20px"),
                                    ],
                                    name="HeroNotes",
                                    basis="340px",
                                    style={
                                        "backgroundColor": "#0a1422",
                                        "border": "1px solid #27415a",
                                        "gap": "6px",
                                        "padding": "14px",
                                    },
                                ),
                            ],
                            basis="auto",
                            name="HeroTop",
                            style={"alignItems": "stretch", "flexWrap": "wrap", "gap": "18px"},
                        ),
                    ],
                    name="Hero",
                    style={
                        "backgroundColor": "#0d1828",
                        "border": "1px solid #1f3a52",
                        "boxShadow": "0 24px 50px rgba(2, 6, 23, 0.34)",
                        "padding": "22px",
                    },
                ),
                row(
                    [
                        panel_for_profile("Main"),
                        panel_for_profile("Backup"),
                    ],
                    basis="auto",
                    name="Panels",
                    style={"alignItems": "stretch", "flexWrap": "wrap", "gap": "24px"},
                ),
            ],
            "meta": {"name": "root"},
            "props": {
                "direction": "column",
                "style": {
                    "backgroundColor": "#07111d",
                    "backgroundImage": "radial-gradient(circle at top left, rgba(56, 189, 248, 0.16), transparent 34%), radial-gradient(circle at top right, rgba(245, 158, 11, 0.14), transparent 30%)",
                    "gap": "24px",
                    "minHeight": "100%",
                    "padding": "28px",
                },
            },
            "type": "ia.container.flex",
        },
    }


def build_page_config() -> dict:
    return {
        "pages": {
            "/": {
                "title": "IAEA RCS SCADA",
                "viewPath": "RCS/Overview",
            }
        },
        "sharedDocks": {},
    }


def build_session_props() -> dict:
    return {
        "custom": {},
        "props": {
            "device": {},
            "geolocation": {},
            "locale": "en-US",
            "theme": "light",
            "timeZoneId": "America/New_York",
        },
    }


def build_project_files(root: Path) -> Path:
    project_dir = root / PROJECT_NAME
    project_dir.mkdir(parents=True, exist_ok=True)

    write_json(
        project_dir / "project.json",
        {
            "title": "IAEA RCS SCADA",
            "description": "Perspective overview and override controls for the IAEA RCS PLC demo",
            "parent": "",
            "enabled": True,
            "inheritable": False,
        },
    )

    page_config_dir = project_dir / "com.inductiveautomation.perspective" / "page-config"
    write_json(page_config_dir / "config.json", build_page_config())
    build_resource_manifest(page_config_dir, ["config.json"])

    session_props_dir = project_dir / "com.inductiveautomation.perspective" / "session-props"
    write_json(session_props_dir / "props.json", build_session_props())
    build_resource_manifest(session_props_dir, ["props.json"])

    view_dir = project_dir / "com.inductiveautomation.perspective" / "views" / "RCS" / "Overview"
    write_json(view_dir / "view.json", build_view_json())
    build_resource_manifest(view_dir, ["view.json"])

    return project_dir


def ensure_opc_server(conn: sqlite3.Connection, server: OpcServerConfig) -> None:
    cur = conn.cursor()
    row = cur.execute("SELECT OPCSERVERS_ID FROM OPCSERVERS WHERE NAME = ?", (server.name,)).fetchone()
    if row:
        server_id = int(row[0])
        cur.execute(
            """
            UPDATE OPCSERVERS
               SET TYPE = ?, DESCRIPTION = ?, READONLY = 0
             WHERE OPCSERVERS_ID = ?
            """,
            ("com.inductiveautomation.OpcUaServerType", server.description, server_id),
        )
    else:
        server_id = int(cur.execute("SELECT COALESCE(MAX(OPCSERVERS_ID), 0) + 1 FROM OPCSERVERS").fetchone()[0])
        cur.execute(
            """
            INSERT INTO OPCSERVERS (OPCSERVERS_ID, NAME, TYPE, DESCRIPTION, READONLY)
            VALUES (?, ?, ?, ?, 0)
            """,
            (server_id, server.name, "com.inductiveautomation.OpcUaServerType", server.description),
        )

    connection_row = cur.execute(
        "SELECT SERVERSETTINGSID FROM OPCUACONNECTIONSETTINGS WHERE SERVERSETTINGSID = ?",
        (server_id,),
    ).fetchone()

    connection_values = (
        server_id,
        2,
        1,
        server.endpoint,
        server.endpoint,
        "None",
        "None",
        None,
        "1dec500a51e36debd310d5418db630fa",
        None,
        5000,
        5000,
        60000,
        120000,
        8192,
        8192,
        2,
        65535,
        33554432,
        2147483647,
        2147483647,
        8192,
        1,
        15000,
        10000,
        "OBJECTS_FOLDER",
        0,
        "client",
        "1dec500a51e36debd310d5418db630fa",
        0,
        3,
        None,
        None,
        None,
    )

    if connection_row:
        cur.execute(
            """
            UPDATE OPCUACONNECTIONSETTINGS
               SET VERSION = ?,
                   ENABLED = ?,
                   DISCOVERYURL = ?,
                   ENDPOINTURL = ?,
                   SECURITYPOLICY = ?,
                   SECURITYMODE = ?,
                   USERNAME = ?,
                   PASSWORD = ?,
                   HOSTOVERRIDE = ?,
                   CONNECTTIMEOUT = ?,
                   ACKNOWLEDGETIMEOUT = ?,
                   REQUESTTIMEOUT = ?,
                   SESSIONTIMEOUT = ?,
                   MAXPEROPERATION = ?,
                   MAXREFERENCESPERNODE = ?,
                   MAXPENDINGPUBLISHREQUESTS = ?,
                   MAXNOTIFICATIONSPERPUBLISH = ?,
                   MAXMESSAGESIZE = ?,
                   MAXARRAYLENGTH = ?,
                   MAXSTRINGLENGTH = ?,
                   TYPEDICTIONARYFRAGMENTSIZE = ?,
                   KEEPALIVEFAILURESALLOWED = ?,
                   KEEPALIVEINTERVAL = ?,
                   KEEPALIVETIMEOUT = ?,
                   BROWSEORIGIN = ?,
                   CERTIFICATEVALIDATIONENABLED = ?,
                   KEYSTOREALIAS = ?,
                   KEYSTOREALIASPASSWORD = ?,
                   FAILOVERENABLED = ?,
                   FAILOVERTHRESHOLD = ?,
                   FAILOVERDISCOVERYURL = ?,
                   FAILOVERENDPOINTURL = ?,
                   FAILOVERHOSTOVERRIDE = ?
             WHERE SERVERSETTINGSID = ?
            """,
            connection_values[1:] + (server_id,),
        )
    else:
        cur.execute(
            """
            INSERT INTO OPCUACONNECTIONSETTINGS (
                SERVERSETTINGSID, VERSION, ENABLED, DISCOVERYURL, ENDPOINTURL,
                SECURITYPOLICY, SECURITYMODE, USERNAME, PASSWORD, HOSTOVERRIDE,
                CONNECTTIMEOUT, ACKNOWLEDGETIMEOUT, REQUESTTIMEOUT, SESSIONTIMEOUT,
                MAXPEROPERATION, MAXREFERENCESPERNODE, MAXPENDINGPUBLISHREQUESTS,
                MAXNOTIFICATIONSPERPUBLISH, MAXMESSAGESIZE, MAXARRAYLENGTH,
                MAXSTRINGLENGTH, TYPEDICTIONARYFRAGMENTSIZE, KEEPALIVEFAILURESALLOWED,
                KEEPALIVEINTERVAL, KEEPALIVETIMEOUT, BROWSEORIGIN,
                CERTIFICATEVALIDATIONENABLED, KEYSTOREALIAS, KEYSTOREALIASPASSWORD,
                FAILOVERENABLED, FAILOVERTHRESHOLD, FAILOVERDISCOVERYURL,
                FAILOVERENDPOINTURL, FAILOVERHOSTOVERRIDE
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            connection_values,
        )


def ensure_folder(conn: sqlite3.Connection, provider_id: int, folder_id: str | None, name: str, rank: int) -> str:
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT ID
          FROM TAGCONFIG
         WHERE PROVIDERID = ?
           AND COALESCE(FOLDERID, '') = COALESCE(?, '')
           AND NAME = ?
        """,
        (provider_id, folder_id, name),
    ).fetchone()
    cfg = json.dumps({"name": name, "tagType": "Folder"}, indent=2)
    if row:
        tag_id = str(row[0])
        cur.execute(
            "UPDATE TAGCONFIG SET CFG = ?, RANK = ?, NAME = ? WHERE ID = ?",
            (cfg, rank, name, tag_id),
        )
        return tag_id

    tag_id = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO TAGCONFIG (ID, PROVIDERID, FOLDERID, CFG, RANK, NAME) VALUES (?, ?, ?, ?, ?, ?)",
        (tag_id, provider_id, folder_id, cfg, rank, name),
    )
    return tag_id


def ensure_opc_tag(
    conn: sqlite3.Connection,
    *,
    provider_id: int,
    folder_id: str,
    name: str,
    opc_server: str,
    rank: int,
) -> None:
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT ID
          FROM TAGCONFIG
         WHERE PROVIDERID = ?
           AND COALESCE(FOLDERID, '') = COALESCE(?, '')
           AND NAME = ?
        """,
        (provider_id, folder_id, name),
    ).fetchone()
    cfg = json.dumps(
        {
            "name": name,
            "tagType": "AtomicTag",
            "valueSource": "opc",
            "opcServer": opc_server,
            "opcItemPath": f"ns=2;s={name}",
            "dataType": "Int4",
            "tagGroup": "Default",
            "enabled": True,
        },
        indent=2,
    )

    if row:
        cur.execute(
            "UPDATE TAGCONFIG SET CFG = ?, RANK = ?, NAME = ? WHERE ID = ?",
            (cfg, rank, name, str(row[0])),
        )
        return

    cur.execute(
        "INSERT INTO TAGCONFIG (ID, PROVIDERID, FOLDERID, CFG, RANK, NAME) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), provider_id, folder_id, cfg, rank, name),
    )


def seed_tags(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        for server in OPC_SERVERS:
            ensure_opc_server(conn, server)

        provider_id = 0
        root_id = ensure_folder(conn, provider_id, None, "RCS", 1)

        for index, (profile, server_name) in enumerate((("Main", MAIN_SERVER_NAME), ("Backup", BACKUP_SERVER_NAME)), start=1):
            profile_id = ensure_folder(conn, provider_id, root_id, profile, index)
            folders: dict[str, str] = {}
            for rank, folder_name in enumerate(("Sensors", "Actuators", "Summary", "Commands", "Bridge"), start=1):
                folders[folder_name] = ensure_folder(conn, provider_id, profile_id, folder_name, rank)

            for rank, (folder_name, point_name) in enumerate(PROFILE_POINTS[profile] + COMMON_POINTS, start=1):
                ensure_opc_tag(
                    conn,
                    provider_id=provider_id,
                    folder_id=folders[folder_name],
                    name=point_name,
                    opc_server=server_name,
                    rank=rank,
                )

        conn.commit()
    finally:
        conn.close()


def wait_for_status(url: str, expected: str, timeout_sec: int = 180) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            response = subprocess.run(
                ["curl", "-fsS", url],
                check=True,
                text=True,
                capture_output=True,
            )
            payload = json.loads(response.stdout)
            if payload.get("state") == expected:
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for {url} to report {expected!r}")


def provision(compose_dir: Path, *, skip_restart: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="ignition-scada-") as tmp_dir_name:
        tmp_dir = Path(tmp_dir_name)
        project_dir = build_project_files(tmp_dir / "projects")
        db_copy = tmp_dir / "config.idb"

        run(["docker", "compose", "cp", f"{IGNITION_SERVICE}:{CONTAINER_DB_PATH}", str(db_copy)], cwd=compose_dir)
        seed_tags(db_copy)

        run(["docker", "compose", "stop", IGNITION_SERVICE], cwd=compose_dir)
        try:
            run(["docker", "compose", "cp", str(db_copy), f"{IGNITION_SERVICE}:{CONTAINER_DB_PATH}"], cwd=compose_dir)
            run(
                ["docker", "compose", "cp", str(project_dir), f"{IGNITION_SERVICE}:{CONTAINER_PROJECTS_DIR}"],
                cwd=compose_dir,
            )
        finally:
            run(["docker", "compose", "start", IGNITION_SERVICE], cwd=compose_dir)

    if skip_restart:
        return

    wait_for_status("http://127.0.0.1:9088/StatusPing", "RUNNING")


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision Ignition with the IAEA RCS Perspective project and OPC tags")
    parser.add_argument(
        "--compose-dir",
        default=".",
        help="Directory that contains docker-compose.yml",
    )
    parser.add_argument(
        "--skip-healthcheck",
        action="store_true",
        help="Do not wait for the Ignition gateway status ping after restarting",
    )
    args = parser.parse_args()

    compose_dir = Path(args.compose_dir).resolve()
    if not (compose_dir / "docker-compose.yml").exists():
        raise SystemExit(f"No docker-compose.yml found under {compose_dir}")

    provision(compose_dir, skip_restart=args.skip_healthcheck)
    print(f"Provisioned Ignition project {PROJECT_NAME!r}")
    print(f"Perspective URL: http://127.0.0.1:9088/data/perspective/client/{PROJECT_NAME}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

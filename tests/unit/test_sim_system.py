import json

from dashboard.sim_system import (
    build_risk_service_compatible_sim_system,
    legacy_to_sectioned_sim_system,
    load_local_sim_system,
    sectioned_to_legacy_sim_system,
)


def test_legacy_to_sectioned_sim_system_preserves_sections_and_links():
    legacy = {
        "version": "1.0",
        "variables": {
            "PLC-1": {"type": "PLC", "domain": "cyber"},
            "PUMP-1": {"type": "PumpModule"},
            "VALVE-1": {"type": "Valve", "category": "physical"},
        },
        "connections": [
            {"source": "PLC-1", "target": "VALVE-1", "s_attr": "Control", "t_attr": "Input"},
            {"source": "PUMP-1", "target": "VALVE-1", "s_attr": "Feed", "t_attr": "Intake"},
        ],
    }

    sectioned = legacy_to_sectioned_sim_system(legacy)

    assert sectioned["version"] == "1.0"
    assert "PLC-1" in sectioned["digital"]
    assert "PUMP-1" in sectioned["physical"]
    assert "VALVE-1" in sectioned["physical"]
    assert sectioned["digital"]["PLC-1"]["target"]["VALVE-1"] == "Control"
    assert sectioned["physical"]["VALVE-1"]["source"]["PLC-1"] == "Input"
    assert sectioned["physical"]["PUMP-1"]["target"]["VALVE-1"] == "Feed"


def test_load_local_sim_system_accepts_sectioned_payload(tmp_path):
    sectioned = {
        "version": "1.0",
        "digital": {
            "PLC-1": {
                "type": "controller",
                "source": {},
                "target": {"VALVE-1": "Control"},
            }
        },
        "physical": {
            "VALVE-1": {
                "type": "valve",
                "source": {"PLC-1": "Input"},
                "target": {},
            }
        },
        "flow": {},
        "function": {},
    }
    sim_path = tmp_path / "sectioned_sim_system.json"
    sim_path.write_text(json.dumps(sectioned), encoding="utf-8")

    legacy = load_local_sim_system(sim_path)

    assert legacy["variables"]["PLC-1"]["category"] == "digital"
    assert legacy["variables"]["PLC-1"]["domain"] == "cyber"
    assert legacy["variables"]["VALVE-1"]["category"] == "physical"
    assert legacy["variables"]["VALVE-1"]["domain"] == "physical"
    assert legacy["connections"] == [
        {
            "source": "PLC-1",
            "target": "VALVE-1",
            "s_attr": "Control",
            "t_attr": "Input",
        }
    ]


def test_sectioned_to_legacy_sim_system_round_trips_metadata():
    sectioned = {
        "version": "1.0",
        "metadata": {"source": "unit-test"},
        "digital": {
            "HMI-1": {"type": "hmi", "source": {}, "target": {}},
        },
        "physical": {},
        "flow": {},
        "function": {},
    }

    legacy = sectioned_to_legacy_sim_system(sectioned)

    assert legacy["metadata"] == {"source": "unit-test"}
    assert legacy["variables"]["HMI-1"]["category"] == "digital"
    assert legacy["variables"]["HMI-1"]["domain"] == "cyber"
    assert legacy["connections"] == []


def test_build_risk_service_compatible_sim_system_collapses_signal_relays():
    sectioned = {
        "version": "1.0",
        "digital": {
            "PLC-Main": {
                "type": "PLC",
                "source": {"S_MAIN_PT455": "signal"},
                "target": {"SD_MAIN_455B": "signal", "SD_MAIN_HEAT": "signal"},
            },
            "PLC-Backup": {
                "type": "PLC",
                "source": {"S_BACKUP_PT458": "signal"},
                "target": {"SD_BACKUP_455B": "signal", "SD_BACKUP_HEAT": "signal"},
            },
            "PT-455": {
                "type": "tr_press",
                "source": {"P_PT455": "pressure"},
                "target": {"S_MAIN_PT455": "signal"},
            },
            "PT-458": {
                "type": "tr_press",
                "source": {"P_PT458": "pressure"},
                "target": {"S_BACKUP_PT458": "signal"},
            },
            "VC-PV455B": {
                "type": "valve_ctrl",
                "source": {"SD_MAIN_455B": "signal", "SD_BACKUP_455B": "signal"},
                "target": {"CTRL_SPRAY_1": "air_pressure"},
            },
            "Heat-Ctrl": {
                "type": "heater_ctrl",
                "source": {"SD_MAIN_HEAT": "signal", "SD_BACKUP_HEAT": "signal"},
                "target": {"CTRL_HEATER_1": "electricity"},
            },
        },
        "physical": {},
        "flow": {
            "P_PT455": {"type": "pressure", "source": {}, "target": {"PT-455": "tr_press"}},
            "P_PT458": {"type": "pressure", "source": {}, "target": {"PT-458": "tr_press"}},
            "CTRL_SPRAY_1": {"type": "air_pressure", "source": {"VC-PV455B": "valve_ctrl"}, "target": {}},
            "CTRL_HEATER_1": {"type": "electricity", "source": {"Heat-Ctrl": "heater_ctrl"}, "target": {}},
            "S_MAIN_PT455": {"type": "signal", "source": {"PT-455": "tr_press"}, "target": {"PLC-Main": "PLC"}},
            "S_BACKUP_PT458": {"type": "signal", "source": {"PT-458": "tr_press"}, "target": {"PLC-Backup": "PLC"}},
            "SD_MAIN_455B": {"type": "signal", "source": {"PLC-Main": "PLC"}, "target": {"VC-PV455B": "valve_ctrl"}},
            "SD_BACKUP_455B": {"type": "signal", "source": {"PLC-Backup": "PLC"}, "target": {"VC-PV455B": "valve_ctrl"}},
            "SD_MAIN_HEAT": {"type": "signal", "source": {"PLC-Main": "PLC"}, "target": {"Heat-Ctrl": "heater_ctrl"}},
            "SD_BACKUP_HEAT": {"type": "signal", "source": {"PLC-Backup": "PLC"}, "target": {"Heat-Ctrl": "heater_ctrl"}},
        },
        "function": {},
    }

    compatible = build_risk_service_compatible_sim_system(sectioned)

    assert "S_MAIN_PT455" not in compatible["flow"]
    assert "SD_MAIN_455B" not in compatible["flow"]
    assert compatible["digital"]["PT-455"]["target"] == {}
    assert set(compatible["digital"]["PT-455"]["networks"].keys()) == {"process_main_net"}
    assert set(compatible["digital"]["PT-458"]["networks"].keys()) == {"process_backup_net"}
    assert compatible["digital"]["PLC-Main"]["source"] == {}
    assert compatible["digital"]["PLC-Main"]["target"] == {}
    assert set(compatible["digital"]["PLC-Main"]["networks"].keys()) == {"control_main_net", "mgmt_main_net"}
    assert set(compatible["digital"]["PLC-Backup"]["networks"].keys()) == {"control_backup_net", "mgmt_backup_net"}
    assert compatible["digital"]["VC-PV455B"]["source"] == {}
    assert set(compatible["digital"]["VC-PV455B"]["networks"].keys()) == {"process_main_net", "process_backup_net"}
    assert compatible["digital"]["Heat-Ctrl"]["source"] == {}
    assert set(compatible["digital"]["Heat-Ctrl"]["networks"].keys()) == {"process_main_net", "process_backup_net"}
    assert compatible["digital"]["process_main_net"]["type"] == "network"
    assert compatible["digital"]["process_backup_firewall"]["type"] == "Firewall"


def test_build_risk_service_compatible_sim_system_normalizes_generic_digital_types():
    sectioned = {
        "version": "1.0",
        "digital": {
            "PLC-Main": {
                "type": "controller",
                "source": {},
                "target": {},
            },
            "edge-fw": {
                "type": "firewall",
                "source": {},
                "target": {},
            },
            "ops-hmi": {
                "type": "hmi",
                "source": {},
                "target": {},
            },
            "db-host": {
                "type": "database",
                "source": {},
                "target": {},
            },
            "hist-1": {
                "type": "historian",
                "source": {},
                "target": {},
            },
            "eng-ws": {
                "type": "workstation",
                "source": {},
                "target": {},
            },
        },
        "physical": {},
        "flow": {},
        "function": {},
    }

    compatible = build_risk_service_compatible_sim_system(sectioned)

    assert compatible["digital"]["PLC-Main"]["type"] == "PLC"
    assert compatible["digital"]["edge-fw"]["type"] == "Firewall"
    assert compatible["digital"]["ops-hmi"]["type"] == "HMI"
    assert compatible["digital"]["db-host"]["type"] == "Database"
    assert compatible["digital"]["hist-1"]["type"] == "DataHistorian"
    assert compatible["digital"]["eng-ws"]["type"] == "Computer"

PROGRAM prog0
  VAR
    pt455_pv AT %IW100 : INT;
    pt455_status AT %IW101 : INT;
    pt456_pv AT %IW102 : INT;
    pt456_status AT %IW103 : INT;
    pt457_pv AT %IW104 : INT;
    pt457_status AT %IW105 : INT;

    hv_owner AT %IW106 : INT;
    hv_applied AT %IW107 : INT;
    hv_last_writer AT %IW108 : INT;
    hv_status AT %IW109 : INT;
    pvb_owner AT %IW110 : INT;
    pvb_applied AT %IW111 : INT;
    pvb_last_writer AT %IW112 : INT;
    pvb_status AT %IW113 : INT;
    pvc_owner AT %IW114 : INT;
    pvc_applied AT %IW115 : INT;
    pvc_last_writer AT %IW116 : INT;
    pvc_status AT %IW117 : INT;
    heat_owner AT %IW118 : INT;
    heat_applied AT %IW119 : INT;
    heat_last_writer AT %IW120 : INT;
    heat_status AT %IW121 : INT;

    hv_owner_claim AT %QW100 : INT;
    hv_command_request AT %QW101 : INT;
    pvb_owner_claim AT %QW102 : INT;
    pvb_command_request AT %QW103 : INT;
    pvc_owner_claim AT %QW104 : INT;
    pvc_command_request AT %QW105 : INT;
    heat_owner_claim AT %QW106 : INT;
    heat_command_request AT %QW107 : INT;

    exported_pt455 AT %QW10 : INT;
    exported_pt456 AT %QW11 : INT;
    exported_pt457 AT %QW12 : INT;
    average_pressure AT %QW13 : INT;
    health_code AT %QW14 : INT;
    exported_hv_owner AT %QW15 : INT;
    exported_hv_command AT %QW16 : INT;
    exported_pvb_owner AT %QW17 : INT;
    exported_pvb_command AT %QW18 : INT;
    exported_pvc_owner AT %QW19 : INT;
    exported_pvc_command AT %QW20 : INT;
    exported_heat_owner AT %QW21 : INT;
    exported_heat_command AT %QW22 : INT;
  END_VAR

  exported_pt455 := pt455_pv;
  exported_pt456 := pt456_pv;
  exported_pt457 := pt457_pv;
  average_pressure := (pt455_pv + pt456_pv + pt457_pv) / 3;

  hv_owner_claim := 1;
  pvb_owner_claim := 1;
  pvc_owner_claim := 1;
  heat_owner_claim := 1;

  IF average_pressure >= 4570 THEN
    hv_command_request := 25;
    pvb_command_request := 80;
    pvc_command_request := 70;
    heat_command_request := 15;
  ELSIF average_pressure >= 4550 THEN
    hv_command_request := 45;
    pvb_command_request := 60;
    pvc_command_request := 55;
    heat_command_request := 30;
  ELSE
    hv_command_request := 70;
    pvb_command_request := 35;
    pvc_command_request := 25;
    heat_command_request := 65;
  END_IF;

  IF (pt455_status = 1) AND (pt456_status = 1) AND (pt457_status = 1) THEN
    health_code := 1;
  ELSE
    health_code := 0;
  END_IF;

  exported_hv_owner := hv_owner;
  exported_hv_command := hv_applied;
  exported_pvb_owner := pvb_owner;
  exported_pvb_command := pvb_applied;
  exported_pvc_owner := pvc_owner;
  exported_pvc_command := pvc_applied;
  exported_heat_owner := heat_owner;
  exported_heat_command := heat_applied;
END_PROGRAM


CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION

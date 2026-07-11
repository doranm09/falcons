# Validation Matrix

Generated from `docker-compose.yml` by `generate_validation_matrix.py`. Do not hand-edit this file.

## Summary

- Service/interface permutations: `495`
- Expected allow results: `141`
- Expected blocked results: `354`
- Route-isolation checks: `5`
- Host published-port checks: `11`

Boundary distribution:
- `Intra-zone: Layer 0 (backup cell)`: `42`
- `Intra-zone: Layer 0 (main cell)`: `42`
- `Intra-zone: Layer 2`: `12`
- `Intra-zone: Layer 4`: `3`
- `Layer 0 (backup cell) -> Layer 0 (main cell) isolation`: `7`
- `Layer 0 (backup cell) -> Layer 1 (main PLC segment) isolation`: `2`
- `Layer 0 (backup cell) -> Layer 1 management (backup) isolation`: `2`
- `Layer 0 (backup cell) -> Layer 1 management (main) isolation`: `2`
- `Layer 0 (backup cell) -> Layer 2 isolation`: `6`
- `Layer 0 (backup cell) -> Layer 3 isolation`: `2`
- `Layer 0 (backup cell) -> Layer 4 isolation`: `3`
- `Layer 0 (main cell) -> Layer 0 (backup cell) isolation`: `7`
- `Layer 0 (main cell) -> Layer 1 (backup PLC segment) isolation`: `2`
- `Layer 0 (main cell) -> Layer 1 management (backup) isolation`: `14`
- `Layer 0 (main cell) -> Layer 1 management (main) isolation`: `14`
- `Layer 0 (main cell) -> Layer 2 isolation`: `42`
- `Layer 0 (main cell) -> Layer 3 isolation`: `14`
- `Layer 0 (main cell) -> Layer 4 isolation`: `21`
- `Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation`: `7`
- `Layer 1 (backup PLC segment) -> Layer 1 (main PLC segment) isolation`: `2`
- `Layer 1 (backup PLC segment) -> Layer 1 management (main) isolation`: `2`
- `Layer 1 (backup PLC segment) -> Layer 3 isolation`: `2`
- `Layer 1 (backup PLC segment) -> Layer 4 isolation`: `3`
- `Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation`: `7`
- `Layer 1 (main PLC segment) -> Layer 1 (backup PLC segment) isolation`: `2`
- `Layer 1 (main PLC segment) -> Layer 1 management (backup) isolation`: `2`
- `Layer 1 (main PLC segment) -> Layer 3 isolation`: `2`
- `Layer 1 (main PLC segment) -> Layer 4 isolation`: `3`
- `Layer 1 / Layer 0 (backup cell)`: `21`
- `Layer 1 / Layer 0 (main cell)`: `21`
- `Layer 2 -> Layer 0 (backup cell) isolation`: `21`
- `Layer 2 -> Layer 0 (main cell) isolation`: `21`
- `Layer 2 -> Layer 1 (backup PLC segment) isolation`: `2`
- `Layer 2 -> Layer 1 (main PLC segment) isolation`: `2`
- `Layer 2 -> Layer 1 management (backup) isolation`: `6`
- `Layer 2 -> Layer 1 management (main) isolation`: `6`
- `Layer 2 / Layer 1`: `20`
- `Layer 3 -> Layer 0 (backup cell) isolation`: `7`
- `Layer 3 -> Layer 0 (main cell) isolation`: `7`
- `Layer 3 -> Layer 1 (backup PLC segment) isolation`: `2`
- `Layer 3 -> Layer 1 (main PLC segment) isolation`: `2`
- `Layer 3 -> Layer 1 management (backup) isolation`: `2`
- `Layer 3 -> Layer 1 management (main) isolation`: `2`
- `Layer 3 / Layer 2`: `12`
- `Layer 3 / Layer 2 + Layer 4 / Layer 3`: `9`
- `Layer 4 -> Layer 0 (backup cell) isolation`: `14`
- `Layer 4 -> Layer 0 (main cell) isolation`: `14`
- `Layer 4 -> Layer 1 (backup PLC segment) isolation`: `4`
- `Layer 4 -> Layer 1 (main PLC segment) isolation`: `4`
- `Layer 4 -> Layer 1 management (backup) isolation`: `4`
- `Layer 4 -> Layer 1 management (main) isolation`: `4`
- `Layer 4 / Layer 3`: `7`
- `Layer 4 / Layer 3 + Layer 3 / Layer 2`: `12`

## Service Reachability Matrix

| Source | Destination | Probe IP | Port | Expected | Layer Under Test | Command |
| --- | --- | --- | --- | --- | --- | --- |
| database | workstation (l4_net) | 10.4.50.10 | 80 | allow | Intra-zone: Layer 4 | probe_port database 10.4.50.10 80 |
| database | workstation (l4_net) | 10.4.50.10 | 443 | allow | Intra-zone: Layer 4 | probe_port database 10.4.50.10 443 |
| database | historian (l3_net) | 10.3.50.10 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 | expect_blocked_port database 10.3.50.10 443 |
| database | historian (l3_net) | 10.3.50.10 | 4840 | blocked (firewall-2) | Layer 4 / Layer 3 | expect_blocked_port database 10.3.50.10 4840 |
| database | hmi (l2_net) | 10.2.50.10 | 80 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port database 10.2.50.10 80 |
| database | hmi (l2_net) | 10.2.50.10 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port database 10.2.50.10 443 |
| database | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port database 10.2.50.20 80 |
| database | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port database 10.2.50.20 443 |
| database | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port database 10.2.50.30 22 |
| database | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port database 10.2.50.30 443 |
| database | plc-backup (l1_backup) | 10.2.23.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port database 10.2.23.10 502 |
| database | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port database 10.2.23.10 44818 |
| database | plc-main (l1_main) | 10.1.13.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 (main PLC segment) isolation | expect_blocked_port database 10.1.13.10 502 |
| database | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 (main PLC segment) isolation | expect_blocked_port database 10.1.13.10 44818 |
| database | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 management (main) isolation | expect_blocked_port database 10.0.13.10 502 |
| database | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 management (main) isolation | expect_blocked_port database 10.0.13.10 44818 |
| database | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 management (backup) isolation | expect_blocked_port database 10.0.23.10 502 |
| database | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 management (backup) isolation | expect_blocked_port database 10.0.23.10 44818 |
| database | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port database 10.3.13.1 502 |
| database | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port database 10.3.13.2 502 |
| database | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port database 10.3.13.3 502 |
| database | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port database 10.3.13.5 502 |
| database | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port database 10.3.13.11 502 |
| database | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port database 10.3.13.12 502 |
| database | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port database 10.3.13.13 502 |
| database | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port database 10.4.23.1 502 |
| database | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port database 10.4.23.2 502 |
| database | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port database 10.4.23.3 502 |
| database | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port database 10.4.23.5 502 |
| database | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port database 10.4.23.12 502 |
| database | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port database 10.4.23.13 502 |
| database | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port database 10.4.23.14 502 |
| workstation | database (l4_net) | 10.4.50.20 | 5432 | allow | Intra-zone: Layer 4 | probe_port workstation 10.4.50.20 5432 |
| workstation | historian (l3_net) | 10.3.50.10 | 443 | allow | Layer 4 / Layer 3 | probe_port workstation 10.3.50.10 443 |
| workstation | historian (l3_net) | 10.3.50.10 | 4840 | allow | Layer 4 / Layer 3 | probe_port workstation 10.3.50.10 4840 |
| workstation | hmi (l2_net) | 10.2.50.10 | 80 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port workstation 10.2.50.10 80 |
| workstation | hmi (l2_net) | 10.2.50.10 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port workstation 10.2.50.10 443 |
| workstation | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port workstation 10.2.50.20 80 |
| workstation | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port workstation 10.2.50.20 443 |
| workstation | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port workstation 10.2.50.30 22 |
| workstation | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 + Layer 3 / Layer 2 | expect_blocked_port workstation 10.2.50.30 443 |
| workstation | plc-backup (l1_backup) | 10.2.23.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port workstation 10.2.23.10 502 |
| workstation | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port workstation 10.2.23.10 44818 |
| workstation | plc-main (l1_main) | 10.1.13.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 (main PLC segment) isolation | expect_blocked_port workstation 10.1.13.10 502 |
| workstation | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 (main PLC segment) isolation | expect_blocked_port workstation 10.1.13.10 44818 |
| workstation | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 management (main) isolation | expect_blocked_port workstation 10.0.13.10 502 |
| workstation | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 management (main) isolation | expect_blocked_port workstation 10.0.13.10 44818 |
| workstation | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 4 -> Layer 1 management (backup) isolation | expect_blocked_port workstation 10.0.23.10 502 |
| workstation | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 4 -> Layer 1 management (backup) isolation | expect_blocked_port workstation 10.0.23.10 44818 |
| workstation | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port workstation 10.3.13.1 502 |
| workstation | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port workstation 10.3.13.2 502 |
| workstation | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port workstation 10.3.13.3 502 |
| workstation | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port workstation 10.3.13.5 502 |
| workstation | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port workstation 10.3.13.11 502 |
| workstation | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port workstation 10.3.13.12 502 |
| workstation | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 4 -> Layer 0 (main cell) isolation | expect_blocked_port workstation 10.3.13.13 502 |
| workstation | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port workstation 10.4.23.1 502 |
| workstation | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port workstation 10.4.23.2 502 |
| workstation | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port workstation 10.4.23.3 502 |
| workstation | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port workstation 10.4.23.5 502 |
| workstation | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port workstation 10.4.23.12 502 |
| workstation | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port workstation 10.4.23.13 502 |
| workstation | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 4 -> Layer 0 (backup cell) isolation | expect_blocked_port workstation 10.4.23.14 502 |
| historian | workstation (l4_net) | 10.4.50.10 | 80 | blocked (firewall-2) | Layer 4 / Layer 3 | expect_blocked_port historian 10.4.50.10 80 |
| historian | workstation (l4_net) | 10.4.50.10 | 443 | blocked (firewall-2) | Layer 4 / Layer 3 | expect_blocked_port historian 10.4.50.10 443 |
| historian | database (l4_net) | 10.4.50.20 | 5432 | blocked (firewall-2) | Layer 4 / Layer 3 | expect_blocked_port historian 10.4.50.20 5432 |
| historian | hmi (l2_net) | 10.2.50.10 | 80 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port historian 10.2.50.10 80 |
| historian | hmi (l2_net) | 10.2.50.10 | 443 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port historian 10.2.50.10 443 |
| historian | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port historian 10.2.50.20 80 |
| historian | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port historian 10.2.50.20 443 |
| historian | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port historian 10.2.50.30 22 |
| historian | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port historian 10.2.50.30 443 |
| historian | plc-backup (l1_backup) | 10.2.23.10 | 502 | blocked (no route) | Layer 3 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port historian 10.2.23.10 502 |
| historian | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (no route) | Layer 3 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port historian 10.2.23.10 44818 |
| historian | plc-main (l1_main) | 10.1.13.10 | 502 | blocked (no route) | Layer 3 -> Layer 1 (main PLC segment) isolation | expect_blocked_port historian 10.1.13.10 502 |
| historian | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (no route) | Layer 3 -> Layer 1 (main PLC segment) isolation | expect_blocked_port historian 10.1.13.10 44818 |
| historian | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 3 -> Layer 1 management (main) isolation | expect_blocked_port historian 10.0.13.10 502 |
| historian | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 3 -> Layer 1 management (main) isolation | expect_blocked_port historian 10.0.13.10 44818 |
| historian | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 3 -> Layer 1 management (backup) isolation | expect_blocked_port historian 10.0.23.10 502 |
| historian | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 3 -> Layer 1 management (backup) isolation | expect_blocked_port historian 10.0.23.10 44818 |
| historian | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 3 -> Layer 0 (main cell) isolation | expect_blocked_port historian 10.3.13.1 502 |
| historian | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 3 -> Layer 0 (main cell) isolation | expect_blocked_port historian 10.3.13.2 502 |
| historian | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 3 -> Layer 0 (main cell) isolation | expect_blocked_port historian 10.3.13.3 502 |
| historian | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 3 -> Layer 0 (main cell) isolation | expect_blocked_port historian 10.3.13.5 502 |
| historian | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 3 -> Layer 0 (main cell) isolation | expect_blocked_port historian 10.3.13.11 502 |
| historian | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 3 -> Layer 0 (main cell) isolation | expect_blocked_port historian 10.3.13.12 502 |
| historian | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 3 -> Layer 0 (main cell) isolation | expect_blocked_port historian 10.3.13.13 502 |
| historian | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 3 -> Layer 0 (backup cell) isolation | expect_blocked_port historian 10.4.23.1 502 |
| historian | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 3 -> Layer 0 (backup cell) isolation | expect_blocked_port historian 10.4.23.2 502 |
| historian | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 3 -> Layer 0 (backup cell) isolation | expect_blocked_port historian 10.4.23.3 502 |
| historian | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 3 -> Layer 0 (backup cell) isolation | expect_blocked_port historian 10.4.23.5 502 |
| historian | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 3 -> Layer 0 (backup cell) isolation | expect_blocked_port historian 10.4.23.12 502 |
| historian | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 3 -> Layer 0 (backup cell) isolation | expect_blocked_port historian 10.4.23.13 502 |
| historian | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 3 -> Layer 0 (backup cell) isolation | expect_blocked_port historian 10.4.23.14 502 |
| engineer-ws | workstation (l4_net) | 10.4.50.10 | 80 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port engineer-ws 10.4.50.10 80 |
| engineer-ws | workstation (l4_net) | 10.4.50.10 | 443 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port engineer-ws 10.4.50.10 443 |
| engineer-ws | database (l4_net) | 10.4.50.20 | 5432 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port engineer-ws 10.4.50.20 5432 |
| engineer-ws | historian (l3_net) | 10.3.50.10 | 443 | allow | Layer 3 / Layer 2 | probe_port engineer-ws 10.3.50.10 443 |
| engineer-ws | historian (l3_net) | 10.3.50.10 | 4840 | allow | Layer 3 / Layer 2 | probe_port engineer-ws 10.3.50.10 4840 |
| engineer-ws | hmi (l2_net) | 10.2.50.10 | 80 | allow | Intra-zone: Layer 2 | probe_port engineer-ws 10.2.50.10 80 |
| engineer-ws | hmi (l2_net) | 10.2.50.10 | 443 | allow | Intra-zone: Layer 2 | probe_port engineer-ws 10.2.50.10 443 |
| engineer-ws | l2-jump (l2_net) | 10.2.50.30 | 22 | allow | Intra-zone: Layer 2 | probe_port engineer-ws 10.2.50.30 22 |
| engineer-ws | l2-jump (l2_net) | 10.2.50.30 | 443 | allow | Intra-zone: Layer 2 | probe_port engineer-ws 10.2.50.30 443 |
| engineer-ws | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 2 / Layer 1 | probe_port engineer-ws 10.2.23.10 502 |
| engineer-ws | plc-backup (l1_backup) | 10.2.23.10 | 44818 | allow | Layer 2 / Layer 1 | probe_port engineer-ws 10.2.23.10 44818 |
| engineer-ws | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 2 / Layer 1 | probe_port engineer-ws 10.1.13.10 502 |
| engineer-ws | plc-main (l1_main) | 10.1.13.10 | 44818 | allow | Layer 2 / Layer 1 | probe_port engineer-ws 10.1.13.10 44818 |
| engineer-ws | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 management (main) isolation | expect_blocked_port engineer-ws 10.0.13.10 502 |
| engineer-ws | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 management (main) isolation | expect_blocked_port engineer-ws 10.0.13.10 44818 |
| engineer-ws | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 management (backup) isolation | expect_blocked_port engineer-ws 10.0.23.10 502 |
| engineer-ws | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 management (backup) isolation | expect_blocked_port engineer-ws 10.0.23.10 44818 |
| engineer-ws | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port engineer-ws 10.3.13.1 502 |
| engineer-ws | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port engineer-ws 10.3.13.2 502 |
| engineer-ws | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port engineer-ws 10.3.13.3 502 |
| engineer-ws | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port engineer-ws 10.3.13.5 502 |
| engineer-ws | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port engineer-ws 10.3.13.11 502 |
| engineer-ws | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port engineer-ws 10.3.13.12 502 |
| engineer-ws | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port engineer-ws 10.3.13.13 502 |
| engineer-ws | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port engineer-ws 10.4.23.1 502 |
| engineer-ws | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port engineer-ws 10.4.23.2 502 |
| engineer-ws | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port engineer-ws 10.4.23.3 502 |
| engineer-ws | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port engineer-ws 10.4.23.5 502 |
| engineer-ws | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port engineer-ws 10.4.23.12 502 |
| engineer-ws | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port engineer-ws 10.4.23.13 502 |
| engineer-ws | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port engineer-ws 10.4.23.14 502 |
| hmi | workstation (l4_net) | 10.4.50.10 | 80 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port hmi 10.4.50.10 80 |
| hmi | workstation (l4_net) | 10.4.50.10 | 443 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port hmi 10.4.50.10 443 |
| hmi | database (l4_net) | 10.4.50.20 | 5432 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port hmi 10.4.50.20 5432 |
| hmi | historian (l3_net) | 10.3.50.10 | 443 | allow | Layer 3 / Layer 2 | probe_port hmi 10.3.50.10 443 |
| hmi | historian (l3_net) | 10.3.50.10 | 4840 | allow | Layer 3 / Layer 2 | probe_port hmi 10.3.50.10 4840 |
| hmi | engineer-ws (l2_net) | 10.2.50.20 | 80 | allow | Intra-zone: Layer 2 | probe_port hmi 10.2.50.20 80 |
| hmi | engineer-ws (l2_net) | 10.2.50.20 | 443 | allow | Intra-zone: Layer 2 | probe_port hmi 10.2.50.20 443 |
| hmi | l2-jump (l2_net) | 10.2.50.30 | 22 | allow | Intra-zone: Layer 2 | probe_port hmi 10.2.50.30 22 |
| hmi | l2-jump (l2_net) | 10.2.50.30 | 443 | allow | Intra-zone: Layer 2 | probe_port hmi 10.2.50.30 443 |
| hmi | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 2 / Layer 1 | probe_port hmi 10.2.23.10 502 |
| hmi | plc-backup (l1_backup) | 10.2.23.10 | 44818 | allow | Layer 2 / Layer 1 | probe_port hmi 10.2.23.10 44818 |
| hmi | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 2 / Layer 1 | probe_port hmi 10.1.13.10 502 |
| hmi | plc-main (l1_main) | 10.1.13.10 | 44818 | allow | Layer 2 / Layer 1 | probe_port hmi 10.1.13.10 44818 |
| hmi | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 management (main) isolation | expect_blocked_port hmi 10.0.13.10 502 |
| hmi | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 management (main) isolation | expect_blocked_port hmi 10.0.13.10 44818 |
| hmi | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 management (backup) isolation | expect_blocked_port hmi 10.0.23.10 502 |
| hmi | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 management (backup) isolation | expect_blocked_port hmi 10.0.23.10 44818 |
| hmi | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port hmi 10.3.13.1 502 |
| hmi | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port hmi 10.3.13.2 502 |
| hmi | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port hmi 10.3.13.3 502 |
| hmi | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port hmi 10.3.13.5 502 |
| hmi | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port hmi 10.3.13.11 502 |
| hmi | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port hmi 10.3.13.12 502 |
| hmi | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port hmi 10.3.13.13 502 |
| hmi | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port hmi 10.4.23.1 502 |
| hmi | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port hmi 10.4.23.2 502 |
| hmi | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port hmi 10.4.23.3 502 |
| hmi | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port hmi 10.4.23.5 502 |
| hmi | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port hmi 10.4.23.12 502 |
| hmi | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port hmi 10.4.23.13 502 |
| hmi | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port hmi 10.4.23.14 502 |
| l2-jump | workstation (l4_net) | 10.4.50.10 | 80 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port l2-jump 10.4.50.10 80 |
| l2-jump | workstation (l4_net) | 10.4.50.10 | 443 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port l2-jump 10.4.50.10 443 |
| l2-jump | database (l4_net) | 10.4.50.20 | 5432 | blocked (firewall-1) | Layer 3 / Layer 2 + Layer 4 / Layer 3 | expect_blocked_port l2-jump 10.4.50.20 5432 |
| l2-jump | historian (l3_net) | 10.3.50.10 | 443 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port l2-jump 10.3.50.10 443 |
| l2-jump | historian (l3_net) | 10.3.50.10 | 4840 | blocked (firewall-1) | Layer 3 / Layer 2 | expect_blocked_port l2-jump 10.3.50.10 4840 |
| l2-jump | hmi (l2_net) | 10.2.50.10 | 80 | allow | Intra-zone: Layer 2 | probe_port l2-jump 10.2.50.10 80 |
| l2-jump | hmi (l2_net) | 10.2.50.10 | 443 | allow | Intra-zone: Layer 2 | probe_port l2-jump 10.2.50.10 443 |
| l2-jump | engineer-ws (l2_net) | 10.2.50.20 | 80 | allow | Intra-zone: Layer 2 | probe_port l2-jump 10.2.50.20 80 |
| l2-jump | engineer-ws (l2_net) | 10.2.50.20 | 443 | allow | Intra-zone: Layer 2 | probe_port l2-jump 10.2.50.20 443 |
| l2-jump | plc-backup (l1_backup) | 10.2.23.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port l2-jump 10.2.23.10 502 |
| l2-jump | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 (backup PLC segment) isolation | expect_blocked_port l2-jump 10.2.23.10 44818 |
| l2-jump | plc-main (l1_main) | 10.1.13.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 (main PLC segment) isolation | expect_blocked_port l2-jump 10.1.13.10 502 |
| l2-jump | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 (main PLC segment) isolation | expect_blocked_port l2-jump 10.1.13.10 44818 |
| l2-jump | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 management (main) isolation | expect_blocked_port l2-jump 10.0.13.10 502 |
| l2-jump | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 management (main) isolation | expect_blocked_port l2-jump 10.0.13.10 44818 |
| l2-jump | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 2 -> Layer 1 management (backup) isolation | expect_blocked_port l2-jump 10.0.23.10 502 |
| l2-jump | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 2 -> Layer 1 management (backup) isolation | expect_blocked_port l2-jump 10.0.23.10 44818 |
| l2-jump | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port l2-jump 10.3.13.1 502 |
| l2-jump | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port l2-jump 10.3.13.2 502 |
| l2-jump | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port l2-jump 10.3.13.3 502 |
| l2-jump | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port l2-jump 10.3.13.5 502 |
| l2-jump | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port l2-jump 10.3.13.11 502 |
| l2-jump | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port l2-jump 10.3.13.12 502 |
| l2-jump | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 2 -> Layer 0 (main cell) isolation | expect_blocked_port l2-jump 10.3.13.13 502 |
| l2-jump | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port l2-jump 10.4.23.1 502 |
| l2-jump | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port l2-jump 10.4.23.2 502 |
| l2-jump | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port l2-jump 10.4.23.3 502 |
| l2-jump | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port l2-jump 10.4.23.5 502 |
| l2-jump | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port l2-jump 10.4.23.12 502 |
| l2-jump | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port l2-jump 10.4.23.13 502 |
| l2-jump | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 2 -> Layer 0 (backup cell) isolation | expect_blocked_port l2-jump 10.4.23.14 502 |
| plc-backup | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 4 isolation | expect_blocked_port plc-backup 10.4.50.10 80 |
| plc-backup | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 4 isolation | expect_blocked_port plc-backup 10.4.50.10 443 |
| plc-backup | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 4 isolation | expect_blocked_port plc-backup 10.4.50.20 5432 |
| plc-backup | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 3 isolation | expect_blocked_port plc-backup 10.3.50.10 443 |
| plc-backup | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 3 isolation | expect_blocked_port plc-backup 10.3.50.10 4840 |
| plc-backup | hmi (l2_net) | 10.2.50.10 | 80 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-backup 10.2.50.10 80 |
| plc-backup | hmi (l2_net) | 10.2.50.10 | 443 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-backup 10.2.50.10 443 |
| plc-backup | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-backup 10.2.50.20 80 |
| plc-backup | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-backup 10.2.50.20 443 |
| plc-backup | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-backup 10.2.50.30 22 |
| plc-backup | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-backup 10.2.50.30 443 |
| plc-backup | plc-main (l1_main) | 10.1.13.10 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 1 (main PLC segment) isolation | expect_blocked_port plc-backup 10.1.13.10 502 |
| plc-backup | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 1 (main PLC segment) isolation | expect_blocked_port plc-backup 10.1.13.10 44818 |
| plc-backup | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 1 management (main) isolation | expect_blocked_port plc-backup 10.0.13.10 502 |
| plc-backup | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 1 management (main) isolation | expect_blocked_port plc-backup 10.0.13.10 44818 |
| plc-backup | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation | expect_blocked_port plc-backup 10.3.13.1 502 |
| plc-backup | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation | expect_blocked_port plc-backup 10.3.13.2 502 |
| plc-backup | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation | expect_blocked_port plc-backup 10.3.13.3 502 |
| plc-backup | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation | expect_blocked_port plc-backup 10.3.13.5 502 |
| plc-backup | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation | expect_blocked_port plc-backup 10.3.13.11 502 |
| plc-backup | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation | expect_blocked_port plc-backup 10.3.13.12 502 |
| plc-backup | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 1 (backup PLC segment) -> Layer 0 (main cell) isolation | expect_blocked_port plc-backup 10.3.13.13 502 |
| plc-backup | vc-hv455a (p23_net) | 10.4.23.1 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port plc-backup 10.4.23.1 502 |
| plc-backup | vc-pv455b (p23_net) | 10.4.23.2 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port plc-backup 10.4.23.2 502 |
| plc-backup | vc-pv455c (p23_net) | 10.4.23.3 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port plc-backup 10.4.23.3 502 |
| plc-backup | heat-ctrl (p23_net) | 10.4.23.5 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port plc-backup 10.4.23.5 502 |
| plc-backup | pt-456 (p23_net) | 10.4.23.12 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port plc-backup 10.4.23.12 502 |
| plc-backup | pt-457 (p23_net) | 10.4.23.13 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port plc-backup 10.4.23.13 502 |
| plc-backup | pt-458 (p23_net) | 10.4.23.14 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port plc-backup 10.4.23.14 502 |
| plc-main | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 4 isolation | expect_blocked_port plc-main 10.4.50.10 80 |
| plc-main | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 4 isolation | expect_blocked_port plc-main 10.4.50.10 443 |
| plc-main | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 4 isolation | expect_blocked_port plc-main 10.4.50.20 5432 |
| plc-main | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 3 isolation | expect_blocked_port plc-main 10.3.50.10 443 |
| plc-main | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 3 isolation | expect_blocked_port plc-main 10.3.50.10 4840 |
| plc-main | hmi (l2_net) | 10.2.50.10 | 80 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-main 10.2.50.10 80 |
| plc-main | hmi (l2_net) | 10.2.50.10 | 443 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-main 10.2.50.10 443 |
| plc-main | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-main 10.2.50.20 80 |
| plc-main | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-main 10.2.50.20 443 |
| plc-main | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-main 10.2.50.30 22 |
| plc-main | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (firewall-0) | Layer 2 / Layer 1 | expect_blocked_port plc-main 10.2.50.30 443 |
| plc-main | plc-backup (l1_backup) | 10.2.23.10 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 1 (backup PLC segment) isolation | expect_blocked_port plc-main 10.2.23.10 502 |
| plc-main | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 1 (backup PLC segment) isolation | expect_blocked_port plc-main 10.2.23.10 44818 |
| plc-main | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 1 management (backup) isolation | expect_blocked_port plc-main 10.0.23.10 502 |
| plc-main | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 1 management (backup) isolation | expect_blocked_port plc-main 10.0.23.10 44818 |
| plc-main | vc-hv455a (p13_net) | 10.3.13.1 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port plc-main 10.3.13.1 502 |
| plc-main | vc-pv455b (p13_net) | 10.3.13.2 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port plc-main 10.3.13.2 502 |
| plc-main | vc-pv455c (p13_net) | 10.3.13.3 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port plc-main 10.3.13.3 502 |
| plc-main | heat-ctrl (p13_net) | 10.3.13.5 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port plc-main 10.3.13.5 502 |
| plc-main | pt-455 (p13_net) | 10.3.13.11 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port plc-main 10.3.13.11 502 |
| plc-main | pt-456 (p13_net) | 10.3.13.12 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port plc-main 10.3.13.12 502 |
| plc-main | pt-457 (p13_net) | 10.3.13.13 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port plc-main 10.3.13.13 502 |
| plc-main | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation | expect_blocked_port plc-main 10.4.23.1 502 |
| plc-main | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation | expect_blocked_port plc-main 10.4.23.2 502 |
| plc-main | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation | expect_blocked_port plc-main 10.4.23.3 502 |
| plc-main | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation | expect_blocked_port plc-main 10.4.23.5 502 |
| plc-main | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation | expect_blocked_port plc-main 10.4.23.12 502 |
| plc-main | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation | expect_blocked_port plc-main 10.4.23.13 502 |
| plc-main | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 1 (main PLC segment) -> Layer 0 (backup cell) isolation | expect_blocked_port plc-main 10.4.23.14 502 |
| heat-ctrl | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port heat-ctrl 10.4.50.10 80 |
| heat-ctrl | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port heat-ctrl 10.4.50.10 443 |
| heat-ctrl | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port heat-ctrl 10.4.50.20 5432 |
| heat-ctrl | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port heat-ctrl 10.3.50.10 443 |
| heat-ctrl | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port heat-ctrl 10.3.50.10 4840 |
| heat-ctrl | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port heat-ctrl 10.2.50.10 80 |
| heat-ctrl | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port heat-ctrl 10.2.50.10 443 |
| heat-ctrl | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port heat-ctrl 10.2.50.20 80 |
| heat-ctrl | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port heat-ctrl 10.2.50.20 443 |
| heat-ctrl | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port heat-ctrl 10.2.50.30 22 |
| heat-ctrl | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port heat-ctrl 10.2.50.30 443 |
| heat-ctrl | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port heat-ctrl 10.2.23.10 502 |
| heat-ctrl | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (firewall-backup-cell) | Layer 1 / Layer 0 (backup cell) | expect_blocked_port heat-ctrl 10.2.23.10 44818 |
| heat-ctrl | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port heat-ctrl 10.1.13.10 502 |
| heat-ctrl | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (firewall-main-cell) | Layer 1 / Layer 0 (main cell) | expect_blocked_port heat-ctrl 10.1.13.10 44818 |
| heat-ctrl | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port heat-ctrl 10.0.13.10 502 |
| heat-ctrl | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port heat-ctrl 10.0.13.10 44818 |
| heat-ctrl | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port heat-ctrl 10.0.23.10 502 |
| heat-ctrl | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port heat-ctrl 10.0.23.10 44818 |
| heat-ctrl | vc-hv455a (p13_net) | 10.3.13.1 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port heat-ctrl 10.3.13.1 502 |
| heat-ctrl | vc-pv455b (p13_net) | 10.3.13.2 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port heat-ctrl 10.3.13.2 502 |
| heat-ctrl | vc-pv455c (p13_net) | 10.3.13.3 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port heat-ctrl 10.3.13.3 502 |
| heat-ctrl | pt-455 (p13_net) | 10.3.13.11 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port heat-ctrl 10.3.13.11 502 |
| heat-ctrl | pt-456 (p13_net) | 10.3.13.12 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port heat-ctrl 10.3.13.12 502 |
| heat-ctrl | pt-457 (p13_net) | 10.3.13.13 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port heat-ctrl 10.3.13.13 502 |
| heat-ctrl | vc-hv455a (p23_net) | 10.4.23.1 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port heat-ctrl 10.4.23.1 502 |
| heat-ctrl | vc-pv455b (p23_net) | 10.4.23.2 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port heat-ctrl 10.4.23.2 502 |
| heat-ctrl | vc-pv455c (p23_net) | 10.4.23.3 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port heat-ctrl 10.4.23.3 502 |
| heat-ctrl | pt-456 (p23_net) | 10.4.23.12 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port heat-ctrl 10.4.23.12 502 |
| heat-ctrl | pt-457 (p23_net) | 10.4.23.13 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port heat-ctrl 10.4.23.13 502 |
| heat-ctrl | pt-458 (p23_net) | 10.4.23.14 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port heat-ctrl 10.4.23.14 502 |
| pt-455 | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-455 10.4.50.10 80 |
| pt-455 | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-455 10.4.50.10 443 |
| pt-455 | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-455 10.4.50.20 5432 |
| pt-455 | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port pt-455 10.3.50.10 443 |
| pt-455 | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port pt-455 10.3.50.10 4840 |
| pt-455 | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-455 10.2.50.10 80 |
| pt-455 | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-455 10.2.50.10 443 |
| pt-455 | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-455 10.2.50.20 80 |
| pt-455 | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-455 10.2.50.20 443 |
| pt-455 | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-455 10.2.50.30 22 |
| pt-455 | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-455 10.2.50.30 443 |
| pt-455 | plc-backup (l1_backup) | 10.2.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 (backup PLC segment) isolation | expect_blocked_port pt-455 10.2.23.10 502 |
| pt-455 | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 (backup PLC segment) isolation | expect_blocked_port pt-455 10.2.23.10 44818 |
| pt-455 | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port pt-455 10.1.13.10 502 |
| pt-455 | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (firewall-main-cell) | Layer 1 / Layer 0 (main cell) | expect_blocked_port pt-455 10.1.13.10 44818 |
| pt-455 | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-455 10.0.13.10 502 |
| pt-455 | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-455 10.0.13.10 44818 |
| pt-455 | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-455 10.0.23.10 502 |
| pt-455 | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-455 10.0.23.10 44818 |
| pt-455 | vc-hv455a (p13_net) | 10.3.13.1 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-455 10.3.13.1 502 |
| pt-455 | vc-pv455b (p13_net) | 10.3.13.2 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-455 10.3.13.2 502 |
| pt-455 | vc-pv455c (p13_net) | 10.3.13.3 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-455 10.3.13.3 502 |
| pt-455 | heat-ctrl (p13_net) | 10.3.13.5 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-455 10.3.13.5 502 |
| pt-455 | pt-456 (p13_net) | 10.3.13.12 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-455 10.3.13.12 502 |
| pt-455 | pt-457 (p13_net) | 10.3.13.13 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-455 10.3.13.13 502 |
| pt-455 | vc-hv455a (p23_net) | 10.4.23.1 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 0 (backup cell) isolation | expect_blocked_port pt-455 10.4.23.1 502 |
| pt-455 | vc-pv455b (p23_net) | 10.4.23.2 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 0 (backup cell) isolation | expect_blocked_port pt-455 10.4.23.2 502 |
| pt-455 | vc-pv455c (p23_net) | 10.4.23.3 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 0 (backup cell) isolation | expect_blocked_port pt-455 10.4.23.3 502 |
| pt-455 | heat-ctrl (p23_net) | 10.4.23.5 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 0 (backup cell) isolation | expect_blocked_port pt-455 10.4.23.5 502 |
| pt-455 | pt-456 (p23_net) | 10.4.23.12 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 0 (backup cell) isolation | expect_blocked_port pt-455 10.4.23.12 502 |
| pt-455 | pt-457 (p23_net) | 10.4.23.13 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 0 (backup cell) isolation | expect_blocked_port pt-455 10.4.23.13 502 |
| pt-455 | pt-458 (p23_net) | 10.4.23.14 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 0 (backup cell) isolation | expect_blocked_port pt-455 10.4.23.14 502 |
| pt-456 | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-456 10.4.50.10 80 |
| pt-456 | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-456 10.4.50.10 443 |
| pt-456 | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-456 10.4.50.20 5432 |
| pt-456 | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port pt-456 10.3.50.10 443 |
| pt-456 | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port pt-456 10.3.50.10 4840 |
| pt-456 | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-456 10.2.50.10 80 |
| pt-456 | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-456 10.2.50.10 443 |
| pt-456 | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-456 10.2.50.20 80 |
| pt-456 | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-456 10.2.50.20 443 |
| pt-456 | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-456 10.2.50.30 22 |
| pt-456 | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-456 10.2.50.30 443 |
| pt-456 | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port pt-456 10.2.23.10 502 |
| pt-456 | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (firewall-backup-cell) | Layer 1 / Layer 0 (backup cell) | expect_blocked_port pt-456 10.2.23.10 44818 |
| pt-456 | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port pt-456 10.1.13.10 502 |
| pt-456 | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (firewall-main-cell) | Layer 1 / Layer 0 (main cell) | expect_blocked_port pt-456 10.1.13.10 44818 |
| pt-456 | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-456 10.0.13.10 502 |
| pt-456 | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-456 10.0.13.10 44818 |
| pt-456 | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-456 10.0.23.10 502 |
| pt-456 | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-456 10.0.23.10 44818 |
| pt-456 | vc-hv455a (p13_net) | 10.3.13.1 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-456 10.3.13.1 502 |
| pt-456 | vc-pv455b (p13_net) | 10.3.13.2 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-456 10.3.13.2 502 |
| pt-456 | vc-pv455c (p13_net) | 10.3.13.3 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-456 10.3.13.3 502 |
| pt-456 | heat-ctrl (p13_net) | 10.3.13.5 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-456 10.3.13.5 502 |
| pt-456 | pt-455 (p13_net) | 10.3.13.11 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-456 10.3.13.11 502 |
| pt-456 | pt-457 (p13_net) | 10.3.13.13 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-456 10.3.13.13 502 |
| pt-456 | vc-hv455a (p23_net) | 10.4.23.1 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-456 10.4.23.1 502 |
| pt-456 | vc-pv455b (p23_net) | 10.4.23.2 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-456 10.4.23.2 502 |
| pt-456 | vc-pv455c (p23_net) | 10.4.23.3 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-456 10.4.23.3 502 |
| pt-456 | heat-ctrl (p23_net) | 10.4.23.5 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-456 10.4.23.5 502 |
| pt-456 | pt-457 (p23_net) | 10.4.23.13 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-456 10.4.23.13 502 |
| pt-456 | pt-458 (p23_net) | 10.4.23.14 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-456 10.4.23.14 502 |
| pt-457 | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-457 10.4.50.10 80 |
| pt-457 | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-457 10.4.50.10 443 |
| pt-457 | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port pt-457 10.4.50.20 5432 |
| pt-457 | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port pt-457 10.3.50.10 443 |
| pt-457 | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port pt-457 10.3.50.10 4840 |
| pt-457 | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-457 10.2.50.10 80 |
| pt-457 | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-457 10.2.50.10 443 |
| pt-457 | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-457 10.2.50.20 80 |
| pt-457 | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-457 10.2.50.20 443 |
| pt-457 | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-457 10.2.50.30 22 |
| pt-457 | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port pt-457 10.2.50.30 443 |
| pt-457 | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port pt-457 10.2.23.10 502 |
| pt-457 | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (firewall-backup-cell) | Layer 1 / Layer 0 (backup cell) | expect_blocked_port pt-457 10.2.23.10 44818 |
| pt-457 | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port pt-457 10.1.13.10 502 |
| pt-457 | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (firewall-main-cell) | Layer 1 / Layer 0 (main cell) | expect_blocked_port pt-457 10.1.13.10 44818 |
| pt-457 | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-457 10.0.13.10 502 |
| pt-457 | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-457 10.0.13.10 44818 |
| pt-457 | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-457 10.0.23.10 502 |
| pt-457 | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-457 10.0.23.10 44818 |
| pt-457 | vc-hv455a (p13_net) | 10.3.13.1 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-457 10.3.13.1 502 |
| pt-457 | vc-pv455b (p13_net) | 10.3.13.2 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-457 10.3.13.2 502 |
| pt-457 | vc-pv455c (p13_net) | 10.3.13.3 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-457 10.3.13.3 502 |
| pt-457 | heat-ctrl (p13_net) | 10.3.13.5 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-457 10.3.13.5 502 |
| pt-457 | pt-455 (p13_net) | 10.3.13.11 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-457 10.3.13.11 502 |
| pt-457 | pt-456 (p13_net) | 10.3.13.12 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port pt-457 10.3.13.12 502 |
| pt-457 | vc-hv455a (p23_net) | 10.4.23.1 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-457 10.4.23.1 502 |
| pt-457 | vc-pv455b (p23_net) | 10.4.23.2 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-457 10.4.23.2 502 |
| pt-457 | vc-pv455c (p23_net) | 10.4.23.3 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-457 10.4.23.3 502 |
| pt-457 | heat-ctrl (p23_net) | 10.4.23.5 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-457 10.4.23.5 502 |
| pt-457 | pt-456 (p23_net) | 10.4.23.12 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-457 10.4.23.12 502 |
| pt-457 | pt-458 (p23_net) | 10.4.23.14 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-457 10.4.23.14 502 |
| pt-458 | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (backup cell) -> Layer 4 isolation | expect_blocked_port pt-458 10.4.50.10 80 |
| pt-458 | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (backup cell) -> Layer 4 isolation | expect_blocked_port pt-458 10.4.50.10 443 |
| pt-458 | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (backup cell) -> Layer 4 isolation | expect_blocked_port pt-458 10.4.50.20 5432 |
| pt-458 | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (backup cell) -> Layer 3 isolation | expect_blocked_port pt-458 10.3.50.10 443 |
| pt-458 | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (backup cell) -> Layer 3 isolation | expect_blocked_port pt-458 10.3.50.10 4840 |
| pt-458 | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (backup cell) -> Layer 2 isolation | expect_blocked_port pt-458 10.2.50.10 80 |
| pt-458 | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (backup cell) -> Layer 2 isolation | expect_blocked_port pt-458 10.2.50.10 443 |
| pt-458 | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (backup cell) -> Layer 2 isolation | expect_blocked_port pt-458 10.2.50.20 80 |
| pt-458 | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (backup cell) -> Layer 2 isolation | expect_blocked_port pt-458 10.2.50.20 443 |
| pt-458 | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (backup cell) -> Layer 2 isolation | expect_blocked_port pt-458 10.2.50.30 22 |
| pt-458 | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (backup cell) -> Layer 2 isolation | expect_blocked_port pt-458 10.2.50.30 443 |
| pt-458 | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port pt-458 10.2.23.10 502 |
| pt-458 | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (firewall-backup-cell) | Layer 1 / Layer 0 (backup cell) | expect_blocked_port pt-458 10.2.23.10 44818 |
| pt-458 | plc-main (l1_main) | 10.1.13.10 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 1 (main PLC segment) isolation | expect_blocked_port pt-458 10.1.13.10 502 |
| pt-458 | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (no route) | Layer 0 (backup cell) -> Layer 1 (main PLC segment) isolation | expect_blocked_port pt-458 10.1.13.10 44818 |
| pt-458 | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-458 10.0.13.10 502 |
| pt-458 | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (backup cell) -> Layer 1 management (main) isolation | expect_blocked_port pt-458 10.0.13.10 44818 |
| pt-458 | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-458 10.0.23.10 502 |
| pt-458 | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (backup cell) -> Layer 1 management (backup) isolation | expect_blocked_port pt-458 10.0.23.10 44818 |
| pt-458 | vc-hv455a (p13_net) | 10.3.13.1 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 0 (main cell) isolation | expect_blocked_port pt-458 10.3.13.1 502 |
| pt-458 | vc-pv455b (p13_net) | 10.3.13.2 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 0 (main cell) isolation | expect_blocked_port pt-458 10.3.13.2 502 |
| pt-458 | vc-pv455c (p13_net) | 10.3.13.3 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 0 (main cell) isolation | expect_blocked_port pt-458 10.3.13.3 502 |
| pt-458 | heat-ctrl (p13_net) | 10.3.13.5 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 0 (main cell) isolation | expect_blocked_port pt-458 10.3.13.5 502 |
| pt-458 | pt-455 (p13_net) | 10.3.13.11 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 0 (main cell) isolation | expect_blocked_port pt-458 10.3.13.11 502 |
| pt-458 | pt-456 (p13_net) | 10.3.13.12 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 0 (main cell) isolation | expect_blocked_port pt-458 10.3.13.12 502 |
| pt-458 | pt-457 (p13_net) | 10.3.13.13 | 502 | blocked (no route) | Layer 0 (backup cell) -> Layer 0 (main cell) isolation | expect_blocked_port pt-458 10.3.13.13 502 |
| pt-458 | vc-hv455a (p23_net) | 10.4.23.1 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-458 10.4.23.1 502 |
| pt-458 | vc-pv455b (p23_net) | 10.4.23.2 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-458 10.4.23.2 502 |
| pt-458 | vc-pv455c (p23_net) | 10.4.23.3 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-458 10.4.23.3 502 |
| pt-458 | heat-ctrl (p23_net) | 10.4.23.5 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-458 10.4.23.5 502 |
| pt-458 | pt-456 (p23_net) | 10.4.23.12 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-458 10.4.23.12 502 |
| pt-458 | pt-457 (p23_net) | 10.4.23.13 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port pt-458 10.4.23.13 502 |
| vc-hv455a | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-hv455a 10.4.50.10 80 |
| vc-hv455a | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-hv455a 10.4.50.10 443 |
| vc-hv455a | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-hv455a 10.4.50.20 5432 |
| vc-hv455a | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port vc-hv455a 10.3.50.10 443 |
| vc-hv455a | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port vc-hv455a 10.3.50.10 4840 |
| vc-hv455a | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-hv455a 10.2.50.10 80 |
| vc-hv455a | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-hv455a 10.2.50.10 443 |
| vc-hv455a | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-hv455a 10.2.50.20 80 |
| vc-hv455a | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-hv455a 10.2.50.20 443 |
| vc-hv455a | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-hv455a 10.2.50.30 22 |
| vc-hv455a | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-hv455a 10.2.50.30 443 |
| vc-hv455a | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port vc-hv455a 10.2.23.10 502 |
| vc-hv455a | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (firewall-backup-cell) | Layer 1 / Layer 0 (backup cell) | expect_blocked_port vc-hv455a 10.2.23.10 44818 |
| vc-hv455a | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port vc-hv455a 10.1.13.10 502 |
| vc-hv455a | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (firewall-main-cell) | Layer 1 / Layer 0 (main cell) | expect_blocked_port vc-hv455a 10.1.13.10 44818 |
| vc-hv455a | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port vc-hv455a 10.0.13.10 502 |
| vc-hv455a | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port vc-hv455a 10.0.13.10 44818 |
| vc-hv455a | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port vc-hv455a 10.0.23.10 502 |
| vc-hv455a | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port vc-hv455a 10.0.23.10 44818 |
| vc-hv455a | vc-pv455b (p13_net) | 10.3.13.2 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-hv455a 10.3.13.2 502 |
| vc-hv455a | vc-pv455c (p13_net) | 10.3.13.3 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-hv455a 10.3.13.3 502 |
| vc-hv455a | heat-ctrl (p13_net) | 10.3.13.5 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-hv455a 10.3.13.5 502 |
| vc-hv455a | pt-455 (p13_net) | 10.3.13.11 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-hv455a 10.3.13.11 502 |
| vc-hv455a | pt-456 (p13_net) | 10.3.13.12 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-hv455a 10.3.13.12 502 |
| vc-hv455a | pt-457 (p13_net) | 10.3.13.13 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-hv455a 10.3.13.13 502 |
| vc-hv455a | vc-pv455b (p23_net) | 10.4.23.2 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-hv455a 10.4.23.2 502 |
| vc-hv455a | vc-pv455c (p23_net) | 10.4.23.3 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-hv455a 10.4.23.3 502 |
| vc-hv455a | heat-ctrl (p23_net) | 10.4.23.5 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-hv455a 10.4.23.5 502 |
| vc-hv455a | pt-456 (p23_net) | 10.4.23.12 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-hv455a 10.4.23.12 502 |
| vc-hv455a | pt-457 (p23_net) | 10.4.23.13 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-hv455a 10.4.23.13 502 |
| vc-hv455a | pt-458 (p23_net) | 10.4.23.14 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-hv455a 10.4.23.14 502 |
| vc-pv455b | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-pv455b 10.4.50.10 80 |
| vc-pv455b | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-pv455b 10.4.50.10 443 |
| vc-pv455b | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-pv455b 10.4.50.20 5432 |
| vc-pv455b | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port vc-pv455b 10.3.50.10 443 |
| vc-pv455b | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port vc-pv455b 10.3.50.10 4840 |
| vc-pv455b | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455b 10.2.50.10 80 |
| vc-pv455b | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455b 10.2.50.10 443 |
| vc-pv455b | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455b 10.2.50.20 80 |
| vc-pv455b | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455b 10.2.50.20 443 |
| vc-pv455b | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455b 10.2.50.30 22 |
| vc-pv455b | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455b 10.2.50.30 443 |
| vc-pv455b | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port vc-pv455b 10.2.23.10 502 |
| vc-pv455b | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (firewall-backup-cell) | Layer 1 / Layer 0 (backup cell) | expect_blocked_port vc-pv455b 10.2.23.10 44818 |
| vc-pv455b | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port vc-pv455b 10.1.13.10 502 |
| vc-pv455b | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (firewall-main-cell) | Layer 1 / Layer 0 (main cell) | expect_blocked_port vc-pv455b 10.1.13.10 44818 |
| vc-pv455b | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port vc-pv455b 10.0.13.10 502 |
| vc-pv455b | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port vc-pv455b 10.0.13.10 44818 |
| vc-pv455b | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port vc-pv455b 10.0.23.10 502 |
| vc-pv455b | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port vc-pv455b 10.0.23.10 44818 |
| vc-pv455b | vc-hv455a (p13_net) | 10.3.13.1 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455b 10.3.13.1 502 |
| vc-pv455b | vc-pv455c (p13_net) | 10.3.13.3 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455b 10.3.13.3 502 |
| vc-pv455b | heat-ctrl (p13_net) | 10.3.13.5 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455b 10.3.13.5 502 |
| vc-pv455b | pt-455 (p13_net) | 10.3.13.11 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455b 10.3.13.11 502 |
| vc-pv455b | pt-456 (p13_net) | 10.3.13.12 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455b 10.3.13.12 502 |
| vc-pv455b | pt-457 (p13_net) | 10.3.13.13 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455b 10.3.13.13 502 |
| vc-pv455b | vc-hv455a (p23_net) | 10.4.23.1 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455b 10.4.23.1 502 |
| vc-pv455b | vc-pv455c (p23_net) | 10.4.23.3 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455b 10.4.23.3 502 |
| vc-pv455b | heat-ctrl (p23_net) | 10.4.23.5 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455b 10.4.23.5 502 |
| vc-pv455b | pt-456 (p23_net) | 10.4.23.12 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455b 10.4.23.12 502 |
| vc-pv455b | pt-457 (p23_net) | 10.4.23.13 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455b 10.4.23.13 502 |
| vc-pv455b | pt-458 (p23_net) | 10.4.23.14 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455b 10.4.23.14 502 |
| vc-pv455c | workstation (l4_net) | 10.4.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-pv455c 10.4.50.10 80 |
| vc-pv455c | workstation (l4_net) | 10.4.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-pv455c 10.4.50.10 443 |
| vc-pv455c | database (l4_net) | 10.4.50.20 | 5432 | blocked (no route) | Layer 0 (main cell) -> Layer 4 isolation | expect_blocked_port vc-pv455c 10.4.50.20 5432 |
| vc-pv455c | historian (l3_net) | 10.3.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port vc-pv455c 10.3.50.10 443 |
| vc-pv455c | historian (l3_net) | 10.3.50.10 | 4840 | blocked (no route) | Layer 0 (main cell) -> Layer 3 isolation | expect_blocked_port vc-pv455c 10.3.50.10 4840 |
| vc-pv455c | hmi (l2_net) | 10.2.50.10 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455c 10.2.50.10 80 |
| vc-pv455c | hmi (l2_net) | 10.2.50.10 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455c 10.2.50.10 443 |
| vc-pv455c | engineer-ws (l2_net) | 10.2.50.20 | 80 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455c 10.2.50.20 80 |
| vc-pv455c | engineer-ws (l2_net) | 10.2.50.20 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455c 10.2.50.20 443 |
| vc-pv455c | l2-jump (l2_net) | 10.2.50.30 | 22 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455c 10.2.50.30 22 |
| vc-pv455c | l2-jump (l2_net) | 10.2.50.30 | 443 | blocked (no route) | Layer 0 (main cell) -> Layer 2 isolation | expect_blocked_port vc-pv455c 10.2.50.30 443 |
| vc-pv455c | plc-backup (l1_backup) | 10.2.23.10 | 502 | allow | Layer 1 / Layer 0 (backup cell) | probe_port vc-pv455c 10.2.23.10 502 |
| vc-pv455c | plc-backup (l1_backup) | 10.2.23.10 | 44818 | blocked (firewall-backup-cell) | Layer 1 / Layer 0 (backup cell) | expect_blocked_port vc-pv455c 10.2.23.10 44818 |
| vc-pv455c | plc-main (l1_main) | 10.1.13.10 | 502 | allow | Layer 1 / Layer 0 (main cell) | probe_port vc-pv455c 10.1.13.10 502 |
| vc-pv455c | plc-main (l1_main) | 10.1.13.10 | 44818 | blocked (firewall-main-cell) | Layer 1 / Layer 0 (main cell) | expect_blocked_port vc-pv455c 10.1.13.10 44818 |
| vc-pv455c | plc-main (mgmt13_net) | 10.0.13.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port vc-pv455c 10.0.13.10 502 |
| vc-pv455c | plc-main (mgmt13_net) | 10.0.13.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (main) isolation | expect_blocked_port vc-pv455c 10.0.13.10 44818 |
| vc-pv455c | plc-backup (mgmt23_net) | 10.0.23.10 | 502 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port vc-pv455c 10.0.23.10 502 |
| vc-pv455c | plc-backup (mgmt23_net) | 10.0.23.10 | 44818 | blocked (no route) | Layer 0 (main cell) -> Layer 1 management (backup) isolation | expect_blocked_port vc-pv455c 10.0.23.10 44818 |
| vc-pv455c | vc-hv455a (p13_net) | 10.3.13.1 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455c 10.3.13.1 502 |
| vc-pv455c | vc-pv455b (p13_net) | 10.3.13.2 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455c 10.3.13.2 502 |
| vc-pv455c | heat-ctrl (p13_net) | 10.3.13.5 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455c 10.3.13.5 502 |
| vc-pv455c | pt-455 (p13_net) | 10.3.13.11 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455c 10.3.13.11 502 |
| vc-pv455c | pt-456 (p13_net) | 10.3.13.12 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455c 10.3.13.12 502 |
| vc-pv455c | pt-457 (p13_net) | 10.3.13.13 | 502 | allow | Intra-zone: Layer 0 (main cell) | probe_port vc-pv455c 10.3.13.13 502 |
| vc-pv455c | vc-hv455a (p23_net) | 10.4.23.1 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455c 10.4.23.1 502 |
| vc-pv455c | vc-pv455b (p23_net) | 10.4.23.2 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455c 10.4.23.2 502 |
| vc-pv455c | heat-ctrl (p23_net) | 10.4.23.5 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455c 10.4.23.5 502 |
| vc-pv455c | pt-456 (p23_net) | 10.4.23.12 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455c 10.4.23.12 502 |
| vc-pv455c | pt-457 (p23_net) | 10.4.23.13 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455c 10.4.23.13 502 |
| vc-pv455c | pt-458 (p23_net) | 10.4.23.14 | 502 | allow | Intra-zone: Layer 0 (backup cell) | probe_port vc-pv455c 10.4.23.14 502 |

## Route Isolation Checks

| Check | Command | Expected | Policy confirmed |
| --- | --- | --- | --- |
| workstation route table | expect_no_l1_l0_or_mgmt_routes workstation | no matching routes present | Layer 4 has no routes into Layer 1, Layer 0, or management nets |
| historian route table | expect_no_l1_l0_or_mgmt_routes historian | no matching routes present | Layer 3 has no routes into Layer 1, Layer 0, or management nets |
| hmi route table | expect_no_l0_or_mgmt_routes hmi | no matching routes present | Layer 2 operator access does not route directly into Layer 0 or management nets |
| engineer-ws route table | expect_no_l0_or_mgmt_routes engineer-ws | no matching routes present | Layer 2 engineering access does not route directly into Layer 0 or management nets |
| l2-jump route table | expect_no_l1_l0_or_mgmt_routes l2-jump | no matching routes present | The Layer 2 jumpbox does not have PLC, process, or management routes |

## Host Published Ports

| Host Port | Destination | Container Port | Command | Expected |
| --- | --- | --- | --- | --- |
| 15432 | database | 5432 | curl -fsS --max-time 3 http://127.0.0.1:15432/ | JSON with `"device": "Database"` and `"local_port": 5432` |
| 8080 | workstation | 80 | curl -fsS --max-time 3 http://127.0.0.1:8080/ | JSON with `"device": "Workstation"` and `"local_port": 80` |
| 8443 | workstation | 443 | curl -fsS --max-time 3 http://127.0.0.1:8443/ | JSON with `"device": "Workstation"` and `"local_port": 443` |
| 4840 | historian | 4840 | curl -fsS --max-time 3 http://127.0.0.1:4840/ | JSON with `"device": "Data-Historian"` and `"local_port": 4840` |
| 8444 | historian | 443 | curl -fsS --max-time 3 http://127.0.0.1:8444/ | JSON with `"device": "Data-Historian"` and `"local_port": 443` |
| 8082 | engineer-ws | 80 | curl -fsS --max-time 3 http://127.0.0.1:8082/ | JSON with `"device": "Engineer-Workstation"` and `"local_port": 80` |
| 8446 | engineer-ws | 443 | curl -fsS --max-time 3 http://127.0.0.1:8446/ | JSON with `"device": "Engineer-Workstation"` and `"local_port": 443` |
| 8081 | hmi | 80 | curl -fsS --max-time 3 http://127.0.0.1:8081/ | JSON with `"device": "HMI"` and `"local_port": 80` |
| 8445 | hmi | 443 | curl -fsS --max-time 3 http://127.0.0.1:8445/ | JSON with `"device": "HMI"` and `"local_port": 443` |
| 2222 | l2-jump | 22 | curl -fsS --max-time 3 http://127.0.0.1:2222/ | JSON with `"device": "Layer2-Jumpbox"` and `"local_port": 22` |
| 8447 | l2-jump | 443 | curl -fsS --max-time 3 http://127.0.0.1:8447/ | JSON with `"device": "Layer2-Jumpbox"` and `"local_port": 443` |

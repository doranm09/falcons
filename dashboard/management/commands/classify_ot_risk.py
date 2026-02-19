import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import Node, SiemEvent


PORT_WEIGHTS = {
    102: 24,      # IEC61850 MMS
    502: 18,      # Modbus/TCP
    1883: 10,     # MQTT
    2404: 22,     # IEC60870-5-104
    4840: 16,     # OPC UA
    44818: 22,    # ENIP/CIP
}

SUBSYSTEM_WEIGHTS = {
    "rcs": 20,
    "mrs": 18,
    "mfw": 16,
    "cws": 14,
    "ot_modbus": 16,
    "ot_opcua": 15,
    "ot_enip": 15,
    "ot_iec60870": 15,
    "ot_iec61850": 15,
}


class Command(BaseCommand):
    help = "Classify OT risk from live service exposure + SIEM signals"

    def add_arguments(self, parser):
        parser.add_argument("--targets", default="172.20.0.2-12", help="Nmap targets")
        parser.add_argument("--ports", default="102,502,1883,2404,4840,44818", help="Ports to assess")
        parser.add_argument("--siem-hours", type=int, default=24, help="SIEM lookback window in hours")
        parser.add_argument("--output", default="/tmp/ot_risk_report.json", help="Output report path")

    def _run_nmap_xml(self, targets: str, ports: str) -> ET.Element:
        cmd = ["nmap", "-sT", "-Pn", "-p", ports, "-oX", "-", targets]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"nmap failed: {proc.stderr.strip()}")
        return ET.fromstring(proc.stdout)

    def _host_info(self, host_el: ET.Element):
        addr = host_el.find("./address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else None

        hname = ""
        hnode = host_el.find("./hostnames/hostname")
        if hnode is not None:
            hname = hnode.get("name", "")

        open_ports = []
        for p in host_el.findall("./ports/port"):
            st = p.find("./state")
            if st is not None and st.get("state") == "open":
                try:
                    open_ports.append(int(p.get("portid")))
                except Exception:
                    pass

        return ip, hname, sorted(open_ports)

    def _subsystem_from_name(self, hostname: str) -> str:
        h = (hostname or "").lower()
        for key in ("rcs", "mrs", "mfw", "cws"):
            if key in h:
                return key
        for key in ("ot_modbus", "ot_opcua", "ot_enip", "ot_iec60870", "ot_iec61850"):
            if key in h:
                return key
        return "unknown"

    def _siem_score(self, ip: str, hours: int) -> dict:
        since = timezone.now() - timedelta(hours=hours)
        events = SiemEvent.objects.filter(asset_ip=ip, timestamp__gte=since)
        count = events.count()
        max_sev = events.order_by("-severity").values_list("severity", flat=True).first() or 0
        score = min(30, count * 2 + int(max_sev or 0) * 2)
        return {"event_count": count, "max_severity": int(max_sev or 0), "siem_score": score}

    def _tier(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

    def handle(self, *args, **opts):
        root = self._run_nmap_xml(opts["targets"], opts["ports"])
        report = []

        for host in root.findall("./host"):
            ip, hostname, open_ports = self._host_info(host)
            if not ip:
                continue

            subsystem = self._subsystem_from_name(hostname)
            exposure_score = sum(PORT_WEIGHTS.get(p, 0) for p in open_ports)
            subsystem_score = SUBSYSTEM_WEIGHTS.get(subsystem, 8)
            siem = self._siem_score(ip, opts["siem_hours"])
            total_score = min(100, exposure_score + subsystem_score + siem["siem_score"])
            tier = self._tier(total_score)

            node, _created = Node.objects.get_or_create(
                ip_address=ip,
                defaults={"name": hostname or f"Host-{ip}", "status": "online"},
            )
            node.name = hostname or node.name
            node.status = "online"
            node.active_ports = open_ports
            node.platform_info = f"subsystem={subsystem};risk_tier={tier};risk_score={total_score}"
            node.save(update_fields=["name", "status", "active_ports", "platform_info"])

            item = {
                "ip": ip,
                "hostname": hostname,
                "subsystem": subsystem,
                "open_ports": open_ports,
                "exposure_score": exposure_score,
                "subsystem_score": subsystem_score,
                **siem,
                "risk_score": total_score,
                "risk_tier": tier,
            }
            report.append(item)
            self.stdout.write(f"{ip} {tier} score={total_score} ports={open_ports}")

        with open(opts["output"], "w", encoding="utf-8") as f:
            json.dump(
                {
                    "generated_at": timezone.now().isoformat(),
                    "targets": opts["targets"],
                    "ports": opts["ports"],
                    "siem_hours": opts["siem_hours"],
                    "results": report,
                },
                f,
                indent=2,
            )

        self.stdout.write(self.style.SUCCESS(f"Saved OT risk report: {opts['output']}"))

#!/usr/bin/env python3
"""
Complete Cyber Data Collection Workflow

This script executes the full workflow:
1. Execute the host agent to collect system data
2. Collect SBOM (Software Bill of Materials)
3. Run Grype vulnerability scan on the SBOM
4. Convert Grype output to cyber template format
5. Generate complete cyber_template.json

Usage:
    python cyber_data_collection_workflow.py --server-url http://localhost:8000
"""

import os
import sys
import json
import subprocess
import argparse
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

class CyberDataCollector:
    def __init__(self, server_url="http://localhost:8000", output_dir="output"):
        self.server_url = server_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Agent configuration
        self.agent_id = self.get_agent_id()
        self.agent_script = Path(__file__).parent / "host_agent" / "agent.py"
        self.sbom_script = Path(__file__).parent / "host_agent" / "sbom" / "os_sbom.py"
        self.grype_converter = Path(__file__).parent / "utils" / "grype_to_json" / "grype_to_json.py"
        self.cyber_template = Path(__file__).parent / "utils" / "grype_to_json" / "template" / "cyber_template.json"

    def get_agent_id(self):
        """Get or generate agent ID"""
        try:
            import uuid
            return str(uuid.getnode())
        except:
            return "unknown_agent"

    def check_dependencies(self):
        """Check if required tools are available"""
        missing_deps = []

        # Check for grype
        if not shutil.which("grype"):
            missing_deps.append("grype")

        # Check for python modules
        try:
            import psutil
        except ImportError:
            missing_deps.append("psutil")

        if missing_deps:
            print(f"Missing dependencies: {', '.join(missing_deps)}")
            print("Please install missing dependencies and try again.")
            return False

        return True

    def step_1_execute_agent(self):
        """Step 1: Execute the host agent to collect system information"""
        print("Step 1: Executing host agent...")

        try:
            # Run agent in info mode to get system data
            result = subprocess.run([
                sys.executable, str(self.agent_script), "info"
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                system_info = json.loads(result.stdout)
                print(f"✓ Agent executed successfully")
                print(f"  Hostname: {system_info.get('hostname', 'Unknown')}")
                print(f"  OS: {system_info.get('os', 'Unknown')} {system_info.get('os_version', 'Unknown')}")
                print(f"  Platform: {system_info.get('platform', 'Unknown')}")
                print(f"  CPU Cores: {system_info.get('cpu_count', 'Unknown')}")
                print(f"  Memory: {system_info.get('memory_total', 0) // (1024**3)} GB")

                # Save system info
                with open(self.output_dir / "system_info.json", 'w') as f:
                    json.dump(system_info, f, indent=2)

                return system_info
            else:
                print(f"✗ Agent execution failed: {result.stderr}")
                return None

        except Exception as e:
            print(f"✗ Error executing agent: {e}")
            return None

    def step_2_collect_sbom(self):
        """Step 2: Collect SBOM (Software Bill of Materials)"""
        print("\nStep 2: Collecting SBOM...")

        try:
            # Import the SBOM collection function
            sys.path.append(str(Path(__file__).parent / "host_agent"))
            from sbom.os_sbom import collect_packages, generate_cyclonedx_sbom

            # Collect packages
            packages = collect_packages()

            if packages:
                print(f"✓ Collected {len(packages)} packages")

                # Generate CycloneDX format SBOM
                sbom_data = generate_cyclonedx_sbom(packages)

                # Save SBOM data
                with open(self.output_dir / "sbom.json", 'w') as f:
                    json.dump(sbom_data, f, indent=2)

                # Also save raw packages list
                with open(self.output_dir / "packages.json", 'w') as f:
                    json.dump(packages, f, indent=2)

                return sbom_data, packages
            else:
                print("✗ No packages collected")
                return None, None

        except Exception as e:
            print(f"✗ Error collecting SBOM: {e}")
            return None, None

    def step_3_run_grype_scan(self, sbom_file):
        """Step 3: Run Grype vulnerability scan on SBOM"""
        print("\nStep 3: Running Grype vulnerability scan...")

        try:
            # Run grype scan on the SBOM file
            grype_output = self.output_dir / "grype_output.json"

            result = subprocess.run([
                "grype", "-o", "json",
                f"sbom:{sbom_file}"
            ], capture_output=True, text=True, timeout=300)  # 5 minute timeout

            if result.returncode == 0:
                # Save grype output
                with open(grype_output, 'w') as f:
                    f.write(result.stdout)

                grype_data = json.loads(result.stdout)
                matches = grype_data.get("matches", [])

                print(f"✓ Grype scan completed")
                print(f"  Found {len(matches)} vulnerability matches")

                return grype_data
            else:
                print(f"✗ Grype scan failed: {result.stderr}")
                return None

        except FileNotFoundError:
            print("✗ Grype not found. Please install grype: https://github.com/anchore/grype")
            return None
        except Exception as e:
            print(f"✗ Error running Grype: {e}")
            return None

    def step_4_convert_to_cyber_template(self, grype_data, system_info, packages):
        """Step 4: Convert Grype output to cyber template format"""
        print("\nStep 4: Converting to cyber template format...")

        try:
            # Use the grype to cyber JSON converter directly in Python
            cyber_output = self.output_dir / "cyber_template_filled.json"

            # Import the converter function directly
            sys.path.append(str(self.grype_converter.parent))
            import grype_to_json

            # Prepare arguments for the converter
            class Args:
                def __init__(self):
                    self.system = "Cyber Pen Test System"
                    self.node_id = f"AGENT_{self.agent_id}"
                    self.node_name = system_info.get("hostname", "Unknown Host")
                    self.desc = f"Host agent {self.agent_id}"
                    self.type = "Host"
                    self.os_ = f"{system_info.get('os', 'Unknown')} {system_info.get('os_version', 'Unknown')}"
                    self.mac = []
                    self.port = []
                    self.lib = []
                    self.comm = []
                    self.det = []
                    self.out = str(cyber_output)
                    self.infile = None

            args = Args()

            # Add MAC addresses if available
            interfaces = system_info.get("interfaces", [])
            for iface in interfaces:
                if iface.get("mac"):
                    args.mac.append(iface["mac"])

            # Add libraries from packages (limit to avoid command line length issues)
            for pkg in packages[:10]:  # Reduced to first 10 packages
                lib_name = f"{pkg.get('name', 'unknown')}@{pkg.get('version', 'unknown')}"
                args.lib.append(lib_name)

            # Convert grype data to matches format expected by converter
            matches = grype_data.get("matches", [])
            mock_grype_data = {"matches": matches}

            # Write grype data to a temporary file for the converter
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(mock_grype_data, f)
                grype_file = f.name

            # Monkey patch stdin for the converter
            original_stdin = sys.stdin
            try:
                with open(grype_file, 'r') as f:
                    sys.stdin = f
                    # Run the converter's main function with proper arguments
                    grype_to_json.main([
                        "--system", args.system,
                        "--node-id", args.node_id,
                        "--node-name", args.node_name,
                        "--desc", args.desc,
                        "--type", args.type,
                        "--os", args.os_,
                        "--out", args.out
                    ] + [f"--mac={mac}" for mac in args.mac[:3]] +  # Limit MACs to avoid timeout
                      [f"--lib={lib}" for lib in args.lib[:3]])  # Limit to 3 libs to avoid timeout

            finally:
                sys.stdin = original_stdin
                os.unlink(grype_file)

            if cyber_output.exists():
                print(f"✓ Cyber template generated: {cyber_output}")

                # Load and display the generated template
                with open(cyber_output, 'r') as f:
                    cyber_data = json.load(f)

                # Show summary
                nodes = cyber_data.get("scanned_nodes", [])
                if nodes:
                    node = nodes[0]
                    vulns = node.get("vulnerability", [])
                    print(f"  Node: {node.get('name', 'Unknown')}")
                    print(f"  OS: {node.get('OS', 'Unknown')}")
                    print(f"  Libraries: {len(node.get('lib', []))}")
                    print(f"  MAC Addresses: {len(node.get('MAC', []))}")
                    print(f"  Ports: {len(node.get('port', []))}")
                    print(f"  Vulnerabilities: {len(vulns)}")

                    if vulns:
                        print("  Top vulnerabilities:")
                        for vuln in vulns[:5]:
                            print(f"    - {vuln.get('id', 'Unknown')} ({vuln.get('severity', 'Unknown')})")

                return cyber_data
            else:
                print("✗ Cyber template file was not created")
                return None

        except Exception as e:
            print(f"✗ Error converting to cyber template: {e}")
            return None

    def step_5_generate_comprehensive_report(self, system_info, sbom_data, grype_data, cyber_data):
        """Step 5: Generate comprehensive report"""
        print("\nStep 5: Generating comprehensive report...")

        try:
            report = {
                "collection_timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id,
                "workflow_version": "1.0",
                "system_info": system_info,
                "sbom_summary": {
                    "total_packages": len(sbom_data.get("components", [])),
                    "os_name": sbom_data.get("metadata", {}).get("component", {}).get("name", "Unknown"),
                    "os_version": sbom_data.get("metadata", {}).get("component", {}).get("version", "Unknown")
                },
                "vulnerability_summary": {
                    "total_matches": len(grype_data.get("matches", [])),
                    "critical_count": len([m for m in grype_data.get("matches", []) if m.get("vulnerability", {}).get("severity") == "Critical"]),
                    "high_count": len([m for m in grype_data.get("matches", []) if m.get("vulnerability", {}).get("severity") == "High"]),
                    "medium_count": len([m for m in grype_data.get("matches", []) if m.get("vulnerability", {}).get("severity") == "Medium"]),
                    "low_count": len([m for m in grype_data.get("matches", []) if m.get("vulnerability", {}).get("severity") == "Low"])
                },
                "cyber_template": cyber_data
            }

            # Save comprehensive report
            report_file = self.output_dir / "cyber_collection_report.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)

            print(f"✓ Comprehensive report generated: {report_file}")
            return report

        except Exception as e:
            print(f"✗ Error generating report: {e}")
            return None

    def run_full_workflow(self):
        """Run the complete cyber data collection workflow"""
        print("CYBER DATA COLLECTION WORKFLOW")
        print("=" * 50)
        print(f"Agent ID: {self.agent_id}")
        print(f"Server URL: {self.server_url}")
        print(f"Output Directory: {self.output_dir}")
        print()

        # Check dependencies
        if not self.check_dependencies():
            return False

        # Step 1: Execute agent
        system_info = self.step_1_execute_agent()
        if not system_info:
            return False

        # Step 2: Collect SBOM
        sbom_data, packages = self.step_2_collect_sbom()
        if not sbom_data:
            return False

        # Step 3: Run Grype scan
        grype_data = self.step_3_run_grype_scan(self.output_dir / "sbom.json")
        if not grype_data:
            print("⚠️  Continuing without vulnerability data...")
            grype_data = {"matches": []}

        # Step 4: Convert to cyber template
        cyber_data = self.step_4_convert_to_cyber_template(grype_data, system_info, packages)
        if not cyber_data:
            return False

        # Step 5: Generate comprehensive report
        report = self.step_5_generate_comprehensive_report(system_info, sbom_data, grype_data, cyber_data)

        print("\n" + "=" * 50)
        print("WORKFLOW COMPLETED SUCCESSFULLY!")
        print("=" * 50)

        if report:
            vuln_summary = report.get("vulnerability_summary", {})
            print("Summary:")
            print(f"  • System: {system_info.get('hostname', 'Unknown')}")
            print(f"  • OS: {system_info.get('os', 'Unknown')} {system_info.get('os_version', 'Unknown')}")
            print(f"  • Packages: {report['sbom_summary']['total_packages']}")
            print(f"  • Vulnerabilities: {vuln_summary['total_matches']}")
            print(f"    - Critical: {vuln_summary['critical_count']}")
            print(f"    - High: {vuln_summary['high_count']}")
            print(f"    - Medium: {vuln_summary['medium_count']}")
            print(f"    - Low: {vuln_summary['low_count']}")

        print(f"\nOutput files in: {self.output_dir}")
        print("  • system_info.json - System information")
        print("  • sbom.json - Software Bill of Materials")
        print("  • packages.json - Raw package list")
        print("  • grype_output.json - Grype scan results")
        print("  • cyber_template_filled.json - Complete cyber template")
        print("  • cyber_collection_report.json - Comprehensive report")

        return True

def main():
    parser = argparse.ArgumentParser(description="Complete Cyber Data Collection Workflow")
    parser.add_argument("--server-url", default="http://localhost:8000",
                       help="Server URL for the dashboard API")
    parser.add_argument("--output-dir", default="cyber_output",
                       help="Output directory for generated files")
    parser.add_argument("--agent-id", help="Override agent ID")

    args = parser.parse_args()

    collector = CyberDataCollector(
        server_url=args.server_url,
        output_dir=args.output_dir
    )

    if args.agent_id:
        collector.agent_id = args.agent_id

    success = collector.run_full_workflow()

    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()

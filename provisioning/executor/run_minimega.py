"""Execute MiniMega scripts and manage execution results."""

import sys
import os
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import json


class MiniMegaRunner:
    """Executes MiniMega scripts using minimega_control.py."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.safety_config = config.get("safety", {})
        self.require_sudo = self.safety_config.get("require_sudo", True)

        # Output directories
        self.run_output_dir = Path("./out/runs")
        self.run_output_dir.mkdir(parents=True, exist_ok=True)

    def run_script(self, mm_file: str, label: str, dry_run: bool = False) -> Dict[str, Any]:
        """
        Execute a MiniMega script file.

        Args:
            mm_file: Path to .mm script file
            label: Run label for tracking
            dry_run: If True, print script instead of executing

        Returns:
            Dict with execution results
        """
        result = {
            "success": False,
            "label": label,
            "mm_file": mm_file,
            "timestamp": datetime.now().isoformat(),
            "dry_run": dry_run,
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "commands": []
        }

        if dry_run:
            # Print script content for dry run
            try:
                with open(mm_file, 'r') as f:
                    content = f.read()
                result["stdout"] = content
                result["success"] = True
                print("DRY RUN - Script content:")
                print(content)
            except Exception as e:
                result["stderr"] = str(e)
                print(f"Error reading script: {e}")
            return result

        # Import and use existing minimega_control functionality
        try:
            sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
            from utils.minimega.minimega_control import run_minimega_script

            # Capture output (modify minimega_control to capture instead of print?)
            # For now, call run_minimega_script which prints to stdout/stderr
            run_minimega_script(mm_file)

            result["success"] = True
            result["exit_code"] = 0  # Assume success if no exception

        except Exception as e:
            result["success"] = False
            result["stderr"] = str(e)
            result["exit_code"] = 1

        # Save run log
        self._save_run_log(result)

        return result

    def _save_run_log(self, result: Dict[str, Any]) -> None:
        """Save execution result to run log."""
        log_file = self.run_output_dir / f"run_{result['label']}_{result['timestamp'][:19].replace(':', '-')}.json"

        with open(log_file, 'w') as f:
            json.dump(result, f, indent=2)

        print(f"Run log saved to: {log_file}")

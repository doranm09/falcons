import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple


def find_osquery_binary() -> str:
    return shutil.which("osqueryi") or ""


def run_osquery(query: str, binary: str = "", timeout: int = 10) -> List[Dict[str, Any]]:
    binary = binary or find_osquery_binary()
    if not binary:
        raise FileNotFoundError("osqueryi not found in PATH")
    result = subprocess.run(
        [binary, "--json", query],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    try:
        data = json.loads(result.stdout or "[]")
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    return []


def build_osquery_event(query: str, results: List[Dict[str, Any]], agent_id: str, hostname: str) -> Dict[str, Any]:
    return {
        "event_type": "osquery.result",
        "source": "osquery",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message": f"osquery: {query}",
        "asset_id": agent_id,
        "asset_ip": None,
        "raw": {
            "query": query,
            "results": results,
            "hostname": hostname,
        },
    }


def _iter_files(paths: Iterable[str]) -> Iterable[str]:
    for path in paths:
        if not path:
            continue
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for name in files:
                    yield os.path.join(root, name)
        elif os.path.isfile(path):
            yield path


def hash_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 128), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_fim_baseline(paths: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    baseline: Dict[str, Dict[str, Any]] = {}
    for file_path in _iter_files(paths):
        try:
            stat = os.stat(file_path)
            baseline[file_path] = {
                "sha256": hash_file(file_path),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            }
        except Exception:
            continue
    return baseline


def save_fim_baseline(baseline: Dict[str, Dict[str, Any]], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(baseline, handle, indent=2)


def load_fim_baseline(path: str) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as handle:
        return json.load(handle) or {}


def diff_fim(baseline: Dict[str, Dict[str, Any]], current: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    changes: List[Dict[str, Any]] = []
    baseline_paths = set(baseline.keys())
    current_paths = set(current.keys())

    for path in current_paths - baseline_paths:
        changes.append({"path": path, "change": "created", "current": current[path]})
    for path in baseline_paths - current_paths:
        changes.append({"path": path, "change": "deleted", "previous": baseline[path]})
    for path in baseline_paths & current_paths:
        if baseline[path].get("sha256") != current[path].get("sha256"):
            changes.append({
                "path": path,
                "change": "modified",
                "previous": baseline[path],
                "current": current[path],
            })
    return changes


def build_fim_events(changes: List[Dict[str, Any]], agent_id: str, hostname: str) -> List[Dict[str, Any]]:
    events = []
    for change in changes:
        events.append(
            {
                "event_type": "fim.change",
                "source": "fim",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "message": f"FIM {change.get('change')} {change.get('path')}",
                "asset_id": agent_id,
                "raw": {
                    "hostname": hostname,
                    "change": change,
                },
            }
        )
    return events

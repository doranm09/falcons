import importlib.util
import io
import json
import sys
import types
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "testbed"
    / "iaea_rcs_demo"
    / "services"
    / "ids-process"
    / "ids_process_forwarder.py"
)


class _FakeHTTPResponse(io.BytesIO):
    def __init__(self, payload):
        super().__init__(json.dumps(payload).encode("utf-8"))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def _load_forwarder_module(monkeypatch):
    fake_influx_module = types.ModuleType("influxdb_client")

    class _FakeInfluxDBClient:  # pragma: no cover - should not be used in this test
        def __init__(self, *args, **kwargs):
            raise AssertionError("InfluxDBClient should not be constructed in historian status mode")

    fake_influx_module.InfluxDBClient = _FakeInfluxDBClient
    monkeypatch.setitem(sys.modules, "influxdb_client", fake_influx_module)

    fake_ids_process_module = types.ModuleType("ids_process")
    fake_ids_process_module._default_threshold_from_env = lambda: 10.0
    fake_ids_process_module._load_live_inference_context = lambda *args, **kwargs: {}
    fake_ids_process_module._parse_tag_keys = lambda raw: [item.strip() for item in str(raw).split(",") if item.strip()]
    fake_ids_process_module._query_rows = lambda *args, **kwargs: []
    fake_ids_process_module._score_row = lambda row, context: {
        "anomaly": False,
        "score": 0.0,
        "decision_threshold": context.get("threshold"),
    }
    monkeypatch.setitem(sys.modules, "ids_process", fake_ids_process_module)

    module_name = "ids_process_forwarder_test_module"
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_iter_scored_process_samples_uses_historian_status_when_selected(monkeypatch):
    module = _load_forwarder_module(monkeypatch)

    payload = {
        "generated_at": 1713700001.0,
        "profiles": {
            "main": {
                "connected": True,
                "updated_at": 1713700000.0,
                "values": {
                    "average_pressure": 4542,
                    "pt455": 4541,
                },
            }
        },
    }

    monkeypatch.setattr(
        module,
        "_load_live_inference_context",
        lambda *args, **kwargs: {"feature_keys": ["average_pressure"], "threshold": 10.0},
    )
    monkeypatch.setattr(
        module,
        "_score_row",
        lambda row, context: {
            "anomaly": True,
            "score": 42.5,
            "decision_threshold": 10.0,
        },
    )
    monkeypatch.setattr(
        module.request,
        "urlopen",
        lambda url, timeout=0: _FakeHTTPResponse(payload),
    )

    sample_iter = module.iter_scored_process_samples(
        source_mode="historian_status",
        influx_url="",
        historian_status_url="http://historian:4840/",
        influx_token="",
        influx_org="iaea",
        influx_bucket="iaea_rcs",
        profile="main",
        measurement="rcs_metrics",
        tag_keys=["average_pressure", "pt455"],
        watch_range_start="-5s",
        poll_interval=0.0,
        model_path=Path("/tmp/ids-process.joblib"),
        decision_threshold=10.0,
    )

    sample = next(sample_iter)

    assert sample["profile"] == "main"
    assert sample["measurement"] == "rcs_metrics"
    assert sample["anomaly"] is True
    assert sample["score"] == 42.5
    assert sample["decision_threshold"] == 10.0
    assert sample["fields"] == {
        "average_pressure": 4542,
        "pt455": 4541,
    }

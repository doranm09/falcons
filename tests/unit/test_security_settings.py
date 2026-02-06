import os

from cyber_pen_test.settings import read_secret


def test_read_secret_prefers_file(tmp_path, monkeypatch):
    secret_path = tmp_path / "secret.txt"
    secret_path.write_text("file-secret")
    monkeypatch.setenv("TEST_SECRET_FILE", str(secret_path))
    monkeypatch.setenv("TEST_SECRET", "env-secret")

    assert read_secret("TEST_SECRET", default="") == "file-secret"


def test_read_secret_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("TEST_SECRET", "env-secret")
    assert read_secret("TEST_SECRET", default="") == "env-secret"


def test_read_secret_default_when_missing(monkeypatch):
    monkeypatch.delenv("MISSING_SECRET", raising=False)
    assert read_secret("MISSING_SECRET", default="fallback") == "fallback"

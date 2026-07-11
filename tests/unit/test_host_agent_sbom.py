import subprocess

from host_agent.sbom.os_sbom import collect_linux_packages, generate_cyclonedx_sbom


def test_collect_linux_packages_parses_apk_inventory(monkeypatch):
    def fake_exists(path):
        return path in {"/etc/os-release", "/sbin/apk"}

    monkeypatch.setattr("host_agent.sbom.os_sbom.os.path.exists", fake_exists)
    monkeypatch.setattr("host_agent.sbom.os_sbom.shutil.which", lambda name: None)
    monkeypatch.setattr(
        "host_agent.sbom.os_sbom.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="\n".join(
                [
                    "alpine-baselayout-3.4.3-r1",
                    "bash-5.2.37-r0",
                    "python3-3.12.12-r0",
                ]
            ),
            stderr="",
        ),
    )

    packages = collect_linux_packages()

    assert packages == [
        {"name": "alpine-baselayout", "version": "3.4.3-r1", "type": "apk"},
        {"name": "bash", "version": "5.2.37-r0", "type": "apk"},
        {"name": "python3", "version": "3.12.12-r0", "type": "apk"},
    ]


def test_generate_cyclonedx_sbom_uses_apk_purls(monkeypatch):
    monkeypatch.setattr(
        "host_agent.sbom.os_sbom.detect_os_metadata",
        lambda: {"name": "alpine", "version": "3.18.6"},
    )

    sbom = generate_cyclonedx_sbom(
        [{"name": "bash", "version": "5.2.37-r0", "type": "apk"}]
    )

    assert sbom["components"][0]["purl"] == "pkg:apk/alpine/bash@5.2.37-r0"

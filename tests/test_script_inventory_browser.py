"""End-to-end tests with headless Chromium against a local fixture site (no internet)."""

import json
import socket

import pytest

pytest.importorskip("playwright.sync_api")

from script_inventory.analyze import build_report  # noqa: E402
from script_inventory.cli import main  # noqa: E402
from script_inventory.collect import collect  # noqa: E402


@pytest.fixture(scope="module")
def report(site):
    raws = list(collect([site + "/"], settle=2.0, delay=0))
    return build_report(raws[0])


def by_name(report):
    return {(s.url or "inline").rsplit("/", 1)[-1]: s for s in report.scripts if not s.inline}


def test_all_scripts_found(report):
    names = set(by_name(report))
    assert {"jquery-3.4.1.min.js", "good.js", "bad.js", "mod.js", "app.js", "lodash.js",
            "injected.js", "moment.js"} <= names
    assert report.inline["count"] == 2
    assert report.inline["data_blocks"] == 1
    assert report.inline["event_handler_elements"] == 1


def test_runtime_injection_and_iframe(report):
    s = by_name(report)
    assert s["injected.js"].loaded_by == "runtime"
    assert s["app.js"].loaded_by == "html" and s["app.js"].defer
    assert s["mod.js"].module
    assert s["lodash.js"].is_async
    assert not s["moment.js"].main_frame
    assert len(report.frames["inspected"]) == 2


def test_sri_checked_against_fetched_body(report):
    s = by_name(report)
    assert s["good.js"].sri == "valid"
    assert s["bad.js"].sri == "invalid"
    assert s["jquery-3.4.1.min.js"].sri == "absent"


def test_party_by_registrable_domain(report):
    s = by_name(report)
    assert s["lodash.js"].party == "third"  # localhost vs 127.0.0.1
    assert s["app.js"].party == "first"
    assert s["app.js"].size == len(b"window.appLoaded = true;\n")


def test_libraries_and_advisories(report):
    libs = {(l.name, l.version): l for l in report.libraries}
    assert set(libs) == {("jquery", "3.4.1"), ("lodash", "4.17.20"), ("moment", "2.29.1")}
    assert libs[("jquery", "3.4.1")].via == ["url", "banner", "global"]
    assert libs[("moment", "2.29.1")].via == ["url", "banner", "global"]  # global probed inside the iframe
    ids = {a["id"] for l in libs.values() for a in l.advisories}
    assert {"CVE-2020-11022", "CVE-2020-11023", "CVE-2021-23337", "CVE-2022-31129"} <= ids
    assert report.mixed_content == []  # plain http page


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_cli_exit_codes(site, tmp_path, capsys):
    out = tmp_path / "r.json"
    assert main([site + "/", "--format", "json", "-o", str(out), "--settle", "0.5", "--delay", "0"]) == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["findings_at_or_above"] >= 5
    assert main([site + "/clean", "--settle", "0", "--delay", "0"]) == 0
    assert "No known library detected." in capsys.readouterr().out
    assert main([site + "/", "--fail-on", "none", "--settle", "0", "--delay", "0"]) == 0
    assert main([f"http://127.0.0.1:{free_port()}/", "--settle", "0", "--timeout", "10"]) == 2
    assert main([site + "/missing", "--settle", "0"]) == 2


def test_cli_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["ftp://example.com/"])
    assert exc.value.code == 2

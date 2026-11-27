"""Regression tests for the defects found in the 2026-11-27 code review.

Each test drives the real CLI (or the real parser) on a fixture report and fails
if the corresponding fix is reverted.
"""

import ast
import csv
import re
import tomllib
import warnings
import zipfile
from pathlib import Path

import pytest
from conftest import EDGE_REPORT, run_cli

from openvasreporting.libs.config import Config, Config_YAML
from openvasreporting.libs.parsed_data import Host, Port, Vulnerability
from openvasreporting.libs.parser import openvas_parser_by_host, openvas_parser_by_vuln

PKG_DIR = Path(__file__).parent.parent / "openvasreporting"
IMPORT_TO_DIST = {
    "yaml": "pyyaml",
    "defusedxml": "defusedxml",
    "netaddr": "netaddr",
    "xlsxwriter": "xlsxwriter",
    "docx": "python-docx",
    "matplotlib": "matplotlib",
    "numpy": "numpy",
    "jinja2": "jinja2",
}


def _read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# 1. every third-party import is a declared dependency
def test_all_third_party_imports_are_declared_dependencies():
    declared = tomllib.loads((PKG_DIR.parent / "pyproject.toml").read_text())["project"]["dependencies"]
    declared_names = {re.split(r"[<>=!~ \[]", d, maxsplit=1)[0].lower() for d in declared}
    imported = set()
    for py in PKG_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(py.read_text())):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
    missing = {IMPORT_TO_DIST[m] for m in imported if m in IMPORT_TO_DIST} - declared_names
    assert not missing, f"imported but not declared in pyproject.toml: {missing}"


# 2. docx export without template (pkg_resources removed from setuptools)
def test_docx_export_with_default_template(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "docx")
    assert res.returncode == 0, res.stderr
    with zipfile.ZipFile(tmp_path / "r.docx") as z:
        assert "SSH Weak Encryption" in z.read("word/document.xml").decode()


def test_docx_export_closes_matplotlib_figures(tmp_path):
    import matplotlib.pyplot as plt

    from openvasreporting.libs.export import export_to_word_by_vuln

    config = Config([str(EDGE_REPORT)], output_file=str(tmp_path / "r"), format="docx", report_type="v")
    export_to_word_by_vuln(openvas_parser_by_vuln(config), None, config.output_file)
    assert plt.get_fignums() == []


# 3. invalid network filter gives a clean error, not NameError
def test_invalid_network_filter_reports_clean_error(tmp_path, edge_report):
    nets = tmp_path / "nets.txt"
    nets.write_text("999.1.1.1\n")
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "csv", "-n", str(nets))
    assert res.returncode == 1
    assert "999.1.1.1" in res.stderr
    assert "Traceback" not in res.stderr


# 4. non numeric port ("package") does not crash and keeps the result text
def test_package_port_is_exported(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 0, res.stderr
    rows = [r for r in _read_csv(tmp_path / "r.csv") if r["vulnerability"] == "Outdated package libfoo"]
    assert len(rows) == 1
    assert rows[0]["protocol"] == "package"


def test_package_port_keeps_result_text():
    vulns = openvas_parser_by_vuln(Config([str(EDGE_REPORT)], format="csv", report_type="v"))
    libfoo = next(v for v in vulns if v.name == "Outdated package libfoo")
    _, port = libfoo.hosts[0]
    assert "Vulnerable package: libfoo" in port.result


# 5. IPv6 hosts in the Excel by-host report
def test_excel_host_report_with_ipv6(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "xlsx", "-T", "h")
    assert res.returncode == 0, res.stderr
    with zipfile.ZipFile(tmp_path / "r.xlsx") as z:
        workbook = z.read("xl/workbook.xml").decode()
    assert "2001.db8..1" in workbook


# 6. references column is not split character by character
def test_csv_by_vuln_references(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 0, res.stderr
    row = next(r for r in _read_csv(tmp_path / "r.csv") if r["vulnerability"].startswith("OpenSSL"))
    assert "https://www.openssl.org/news/secadv/20221101.txt" in row["references"]


# 7. YAML: regex includes alone are honoured
def test_yaml_regex_includes_only(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text("regex:\n  includes:\n    - 'ssh'\n")
    config = Config_YAML([str(EDGE_REPORT)], str(cfg))
    assert config.regex_included is not None
    names = {v.name for v in openvas_parser_by_vuln(config)}
    assert names == {"SSH Weak Encryption Algorithms Supported"}


def test_yaml_accepts_html_format(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text("format: html\n")
    assert Config_YAML([str(EDGE_REPORT)], str(cfg), str(tmp_path / "r")).format == "html"


# 8. input validation
def test_non_openvas_xml_is_rejected_cleanly(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<report>garbage")
    res = run_cli("-i", str(bad), "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 1
    assert "bad.xml" in res.stderr and "Traceback" not in res.stderr


def test_xml_that_is_not_a_report_is_rejected(tmp_path):
    other = tmp_path / "other.xml"
    other.write_text('<?xml version="1.0"?><config><x/></config>')
    res = run_cli("-i", str(other), "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 1
    assert "other.xml" in res.stderr


def test_report_with_xml_declaration_is_accepted(tmp_path):
    f = tmp_path / "decl.xml"
    f.write_text('<?xml version="1.0" encoding="UTF-8"?>\n' + EDGE_REPORT.read_text())
    res = run_cli("-i", str(f), "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 0, res.stderr


# 9. input pattern that matches nothing
def test_input_glob_without_match_is_an_error(tmp_path):
    res = run_cli("-i", str(tmp_path / "nope*.xml"), "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 1
    assert "nope*.xml" in res.stderr
    assert not (tmp_path / "r.csv").exists()


# Host mode keeps every port of a vulnerability
def test_host_csv_lists_every_port(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "csv", "-T", "h")
    assert res.returncode == 0, res.stderr
    ports = {r["port"] for r in _read_csv(tmp_path / "r.csv") if r["ip"] == "192.168.1.10"}
    assert ports == {"443", "8443"}


def test_host_vuln_count_is_unique_per_vuln():
    tree = openvas_parser_by_host(Config([str(EDGE_REPORT)], format="csv", report_type="h"))
    assert tree["192.168.1.10"].num_vulns == 1
    assert tree["192.168.1.10"].nv["critical"] == 1


# Parser robustness
def test_missing_hostname_and_bare_tag_are_tolerated():
    vulns = openvas_parser_by_vuln(Config([str(EDGE_REPORT)], format="csv", report_type="v"))
    libfoo = next(v for v in vulns if v.name == "Outdated package libfoo")
    host, _ = libfoo.hosts[0]
    assert host.ip == "2001:db8::1"
    assert libfoo.insight == ""


def test_installed_version_is_extracted_cleanly(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "csv", "-T", "h")
    assert res.returncode == 0, res.stderr
    versions = {r["ip"]: r["version"] for r in _read_csv(tmp_path / "r.csv") if r["vulnerability"].startswith("OpenSSL")}
    assert versions["192.168.1.10"] == "3.0.1 (vendor build)"
    assert versions["192.168.1.12"] == "3.0.2"


def test_result_text_collapses_crlf_runs():
    vulns = openvas_parser_by_vuln(Config([str(EDGE_REPORT)], format="csv", report_type="v"))
    ssh = next(v for v in vulns if v.name.startswith("SSH"))
    assert "\n\n" not in ssh.hosts[0][1].result


# Excel by vuln: row heights applied to the right rows
def test_excel_vuln_row_heights_target_hosts_rows(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "xlsx")
    assert res.returncode == 0, res.stderr
    with zipfile.ZipFile(tmp_path / "r.xlsx") as z:
        # sheet1 = Summary, sheet2 = TOC, then one sheet per vulnerability by CVSS desc:
        # sheet3 = OpenSSL (9.8), sheet4 = SSH (7.5) whose multi-line result is on row 15
        ssh_sheet = z.read("xl/worksheets/sheet4.xml").decode()
    row15 = re.search(r'<row r="15"[^>]*>', ssh_sheet).group(0)
    row16 = re.search(r'<row r="16"[^>]*>', ssh_sheet)
    assert 'customHeight="1"' in row15
    assert row16 is None or "customHeight" not in row16.group(0)


# Model sanity
def test_vulnerability_equality_with_other_types():
    v = Vulnerability("1.2", name="n", threat="high")
    assert (v == "something") is False


def test_vulnerability_equality_compares_hosts():
    a = Vulnerability("1.2", name="n", threat="high")
    b = Vulnerability("1.2", name="n", threat="high")
    a.add_vuln_host(Host("10.0.0.1"), Port(80))
    b.add_vuln_host(Host("10.0.0.2"), Port(80))
    assert a != b


def test_sources_compile_without_syntax_warnings():
    for py in PKG_DIR.rglob("*.py"):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(py.read_text(), str(py), "exec")


@pytest.mark.parametrize("fmt", ["xlsx", "csv", "docx"])
def test_vulnerability_exports_succeed(tmp_path, edge_report, fmt):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", fmt)
    assert res.returncode == 0, res.stderr
    assert (tmp_path / f"r.{fmt}").stat().st_size > 0


def test_zero_cvss_is_kept():
    vulns = openvas_parser_by_vuln(Config([str(EDGE_REPORT)], format="csv", report_type="v"))
    os_detection = next(v for v in vulns if v.name == "OS Detection Consolidation")
    assert os_detection.cvss == 0.0
    assert Vulnerability("1", name="n", threat="log").cvss == -1.0


def test_pyproject_metadata_is_well_formed():
    project = tomllib.loads((PKG_DIR.parent / "pyproject.toml").read_text())["project"]
    assert project["requires-python"].startswith(">=")
    for key in ("authors", "description", "readme", "license", "classifiers", "dynamic"):
        assert key in project, key
    extras = project["optional-dependencies"]
    assert set(extras) == {"test", "browser"}
    assert all(isinstance(v, list) for v in extras.values())

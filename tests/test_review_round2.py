"""Regression tests for the defects found by the adversarial review of the branch."""

import csv
import zipfile

from conftest import result_xml, run_cli, write_report

from openvasreporting.libs.config import Config
from openvasreporting.libs.parser import openvas_parser_by_vuln


def _csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_vuln_cvss_is_max_over_results(tmp_path):
    a = write_report(tmp_path / "a.xml", result_xml("1.1", "Same", "10.0.0.1", "80/tcp", "7.5"),
                     result_xml("1.1", "Same", "10.0.0.9", "80/tcp", "9.5"))
    (vuln,) = openvas_parser_by_vuln(Config([a], format="csv", report_type="v"))
    assert vuln.cvss == 9.5 and vuln.level == "critical"


def test_installed_version_stays_on_its_line(tmp_path):
    a = write_report(tmp_path / "a.xml",
                     result_xml("1.1", "Empty", "10.0.0.1", "22/tcp", "5.0", "Installed version: \nFixed version: 2.0"),
                     result_xml("1.2", "Debian", "10.0.0.1", "22/tcp", "5.0",
                                "Installed version: 7.4p1 Debian 10+deb9u7\nFixed version: 8.0"))
    res = run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "csv", "-T", "h")
    assert res.returncode == 0, res.stderr
    versions = {r["vulnerability"]: r["version"] for r in _csv(tmp_path / "r.csv")}
    assert versions == {"Empty": "", "Debian": "7.4p1 Debian 10+deb9u7"}


# host mode: one row / one label per port even when results differ
def test_host_mode_dedupes_ports(tmp_path):
    a = write_report(tmp_path / "a.xml", result_xml("1.1", "Dup", "10.0.0.2", "443/tcp", "5.0", "result one"),
                     result_xml("1.1", "Dup", "10.0.0.2", "443/tcp", "5.0", "result two"))
    assert run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "csv", "-T", "h").returncode == 0
    assert len(_csv(tmp_path / "r.csv")) == 1
    assert run_cli("-i", a, "-o", str(tmp_path / "x"), "-f", "xlsx", "-T", "h").returncode == 0
    with zipfile.ZipFile(tmp_path / "x.xlsx") as z:
        strings = z.read("xl/sharedStrings.xml").decode()
    assert "443/tcp, 443/tcp" not in strings and "443/tcp" in strings


# docx with an empty selection
def test_docx_with_no_selected_vulnerability(tmp_path):
    a = write_report(tmp_path / "a.xml", result_xml("1.1", "Medium only", "10.0.0.2", "443/tcp", "5.0"))
    res = run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "docx", "-l", "c")
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "r.docx").stat().st_size > 0


# existing file names with glob characters
def test_literal_path_with_glob_characters(tmp_path):
    a = write_report(tmp_path / "report[1].xml", result_xml("1.1", "X", "10.0.0.2", "443/tcp", "5.0"))
    res = run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 0, res.stderr
    assert len(_csv(tmp_path / "r.csv")) == 1


def test_input_option_requires_a_file(tmp_path):
    res = run_cli("-i", "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 2
    assert not (tmp_path / "r.csv").exists()


# parser / config robustness
def test_network_filter_with_hostname_instead_of_ip(tmp_path):
    a = write_report(tmp_path / "a.xml", result_xml("1.1", "X", "srv.example.com", "443/tcp", "5.0"),
                     result_xml("1.2", "Y", "10.0.0.2", "443/tcp", "5.0"))
    nets = tmp_path / "n.txt"
    nets.write_text("10.0.0.0/8\n   \n")
    res = run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "csv", "-n", str(nets))
    assert res.returncode == 0, res.stderr
    assert {r["ip"] for r in _csv(tmp_path / "r.csv")} == {"10.0.0.2"}


def test_general_port_with_dash(tmp_path):
    a = write_report(tmp_path / "a.xml", result_xml("1.1", "CPE", "10.0.0.2", "general/CPE-T", "0.0"))
    assert run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "csv").returncode == 0
    assert _csv(tmp_path / "r.csv")[0]["protocol"] == "CPE-T"


def test_result_without_threat_or_nvt_name(tmp_path):
    broken = ('<result><name>n</name><host>10.0.0.3</host><port>80/tcp</port>'
              '<nvt oid="1.9"><family>F</family><tags>summary=x</tags></nvt><severity>5.0</severity></result>')
    no_nvt = '<result><name>n</name><host>10.0.0.4</host><port>80/tcp</port><severity>5.0</severity></result>'
    a = write_report(tmp_path / "a.xml", broken, no_nvt)
    res = run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 0, res.stderr
    assert [r["ip"] for r in _csv(tmp_path / "r.csv")] == ["10.0.0.3"]


def test_docx_export_leaves_matplotlib_backend_alone(tmp_path):
    import matplotlib

    from openvasreporting.libs.export import export_to_word_by_vuln

    before = matplotlib.get_backend()
    a = write_report(tmp_path / "a.xml", result_xml("1.1", "X", "10.0.0.2", "443/tcp", "5.0"))
    config = Config([a], output_file=str(tmp_path / "r"), format="docx", report_type="v")
    export_to_word_by_vuln(openvas_parser_by_vuln(config), None, config.output_file)
    assert matplotlib.get_backend() == before


# GitHub issue #49: a result found on 541 ports of one host appeared only once in host reports
def test_issue_49_every_port_of_a_host_is_reported(tmp_path):
    results = [result_xml("1.3.6.1.4.1.25623.1.0.900498", "Service Detection", "10.0.0.5", f"{p}/tcp", "5.0",
                          f"Service on port {p}") for p in range(1000, 1541)]
    a = write_report(tmp_path / "a.xml", *results)
    assert run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "csv", "-T", "h").returncode == 0
    assert len(_csv(tmp_path / "r.csv")) == 541
    assert run_cli("-i", a, "-o", str(tmp_path / "x"), "-f", "xlsx", "-T", "h").returncode == 0
    with zipfile.ZipFile(tmp_path / "x.xlsx") as z:
        assert z.read("xl/sharedStrings.xml").decode().count("/tcp") == 541

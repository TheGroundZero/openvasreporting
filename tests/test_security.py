"""Security regressions found by the red-team review of the XML parser and configuration."""

from conftest import EDGE_REPORT, run_cli


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


def test_yaml_template_must_be_a_path(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text("format: docx\ntemplate: 123\n")
    res = run_cli("-i", str(EDGE_REPORT), "-o", str(tmp_path / "r"), "-c", str(cfg))
    assert res.returncode == 1 and "Traceback" not in res.stderr

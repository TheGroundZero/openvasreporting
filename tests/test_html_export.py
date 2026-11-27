"""Integration tests for the HTML export (-f html), driven through the real CLI."""

import base64
import hashlib
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from conftest import run_cli


class _Collector(HTMLParser):
    """Collects tags with attributes and the text content of <script> elements."""

    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict]] = []
        self.scripts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "script":
            self._in_script = True
            self.scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.scripts[-1] += data

    def find(self, tag: str, **attrs) -> list[dict]:
        return [a for t, a in self.tags if t == tag and all(a.get(k) == v for k, v in attrs.items())]


def _render(tmp_path: Path, report: str, *extra: str) -> tuple[str, _Collector]:
    res = run_cli("-i", report, "-o", str(tmp_path / "r"), "-f", "html", *extra)
    assert res.returncode == 0, res.stderr
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    doc = _Collector()
    doc.feed(html)
    return html, doc


def _section(html: str, section_id: str) -> str:
    match = re.search(rf'<section[^>]*id="{section_id}"[^>]*>(.*?)</section>', html, re.DOTALL)
    assert match, section_id
    return match.group(1)


@pytest.fixture
def rendered(tmp_path, edge_report):
    return _render(tmp_path, edge_report)


def test_three_views_are_present(rendered):
    html, doc = rendered
    for section_id in ("summary", "vulnerabilities", "hosts"):
        assert doc.find("section", id=section_id), section_id
    assert "<title>" in html


def test_scan_controlled_text_is_escaped(rendered):
    html, doc = rendered
    assert "<script>alert(" not in html
    assert "<img src=x onerror" not in html
    assert "</textarea><script>" not in html
    assert "&lt;script&gt;alert(&#39;xss-name&#39;)&lt;/script&gt;" in html
    # only our own inline script exists in the document
    assert len(doc.find("script")) == 1


def test_csp_only_allows_our_own_script(rendered):
    _, doc = rendered
    csp = doc.find("meta", **{"http-equiv": "Content-Security-Policy"})
    assert csp, "missing CSP"
    policy = csp[0]["content"]
    assert "default-src 'none'" in policy
    assert "unsafe-inline" not in policy.split("script-src")[1].split(";")[0]
    digest = base64.b64encode(hashlib.sha256(doc.scripts[0].encode()).digest()).decode()
    assert f"'sha256-{digest}'" in policy


def test_report_is_self_contained(rendered):
    _, doc = rendered
    assert not [s for s in doc.find("script") if "src" in s]
    assert not doc.find("link", rel="stylesheet")
    images = doc.find("img")
    assert images and all(img["src"].startswith("data:image/png;base64,") for img in images)


def test_summary_counts_per_level(rendered):
    html, _ = rendered
    summary = _section(html, "summary")
    expected = {"critical": (1, 2), "high": (1, 1), "medium": (1, 1), "low": (1, 1), "none": (1, 1)}
    for level, (vulns, hosts) in expected.items():
        tile = re.search(rf'data-level="{level}".*?data-vulns="(\d+)".*?data-hosts="(\d+)"', summary, re.DOTALL)
        assert tile, level
        assert (int(tile.group(1)), int(tile.group(2))) == (vulns, hosts), level


def test_summary_top_hosts_ranked(rendered):
    html, _ = rendered
    summary = _section(html, "summary")
    ranked = re.findall(r'data-host-rank="\d+"[^>]*data-ip="([^"]+)"', summary)
    assert ranked[0] == "192.168.1.10"
    assert set(ranked) == {"192.168.1.10", "192.168.1.12", "192.168.1.20", "2001:db8::1"}


def test_vulnerability_view_lists_every_affected_port(rendered):
    html, _ = rendered
    vulns = _section(html, "vulnerabilities")
    card = re.search(r'<article[^>]*data-oid="1.3.6.1.4.1.25623.1.0.100001".*?</article>', vulns, re.DOTALL).group(0)
    rows = re.findall(r"<tr data-affected>.*?</tr>", card, re.DOTALL)
    assert len(rows) == 3
    assert "8443" in card and "CVE-2022-3602" in card
    assert "Update to 3.0.7 or later." in card


def test_vulnerabilities_sorted_by_cvss(rendered):
    html, _ = rendered
    scores = [float(s) for s in re.findall(r'<article[^>]*data-cvss="([\d.]+)"', _section(html, "vulnerabilities"))]
    assert scores == sorted(scores, reverse=True)
    assert len(scores) == 5


def test_host_view_links_to_vulnerability_cards(rendered):
    html, doc = rendered
    hosts = _section(html, "hosts")
    ipv6 = re.search(r'<article[^>]*data-ip="2001:db8::1".*?</article>', hosts, re.DOTALL).group(0)
    assert "Outdated package libfoo" in ipv6 and "package" in ipv6
    card_ids = {a["id"] for a in doc.find("article") if a.get("id", "").startswith("vuln-")}
    links = set(re.findall(r'href="#(vuln-\d+)"', hosts))
    assert links and links <= card_ids


def test_only_http_references_become_links(rendered):
    html, _ = rendered
    assert 'href="https://www.openssl.org/news/secadv/20221101.txt"' in html
    assert 'href="WID-SEC-2022-1234"' not in html
    assert "WID-SEC-2022-1234" in html


def test_summary_is_the_only_printed_section(rendered):
    html, _ = rendered
    print_css = re.search(r"@media print\s*{(.*?)}\s*}", html, re.DOTALL)
    assert print_css and "#vulnerabilities" in print_css.group(1) and "#hosts" in print_css.group(1)


def test_report_type_is_ignored_for_html(tmp_path, edge_report):
    html_v, _ = _render(tmp_path, edge_report)
    html_h, _ = _render(tmp_path, edge_report, "-T", "h")
    strip = lambda h: re.sub(r"Generated on [^<]+", "", h)
    assert strip(html_v) == strip(html_h)


def test_scan_metadata_in_header(rendered):
    html, _ = rendered
    summary = _section(html, "summary")
    assert "Weekly LAN scan" in summary
    assert "2026-11-20" in summary
    assert "report_edge_cases.xml" in summary


def test_custom_template_with_t_option(tmp_path, edge_report):
    tpl = tmp_path / "mine.html.j2"
    tpl.write_text("{{ vulnerabilities|length }}|{{ hosts|length }}|{{ levels[0].vulns }}")
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "html", "-t", str(tpl))
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "r.html").read_text() == "5|4|1"


def test_missing_custom_template_is_a_clean_error(tmp_path, edge_report):
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-f", "html", "-t", str(tmp_path / "nope.j2"))
    assert res.returncode == 1
    assert "nope.j2" in res.stderr and "Traceback" not in res.stderr


def test_empty_selection_still_renders(tmp_path, edge_report):
    regex = tmp_path / "re.txt"
    regex.write_text("no-such-vulnerability\n")
    html, _ = _render(tmp_path, edge_report, "-r", str(regex))
    assert "No vulnerabilities" in _section(html, "vulnerabilities")


def test_yaml_config_html_format(tmp_path, edge_report):
    cfg = tmp_path / "c.yml"
    cfg.write_text("format: html\nlevel: high\n")
    res = run_cli("-i", edge_report, "-o", str(tmp_path / "r"), "-c", str(cfg))
    assert res.returncode == 0, res.stderr
    html = (tmp_path / "r.html").read_text()
    assert len(re.findall(r"<article[^>]*data-cvss=", _section(html, "vulnerabilities"))) == 2


def test_affected_ips_link_to_their_host(rendered):
    html, doc = rendered
    host_ids = {a["data-ip"]: a["id"] for a in doc.find("article") if a.get("id", "").startswith("host-")}
    assert set(host_ids) == {"192.168.1.10", "192.168.1.12", "192.168.1.20", "2001:db8::1"}
    rows = re.findall(r"<tr data-affected>.*?</tr>", _section(html, "vulnerabilities"), re.DOTALL)
    assert rows
    for row in rows:
        link = re.search(r'<a class="host-link" href="#(host-\d+)">([^<]+)</a>', row)
        assert link, row[:200]
        assert host_ids[link.group(2)] == link.group(1)


def test_summary_top_hosts_link_to_their_host(rendered):
    html, doc = rendered
    host_ids = {a["data-ip"]: a["id"] for a in doc.find("article") if a.get("id", "").startswith("host-")}
    rows = re.findall(r'<tr data-host-rank="\d+" data-ip="([^"]+)">(.*?)</tr>', _section(html, "summary"), re.DOTALL)
    assert rows
    for ip, row in rows:
        assert f'<a class="host-link" href="#{host_ids[ip]}">{ip}</a>' in row

#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

"""Self-contained HTML report: Summary / By vulnerability / By host."""

import base64
import hashlib
import os
import re
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime
from importlib.resources import files
from pathlib import Path

from jinja2 import FileSystemLoader, StrictUndefined, TemplateError, TemplateNotFound
from jinja2.sandbox import ImmutableSandboxedEnvironment

from .config import Config
from .parsed_data import Port, Vulnerability, installed_version, level_of
from .parser import ScanInfo

DEFAULT_TEMPLATE_DIR = files("openvasreporting") / "src" / "html"
TEMPLATE_NAME = "report.html.j2"
SCRIPT_NAME = "report.js"
LOGO_NAME = "logo.png"
TOP_HOSTS = 10
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE | re.ASCII)
# bidirectional control characters: a scanned host could use them to disguise its name
BIDI_CONTROLS_RE = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069]")
LEVELS = tuple(Config.levels().values())  # critical .. none


@dataclass(frozen=True)
class Reference:
    text: str
    url: str | None


@dataclass(frozen=True)
class Affected:
    ip: str
    hostname: str
    port: str
    protocol: str
    result: str
    cvss: float
    level: str
    version: str


@dataclass(frozen=True)
class VulnView:
    anchor: str
    oid: str
    name: str
    cvss: float
    level: str
    family: str
    description: str
    insight: str
    detection: str
    impact: str
    affected_products: str
    solution: str
    solution_type: str
    cves: tuple[Reference, ...]
    references: tuple[Reference, ...]
    affected: tuple[Affected, ...]


@dataclass(frozen=True)
class HostFinding:
    vuln: VulnView
    ports: str
    cvss: float  # worst severity of this vulnerability on this host
    level: str


@dataclass(frozen=True)
class HostView:
    anchor: str
    ip: str
    hostname: str
    max_cvss: float
    level: str
    counts: dict
    total: int
    findings: tuple[HostFinding, ...]


@dataclass(frozen=True)
class LevelStat:
    level: str
    color: str
    vulns: int
    hosts: int


def _port_label(port: Port) -> tuple[str, str]:
    """(port, protocol) columns: 'general' for host level network findings, and
    non network 'ports' (e.g. 'package') keep their label as protocol."""
    if port.number:
        return str(port.number), port.protocol
    if port.protocol in ("tcp", "udp", "icmp"):
        return "general", port.protocol
    return "", port.protocol


def _clean(text: str) -> str:
    """Scan-derived text with bidirectional controls made visible (e.g. '[U+202E]')."""
    return BIDI_CONTROLS_RE.sub(lambda m: f"[U+{ord(m.group(0)):04X}]", text or "")


def _references(vuln: Vulnerability) -> tuple[Reference, ...]:
    refs = list(vuln.reference_list) or vuln.references.split(" , ")
    refs = [r.strip() for r in refs if r.strip() and r.strip() != "Unknown"]
    return tuple(Reference(_clean(r), r if r.lower().startswith(("https://", "http://"))
                           and not BIDI_CONTROLS_RE.search(r) else None) for r in refs)


def _cves(vuln: Vulnerability) -> tuple[Reference, ...]:
    return tuple(Reference(_clean(c.upper()), f"https://nvd.nist.gov/vuln/detail/{c.upper()}"
                           if CVE_RE.fullmatch(c) else None) for c in vuln.cves)


def _affected(vuln: Vulnerability) -> tuple[Affected, ...]:
    rows = []
    for host, port in vuln.hosts:
        cvss = port.cvss if port.cvss is not None else vuln.cvss
        number, protocol = _port_label(port)
        rows.append(Affected(_clean(host.ip), _clean(host.host_name if host.host_name not in ("", "N/A") else ""),
                             number, _clean(protocol), _clean(port.result), cvss, level_of(cvss),
                             _clean(installed_version(port.result))))
    return tuple(rows)


def _vuln_view(index: int, vuln: Vulnerability) -> VulnView:
    return VulnView(anchor=f"vuln-{index}", oid=_clean(vuln.vuln_id), name=_clean(vuln.name),
                    cvss=vuln.cvss, level=vuln.level, family=_clean(vuln.family),
                    description=_clean(vuln.description), insight=_clean(vuln.insight),
                    detection=_clean(vuln.detect), impact=_clean(vuln.impact),
                    affected_products=_clean(vuln.affected), solution=_clean(vuln.solution),
                    solution_type=_clean(vuln.solution_type), cves=_cves(vuln), references=_references(vuln),
                    affected=_affected(vuln))


def _host_views(vulns: list[VulnView]) -> list[HostView]:
    """Pivot the vulnerability list into hosts, ranked like the OpenVAS host tab."""
    grouped: dict[str, dict] = {}
    for vuln in vulns:
        for item in vuln.affected:
            host = grouped.setdefault(item.ip, {"hostname": "", "findings": {}})
            host["hostname"] = host["hostname"] or item.hostname
            finding = host["findings"].setdefault(vuln.anchor, {"vuln": vuln, "ports": [], "cvss": item.cvss})
            finding["cvss"] = max(finding["cvss"], item.cvss)
            label = f"{item.port}/{item.protocol}" if item.port else item.protocol
            if label not in finding["ports"]:
                finding["ports"].append(label)

    views = []
    for ip, data in grouped.items():
        findings = tuple(sorted((HostFinding(f["vuln"], ", ".join(f["ports"]), f["cvss"], level_of(f["cvss"]))
                                 for f in data["findings"].values()), key=lambda f: (-f.cvss, f.vuln.name)))
        counts = {level: sum(1 for f in findings if f.level == level) for level in LEVELS}
        max_cvss = max(f.cvss for f in findings)
        views.append(HostView(anchor="", ip=ip, hostname=data["hostname"], max_cvss=max_cvss,
                              level=level_of(max_cvss), counts=counts,
                              total=sum(counts[lvl] for lvl in LEVELS if lvl != "none"),
                              findings=findings))
    rank = lambda h: (h.max_cvss, *(h.counts[lvl] for lvl in LEVELS[:-1]))
    ranked = sorted(views, key=rank, reverse=True)
    return [replace(h, anchor=f"host-{i}") for i, h in enumerate(ranked, 1)]


def _level_stats(vulns: list[VulnView]) -> list[LevelStat]:
    return [LevelStat(level=level, color=Config.colors()[level],
                      vulns=sum(1 for v in vulns if v.level == level),
                      hosts=len({a.ip for v in vulns if v.level == level for a in v.affected}))
            for level in LEVELS]


def _family_stats(vulns: list[VulnView]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for v in vulns:
        counts[v.family] = counts.get(v.family, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _environment(template: str | None) -> tuple[ImmutableSandboxedEnvironment, str]:
    """Sandboxed Jinja environment (autoescape on) and template name.

    The sandbox keeps a custom template from running Python code (templates are often shared files).
    """
    if template is None:
        directory, name = Path(str(DEFAULT_TEMPLATE_DIR)), TEMPLATE_NAME
    else:
        try:
            resolved = Path(template).resolve(strict=True)
        except OSError as e:
            raise FileNotFoundError(f"HTML template '{template}' not found") from e
        if not resolved.is_file():
            raise FileNotFoundError(f"HTML template '{template}' not found")
        directory, name = resolved.parent, resolved.name
    env = ImmutableSandboxedEnvironment(loader=FileSystemLoader(str(directory)), autoescape=True,
                                        undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    return env, name


def _script_and_hash(raw: bytes) -> tuple[str, str]:
    """Inline script text and its CSP sha256 (browsers hash after newline normalisation)."""
    script = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return script, base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()


def _write_atomically(output_file: str, content: str) -> None:
    """Write through a temporary file then rename: an existing symlink is replaced, never followed."""
    directory = os.path.dirname(os.path.abspath(output_file))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".openvasreporting-", suffix=".html")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, output_file)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def export_to_html(vuln_info: list[Vulnerability], template: str | None = None,
                   output_file: str = "openvas_report.html", scan_info: list[ScanInfo] | None = None):
    """
    Export vulnerabilities info in a single self-contained HTML file.

    :param vuln_info: Vulnerability list info
    :param template: optional path to a custom Jinja2 template, rendered in a sandbox
    :param output_file: Filename of the HTML file
    :param scan_info: task / scan dates of each input report, shown in the summary header

    :raises: TypeError, ValueError, FileNotFoundError
    """
    if not isinstance(vuln_info, list) or not all(isinstance(v, Vulnerability) for v in vuln_info):
        raise TypeError(f"Expected list of Vulnerability, got '{type(vuln_info)}' instead")
    if not isinstance(output_file, str) or not output_file:
        raise ValueError("output_file must have a valid name.")
    if template is not None and not isinstance(template, str):
        raise TypeError(f"Expected str, got '{type(template)}' instead")

    ordered = sorted(vuln_info, key=lambda v: (-v.cvss, v.name))
    vulns = [_vuln_view(i, v) for i, v in enumerate(ordered, 1)]
    hosts = _host_views(vulns)

    env, name = _environment(template)
    # only the packaged script is ever embedded and allowed by the CSP
    script, script_hash = _script_and_hash((DEFAULT_TEMPLATE_DIR / SCRIPT_NAME).read_bytes())
    logo = (DEFAULT_TEMPLATE_DIR / LOGO_NAME).read_bytes()
    families = _family_stats(vulns)

    try:
        html = env.get_template(name).render(
            vulnerabilities=vulns,
            hosts=hosts,
            host_anchors={h.ip: h.anchor for h in hosts},
            top_hosts=hosts[:TOP_HOSTS],
            levels=_level_stats(vulns),
            families=families,
            family_max=max((count for _, count in families), default=0),
            colors=Config.colors(),
            scan_info=[ScanInfo(*(_clean(v) for v in (i.file, i.task, i.start, i.end))) for i in scan_info or []],
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
            logo_b64=base64.b64encode(logo).decode("ascii"),
            script=script,
            script_hash=script_hash,
        )
    except TemplateNotFound as e:
        raise FileNotFoundError(f"HTML template '{name}' not found") from e
    except TemplateError as e:  # syntax errors, undefined variables, sandbox violations
        raise ValueError(f"HTML template '{template or name}': {e}") from e
    _write_atomically(output_file, html)

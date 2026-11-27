import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
EDGE_REPORT = FIXTURES / "report_edge_cases.xml"


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run the real CLI entry point in a subprocess, like a user would.

    Runs from the tests directory by default so that a parent directory named like the
    package (e.g. a checkout called 'openvasreporting') cannot shadow the installed package.
    """
    return subprocess.run(
        [sys.executable, "-m", "openvasreporting", *args],
        check=False,
        capture_output=True,
        text=True,
        cwd=cwd or Path(__file__).parent,
        timeout=120,
    )


def result_xml(oid: str, name: str, host: str, port: str, severity: str, description: str = "",
               family: str = "General", refs: str = "", hostname: str = "h") -> str:
    """One <result> element of an OpenVAS report (values are inserted verbatim: escape them yourself)."""
    return (
        f'<result><name>{name}</name><host>{host}<hostname>{hostname}</hostname></host><port>{port}</port>'
        f'<nvt oid="{oid}"><name>{name}</name><family>{family}</family>'
        f'<tags>summary=s|solution=fix it|solution_type=VendorFix</tags><refs>{refs}</refs></nvt>'
        f'<threat>Medium</threat><severity>{severity}</severity><description>{description}</description></result>'
    )


def write_report(path: Path, *results: str, task: str = "t", start: str = "2026-01-01T00:00:00Z") -> str:
    """Write a minimal but valid OpenVAS XML report and return its path."""
    path.write_text(
        '<report id="x" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">'
        f'<report id="x"><task><name>{task}</name></task><scan_start>{start}</scan_start>'
        f'<results>{"".join(results)}</results></report></report>',
        encoding="utf-8",
    )
    return str(path)


@pytest.fixture
def edge_report() -> str:
    return str(EDGE_REPORT)

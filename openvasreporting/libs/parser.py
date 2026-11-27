# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as Et

from .config import Config
from .parsed_data import Host, ParseVulnerability, Port, ResultTree, Vulnerability



@dataclass(frozen=True)
class ScanInfo:
    """Task name and scan period of one input report (empty strings when absent)."""
    file: str
    task: str
    start: str
    end: str


def scan_info_of(file: str, root) -> ScanInfo:
    def text(path: str) -> str:
        found = root.find(path)
        return found.text.strip() if found is not None and found.text else ""

    return ScanInfo(file=Path(file).name,
                    task=text("./task/name") or text("./report/task/name"),
                    start=text("./report/scan_start"),
                    end=text("./report/scan_end"))


def iter_report_roots(config: Config) -> Iterator[tuple[str, object]]:
    """
    Parse the input files one at a time (only one tree in memory) and check each is an
    OpenVAS/GVM XML report.

    :return: iterator of (file name, root element)
    :raises: TypeError, ValueError (invalid or non-report file), OSError (unreadable file)
    """
    if not isinstance(config, Config):
        raise TypeError("Expected Config, got '{}' instead".format(type(config)))
    for file in config.input_files:
        if not isinstance(file, str):
            raise TypeError("Expected str, got '{}' instead".format(type(file)))
        try:
            # GVM exports never contain a DTD; forbidding it blocks entity and attribute-default bombs
            root = Et.parse(file, forbid_dtd=True).getroot()
        except (ParseError, LookupError) as e:  # LookupError: unknown encoding declaration
            raise ValueError("{}: not a valid XML file ({})".format(file, e)) from e
        except DefusedXmlException as e:
            raise ValueError("{}: refused unsafe XML construct ({})".format(file, e)) from e
        if root.tag != "report":
            raise ValueError("{}: not an OpenVAS XML report (root element is <{}>, expected <report>)".format(
                file, root.tag))
        yield file, root


def _results(config: Config, scan_info: list | None) -> Iterator[ParseVulnerability]:
    """Selected results of every input report; appends each report's ScanInfo to `scan_info` if given."""
    for file, root in iter_report_roots(config):
        if scan_info is not None:
            scan_info.append(scan_info_of(file, root))
        for vuln in root.findall(".//results/result"):
            parsed_vuln = ParseVulnerability.check_and_parse_result(vuln, config)
            if parsed_vuln is not None:
                yield parsed_vuln


def parsers():
        """
        Enum-like instance containing references to correct parser function
    
        > parsers()[key](param[s])
    
        :return: Pointer to parser function
        """
        return {
            'vulnerability': openvas_parser_by_vuln,
            'host': openvas_parser_by_host,
            'summary': openvas_parser_by_vuln
        }

def openvas_parser_by_vuln(config: Config, scan_info: list | None = None):
    """
    This function takes an OpenVAS XML report and returns Vulnerability info

    :param config: config options as by the command line or defaults
    :type config: Config

    :param scan_info: optional list receiving one ScanInfo per input report

    :return: list

    :raises: TypeError, InvalidFormat
    """
    
    vulnerabilities:dict[str, Vulnerability] = {}

    for parsed_vuln in _results(config, scan_info):
        # store hosts per vulnerability; results are kept per port as they are unique per port on each host
        host = Host(parsed_vuln.vuln_host, host_name=parsed_vuln.vuln_host_name)
        port = Port.string2port(parsed_vuln.vuln_port, parsed_vuln.vuln_result, parsed_vuln.vuln_cvss)
        if parsed_vuln.vuln_id not in vulnerabilities:
            vulnerabilities[parsed_vuln.vuln_id] = Vulnerability(
                parsed_vuln.vuln_id,
                name=parsed_vuln.vuln_name,
                version=parsed_vuln.vuln_version,
                threat=parsed_vuln.vuln_threat,
                tags=parsed_vuln.vuln_tags,
                cvss=parsed_vuln.vuln_cvss,
                cves=parsed_vuln.vuln_cves,
                references=parsed_vuln.vuln_references,
                reference_list=parsed_vuln.ref_list,
                family=parsed_vuln.vuln_family,
                level=parsed_vuln.vuln_level)
        vulnerabilities[parsed_vuln.vuln_id].add_vuln_host(host, port)

    return list(vulnerabilities.values())

def openvas_parser_by_host(config: Config, scan_info: list | None = None):
    """
    This function takes an OpenVAS XML report and returns Vulnerability info

    :param config: config options as by the command line or defaults
    :type config: Config

    :param scan_info: optional list receiving one ScanInfo per input report

    :return: list

    :raises: TypeError, InvalidFormat
    """
    
    resulttree = ResultTree()

    for parsed_vuln in _results(config, scan_info):
        resulttree.addresult(parsed_vuln)

    if len(resulttree) == 0:
        raise ValueError('No valid <results> found. Check exclusions and/or scope listings. I\'ve got nothing to do')
    
    return resulttree


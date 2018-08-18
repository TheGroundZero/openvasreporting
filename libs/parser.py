# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: TODO

import sys
import logging

from libs.config import Config
from libs.parsed_data import Host, Port, Vulnerability

logging.basicConfig(stream=sys.stderr, level=logging.ERROR)

__all__ = ["openvas_parser"]

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


def openvas_parser(input_files, min_lvl=Config.levels()["n"]):
    """
    This function takes an OpenVAS XML report and returns Vulnerability info

    :param input_files: path to XML files
    :type input_files: list(str)

    :param min_lvl: Minimal level (none, low, medium, high, critical) for displaying vulnerabilities
    :type min_lvl: str

    :return: list

    :raises: TypeError, InvalidFormat
    """
    if not isinstance(input_files, list):
        raise TypeError("Expected list, got '{}' instead".format(type(input_files)))
    else:
        for file in input_files:
            if not isinstance(file, str):
                raise TypeError("Expected basestring, got '{}' instead".format(type(file)))
            with open(file, "r", newline=None) as f:
                first_line = f.readline()
                if not first_line.startswith("<report") or \
                        not all(True for x in ("extension", "format_id", "content_type") if x in first_line):
                    raise IOError("Invalid report format")

    if not isinstance(min_lvl, str):
        raise TypeError("Expected basestring, got '{}' instead".format(type(min_lvl)))

    vulnerabilities = {}

    for f_file in input_files:
        root = ET.parse(f_file).getroot()

        logging.debug(root)  # DEBUG

        for vuln in root.findall(".//results/result"):

            logging.debug(vuln)  # DEBUG

            nvt_tmp = vuln.find(".//nvt")

            vuln_cvss = vuln.find(".//severity").text
            if vuln_cvss is None:
                vuln_cvss = 0.0
            vuln_cvss = float(vuln_cvss)

            logging.debug("* vuln_cvss: {}".format(vuln_cvss))  # DEBUG

            if vuln_cvss < 0.1:
                vuln_level = Config.levels()["n"]
                if min_lvl not in Config.levels()["n"]:
                    continue
            elif vuln_cvss < 4:
                vuln_level = Config.levels()["l"]
                if min_lvl not in (Config.levels()["n"], Config.levels()["l"]):
                    continue
            elif vuln_cvss < 7:
                vuln_level = Config.levels()["m"]
                if min_lvl not in (Config.levels()["n"], Config.levels()["l"], Config.levels()["m"]):
                    continue
            elif vuln_cvss < 9:
                vuln_level = Config.levels()["h"]
                if min_lvl not in (Config.levels()["n"], Config.levels()["l"], Config.levels()["m"],
                                   Config.levels()["h"]):
                    continue
            else:
                vuln_level = Config.levels()["c"]

            vuln_id = nvt_tmp.get("oid")
            if not vuln_id or vuln_id == "0":
                continue

            logging.debug("* vuln_id: {}".format(vuln_id))  # DEBUG

            vuln_threat = vuln.find(".//threat").text
            if vuln_threat is None:
                vuln_threat = Config.levels()["n"]
            else:
                vuln_threat = vuln_threat.lower()

            logging.debug("* vuln_threat: {}".format(vuln_threat))  # DEBUG

            vuln_name = nvt_tmp.find(".//name").text

            logging.debug("* vuln_name: {}".format(vuln_name))  # DEBUG

            vuln_family = nvt_tmp.find(".//family").text

            logging.debug("* vuln_family: {}".format(vuln_family))  # DEBUG

            vuln_cves = nvt_tmp.find(".//cve").text
            if vuln_cves:
                if vuln_cves.lower() == "nocve":
                    vuln_cves = []
                else:
                    vuln_cves = [vuln_cves.lower()]

            logging.debug("* vuln_cves: {}".format(vuln_cves))  # DEBUG

            vuln_references = nvt_tmp.find(".//xref").text
            if vuln_references:
                if vuln_references.lower() == "noxref":
                    vuln_references = []
                else:
                    tmp1 = vuln_references.strip().lower()
                    tmp1_init = tmp1.find("url:")
                    tmp2 = tmp1[tmp1_init + 4:].split(",")
                    vuln_references = [x.strip() for x in tmp2]

            logging.debug("* vuln_references: {}".format(vuln_references))  # DEBUG

            vuln_host = vuln.find(".//host").text
            vuln_port = vuln.find(".//port").text
            logging.debug("* vuln_host: {} port: {}".format(vuln_host, vuln_port))  # DEBUG

            vuln_description = vuln.find(".//description").text
            logging.debug("* vuln_description: {}".format(vuln_description))  # DEBUG

            host = Host(vuln_host)
            try:
                port = Port.string2port(vuln_port)
            except ValueError:
                port = None

            try:
                vuln_store = vulnerabilities[vuln_id]
            except KeyError:
                vuln_store = Vulnerability(vuln_id,
                                           name=vuln_name,
                                           threat=vuln_threat,
                                           description=vuln_description,
                                           cvss=vuln_cvss,
                                           cves=vuln_cves,
                                           references=vuln_references,
                                           family=vuln_family,
                                           level=vuln_level)

            vuln_store.add_host(host, port)
            vulnerabilities[vuln_id] = vuln_store

    return list(vulnerabilities.values())

# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting
import re
import sys
import logging

from .config import Config
from .parsed_data import Host, Port, Vulnerability

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG,
                     format="%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
#logging.basicConfig(stream=sys.stderr, level=logging.ERROR,
#                    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

__all__ = ["openvas_parser"]

try:
    from xml.etree import cElementTree as Et
except ImportError:
    from xml.etree import ElementTree as Et


def openvas_parser(input_files, min_level=Config.levels()["n"]):
    """
    This function takes an OpenVAS XML report and returns Vulnerability info

    :param input_files: path to XML files
    :type input_files: list(str)

    :param min_level: Minimal level (none, low, medium, high, critical) for displaying vulnerabilities
    :type min_level: str

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

    if not isinstance(min_level, str):
        raise TypeError("Expected basestring, got '{}' instead".format(type(min_level)))

    vulnerabilities = {}

    for f_file in input_files:
        root = Et.parse(f_file).getroot()

        logging.debug("================================================================================")
#        logging.debug("= {}".format(root.find("./task/name").text))  # DEBUG
        logging.debug("================================================================================")

        for vuln in root.findall(".//results/result"):

            nvt_tmp = vuln.find("./nvt")

            # --------------------
            #
            # VULN_NAME
            vuln_name = nvt_tmp.find("./name").text

            logging.debug("--------------------------------------------------------------------------------")
            logging.debug("- {}".format(vuln_name))  # DEBUG
            logging.debug("--------------------------------------------------------------------------------")

            # --------------------
            #
            # VULN_ID
            vuln_id = nvt_tmp.get("oid")
            if not vuln_id or vuln_id == "0":
                logging.debug("  ==> SKIP")  # DEBUG
                continue
            logging.debug("* vuln_id:\t{}".format(vuln_id))  # DEBUG

            # --------------------
            #
            # VULN_CVSS
            vuln_cvss = vuln.find("./severity").text
            if vuln_cvss is None:
                vuln_cvss = 0.0
            vuln_cvss = float(vuln_cvss)
            logging.debug("* vuln_cvss:\t{}".format(vuln_cvss))  # DEBUG

            # --------------------
            #
            # VULN_LEVEL
            vuln_level = "none"
            for level in Config.levels().values():
                if vuln_cvss >= Config.thresholds()[level]:
                    vuln_level = level
                    logging.debug("* vuln_level:\t{}".format(vuln_level))  # DEBUG
                    break

            logging.debug("* min_level:\t{}".format(min_level))  # DEBUG
            if vuln_level not in Config.min_levels()[min_level]:
                logging.debug("   => SKIP")  # DEBUG
                continue

            # --------------------
            #
            # VULN_HOST
            vuln_host = vuln.find("./host").text
            vuln_port = vuln.find("./port").text
            logging.debug("* vuln_host:\t{} port:\t{}".format(vuln_host, vuln_port))  # DEBUG

            # --------------------
            #
            # VULN_TAGS
            # Replace double newlines by a single newline
            vuln_tags_text = re.sub(r"(\r\n)+", "\r\n", nvt_tmp.find("./tags").text)
            vuln_tags_text = re.sub(r"\n+", "\n", vuln_tags_text)
            # Remove useless whitespace but not newlines
            vuln_tags_text = re.sub(r"[^\S\r\n]+", " ", vuln_tags_text)
            vuln_tags_temp = vuln_tags_text.split('|')
            vuln_tags = dict(tag.split('=', 1) for tag in vuln_tags_temp)
            logging.debug("* vuln_tags:\t{}".format(vuln_tags))  # DEBUG

            # --------------------
            #
            # VULN_THREAT
            vuln_threat = vuln.find("./threat").text
            if vuln_threat is None:
                vuln_threat = Config.levels()["n"]
            else:
                vuln_threat = vuln_threat.lower()

            logging.debug("* vuln_threat:\t{}".format(vuln_threat))  # DEBUG

            # --------------------
            #
            # VULN_FAMILY
            vuln_family = nvt_tmp.find("./family").text

            logging.debug("* vuln_family:\t{}".format(vuln_family))  # DEBUG

            # --------------------
            #
            # VULN_CVES
            vuln_cves = nvt_tmp.find("./cve").text
            if vuln_cves:
                if vuln_cves.lower() == "nocve":
                    vuln_cves = []
                else:
                    vuln_cves = [vuln_cves.lower()]

            logging.debug("* vuln_cves:\t{}".format(vuln_cves))  # DEBUG

            # --------------------
            #
            # VULN_REFERENCES
            vuln_references = nvt_tmp.find("./xref").text
            if vuln_references:
                if vuln_references.lower() == "noxref":
                    vuln_references = []
                else:
                    # tmp1 = vuln_references.strip().lower()
                    # tmp1_init = tmp1.find("url:")
                    #tmp2 = tmp1[tmp1_init + 4:].split(",")
                    vuln_references = vuln_references.lower().replace("url:", "\n")

            logging.debug("* vuln_references:\t{}".format(vuln_references))  # DEBUG

            # --------------------
            #
            # VULN_DESCRIPTION
            vuln_result = vuln.find("./description").text
            if vuln_result is None:
                vuln_result = []

            if type(vuln_result) == list:
                vuln_result = "\n".join(vuln_result)

            # Replace double newlines by a single newline
            vuln_result = vuln_result.replace("(\r\n)+", "\n")

            logging.debug("* vuln_result:\t{}".format(vuln_result))  # DEBUG

            # --------------------
            #
            # STORE VULN_HOSTS PER VULN
            host = Host(vuln_host)
            try:
	    # added results to port function as will ne unique per port on each host.
                port = Port.string2port(vuln_port, vuln_result)
            except ValueError:
                port = None

            try:
                vuln_store = vulnerabilities[vuln_id]
            except KeyError:
                vuln_store = Vulnerability(vuln_id,
                                           name=vuln_name,
                                           threat=vuln_threat,
                                           tags=vuln_tags,
                                           cvss=vuln_cvss,
                                           cves=vuln_cves,
                                           references=vuln_references,
                                           family=vuln_family,
                                           level=vuln_level)

            vuln_store.add_vuln_host(host, port)
            vulnerabilities[vuln_id] = vuln_store

    return list(vulnerabilities.values())

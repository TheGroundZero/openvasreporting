# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS2Report: A set of tools to manager OpenVAS XML report files.
# Project URL: https://github.com/cr0hn/openvas_to_report
#
# Copyright (c) 2015, cr0hn<-AT->cr0hn.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


__all__ = ["openvas_parser"]


try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from ..data.parsed_data import Port, Host, Vulnerability


# ----------------------------------------------------------------------
def openvas_parser(files_path, excluded_hosts=None, scope_hosts=None):
    """
    This function takes an OpenVAS XML with results and return Vulnerability info.

    :param files_path: path to xml file
    :type files_path: list(str)
    
    :param excluded_hosts: list with hosts to exclude
    :type excluded_hosts: list(str)
    
    :param scope_hosts: list with scope hosts
    :type scope_hosts: list(str)

    :raises: TypeError, InvalidFormat
    """
    if not isinstance(files_path, list):
        raise TypeError("Expected list, got '%s' instead" % type(files_path))
    else:
        for f in files_path:
            if not isinstance(f, str):
                raise TypeError("Expected basestring, got '%s' instead" % type(f))

    if scope_hosts is not None:
        if not isinstance(scope_hosts, list):
            raise TypeError("Expected list, got '%s' instead" % type(scope_hosts))
        else:
            for s in scope_hosts:
                if not isinstance(s, str):
                    raise TypeError("Expected basestring, got '%s' instead" % type(s))

    if excluded_hosts is not None:
        if not isinstance(excluded_hosts, list):
            raise TypeError("Expected list, got '%s' instead" % type(excluded_hosts))
        else:
            for e in excluded_hosts:
                if not isinstance(e, str):
                    raise TypeError("Expected basestring, got '%s' instead" % type(e))
    else:
        excluded_hosts = []

    # Check format
    for f_file in files_path:
        with open(f_file, "rU") as f:
            first_line = f.readline()

            if not first_line.startswith("<report ") or \
                    not all(True for x in ("extension", "format_id", "content_type") if x in first_line):
                raise IOError("Invalid report format")

    # Temporal vulnerability indexed list
    vulnerabilities = {}

    for f_file in files_path:
        # Parse xml file
        root = ET.parse(f_file).getroot()

        # Make vulnerabilities
        for vuln in root.findall(".//results/result"):
            # --------------------------------------------------------------------------
            # NVT info
            # --------------------------------------------------------------------------
            nvt_tmp = vuln.find(".//nvt")

            # Vuln Id
            vuln_id = nvt_tmp.get("oid")

            # 0 is an special case of OpenVAS when not info available
            if not vuln_id or vuln_id == "0":
                continue

            # threat type
            vuln_threat = vuln.find(".//threat")
            if vuln_threat is None:
                vuln_threat = "Log"
            else:
                vuln_threat = vuln_threat.text

            # Exclude log info
            if vuln_threat.lower() == "log":
                continue

            # Vuln ID
            vuln_id = vuln_id.split(".")[-1]

            # Vuln Level
            vuln_level = nvt_tmp.find(".//risk_factor").text
            if vuln_level:
                if vuln_level.lower() == "none":
                    continue
                elif "log" in vuln_level.lower():
                    continue
            else:  # ONLY vulns with relevant info: Low, Middle, high or Critical
                continue

            # Vuln name
            vuln_name = nvt_tmp.find(".//name").text
            # Vuln family
            vuln_family = nvt_tmp.find(".//family").text
            # Vuln CVSS
            vuln_cvss = nvt_tmp.find(".//cvss_base").text
            if vuln_cvss is None:
                vuln_cvss = 0.0
            vuln_cvss = float(vuln_cvss)

            # Vuln CVEs
            # Get and filter CVE
            vuln_cves = nvt_tmp.find(".//cve").text
            if vuln_cves:
                if vuln_cves.lower() == "nocve":
                    vuln_cves = []
                else:
                    vuln_cves = [vuln_cves.lower()]

            # Get and filter References
            vuln_references = nvt_tmp.find(".//xref").text
            if vuln_references:
                if vuln_references.lower() == "noxref":
                    vuln_references = []
                else:
                    tmp1 = vuln_references.strip().lower()
                    tmp1_init = tmp1.find("url:")
                    tmp2 = tmp1[tmp1_init + 4:].split(",")
                    vuln_references = [x.strip() for x in tmp2]

            # --------------------------------------------------------------------------
            # Target info
            # --------------------------------------------------------------------------
            vuln_host = vuln.find(".//host").text
            vuln_port = vuln.find(".//port").text

            # Apply filter to include hosts or not
            if vuln_host in excluded_hosts:
                continue

            if scope_hosts is not None:
                if vuln_host not in scope_hosts:
                    continue

            # --------------------------------------------------------------------------
            # Vulnerability description
            # --------------------------------------------------------------------------
            vuln_description = vuln.find(".//description").text

            # --------------------------------------------------------------------------
            # Store
            # --------------------------------------------------------------------------
            host = Host(vuln_host)
            try:
                port = Port.string2port(vuln_port)
            except ValueError:
                # Not valid or sense port, like: "general/tcp"
                port = None

            try:
                vuln_store = vulnerabilities[vuln_id]
            except KeyError:
                vuln_store = Vulnerability(vuln_id,
                                           name=vuln_name,
                                           threat=vuln_threat,
                                           cves=vuln_cves,
                                           cvss=vuln_cvss,
                                           description=vuln_description,
                                           references=vuln_references,
                                           level=vuln_level,
                                           family=vuln_family)

            # Append host
            vuln_store.add_host(host, port)

            # Append
            vulnerabilities[vuln_id] = vuln_store

    return list(vulnerabilities.values())
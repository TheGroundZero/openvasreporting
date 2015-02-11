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

from .libs.data.config import Config
from .libs.parsers.openvas_parser import openvas_parser


# ----------------------------------------------------------------------
def crop(config):
    """
    This function takes an OpenVAS XML with results and return Vulnerability info.

    :param config: Config instance
    :type config: Config

    :raises: TypeError, InvalidFormat
    """
    import copy

    if not isinstance(config, Config):
        raise TypeError("Expected Config, got '%s' instead" % type(config))

    try:
        from xml.etree import cElementTree as ET
    except ImportError:
        from xml.etree import ElementTree as ET

    output_file = config.output_file
    file_path = config.input_files
    scope_hosts = config.scope
    excluded_hosts = config.excluded

    # Check format
    with open(file_path, "rU") as f:
        first_line = f.readline()

        if not first_line.startswith("<report ") or \
                not all(True for x in ("extension", "format_id", "content_type") if x in first_line):
            raise IOError("Invalid report format")

    # Read input file
    root = ET.parse(file_path).getroot()
    report = root.getchildren()[0]

    # --------------------------------------------------------------------------
    # Create clone
    # --------------------------------------------------------------------------
    root_clone = ET.Element(root.tag)
    root_clone.attrib=root.attrib

    report_clone = ET.SubElement(root_clone, "report")
    report_clone.attrib = report.attrib

    # Copy all elements
    for child in report.getchildren():

        # Add only these tags that not contain target information
        if child.tag not in ("host_start", "host_end", "host", "ports", "results"):
            tag = copy.deepcopy(child)

            # Add to clone
            report_clone.append(tag)

    # --------------------------------------------------------------------------
    # Add results tag
    # --------------------------------------------------------------------------
    results_tag = ET.Element("results")
    results_tag.attrib = root.find(".//results").attrib
    for vuln in root.findall(".//results/result"):

        # --------------------------------------------------------------------------
        # Target info
        # --------------------------------------------------------------------------
        vuln_host = vuln.find(".//host").text

        # Apply filter to include hosts or not
        if vuln_host in excluded_hosts:
            continue

        if scope_hosts is not None:
            if vuln_host not in scope_hosts:
                continue

        # Add to clone
        results_tag.append(vuln)

    # Add to clone
    report_clone.append(results_tag)

    # --------------------------------------------------------------------------
    # Add ports tag
    # --------------------------------------------------------------------------
    ports_tag = ET.Element("ports")
    ports_tag.attrib = root.find(".//ports").attrib
    for port in root.findall(".//ports/port"):

        # --------------------------------------------------------------------------
        # Target info
        # --------------------------------------------------------------------------
        vuln_host = port.find(".//host").text

        # Apply filter to include hosts or not
        if vuln_host in excluded_hosts:
            continue

        if scope_hosts is not None:
            if vuln_host not in scope_hosts:
                continue

        # Add to clone
        ports_tag.append(port)

    # Add to clone
    report_clone.append(ports_tag)

    # --------------------------------------------------------------------------
    # Add host tag
    # --------------------------------------------------------------------------
    for host in root.findall(".//report/host"):

        # --------------------------------------------------------------------------
        # Target info
        # --------------------------------------------------------------------------
        vuln_host = host.find(".//ip").text

        # Apply filter to include hosts or not
        if vuln_host in excluded_hosts:
            continue

        if scope_hosts is not None:
            if vuln_host not in scope_hosts:
                continue

        #host_tag = ET.Element("host", attrib=host.attrib, text=host.text)

        # Add to clone
        report_clone.append(host)

    # --------------------------------------------------------------------------
    # Add host_start tag
    # --------------------------------------------------------------------------
    for host_start in root.findall(".//report/host_start"):

        # --------------------------------------------------------------------------
        # Target info
        # --------------------------------------------------------------------------
        vuln_host = host_start.find(".//host").text

        # Apply filter to include hosts or not
        if vuln_host in excluded_hosts:
            continue

        if scope_hosts is not None:
            if vuln_host not in scope_hosts:
                continue

        # host_tag = ET.Element("host", attrib=host_start.attrib)

        # Add to clone
        report_clone.append(host_start)

    # --------------------------------------------------------------------------
    # Add host_end tag
    # --------------------------------------------------------------------------
    for host_end in root.findall(".//report/host_end"):

        # --------------------------------------------------------------------------
        # Target info
        # --------------------------------------------------------------------------
        vuln_host = host_end.find(".//host").text

        # Apply filter to include hosts or not
        if vuln_host in excluded_hosts:
            continue

        if scope_hosts is not None:
            if vuln_host not in scope_hosts:
                continue

        # host_tag = ET.Element("host", attrib=host_start.attrib)

        # Add to clone
        report_clone.append(host_end)

    # Save to file
    tree = ET.ElementTree(root_clone)
    # Un IO Memory and delete first line.
    tree.write(output_file, encoding="UTF-8", xml_declaration=False)


# ----------------------------------------------------------------------
def convert(config):
    """
    Convert a file to selected format.

    :param config: Config instance 
    :type config: Config
    
    :raises: TypeError, ValueError, IOError
    """
    if not isinstance(config, Config):
        raise TypeError("Expected Config, got '%s' instead" % type(config))

    # Check restrictions
    if config.scope is not None and config.excluded is not None:
        raise ValueError("Scope and excluded can't be set simultaneously")

    if config.excluded:
        excluded_hosts = [x.strip().replace("\n", "").replace("\t", "").replace("\r", "") for x in open(config.excluded, "rU").readlines()]
    else:
        excluded_hosts = None

    if config.scope:
        scope_hosts = [x.strip().replace("\n", "").replace("\t", "").replace("\r", "") for x in open(config.scope, "rU").readlines()]
    else:
        scope_hosts = None

    # --------------------------------------------------------------------------
    # Load OpenVas info
    # --------------------------------------------------------------------------
    openvas_info = openvas_parser(config.input_files, excluded_hosts=excluded_hosts, scope_hosts=scope_hosts)

    # Output config
    output_file = config.output_file
    lang = config.lang

    # --------------------------------------------------------------------------
    # Generate Word file
    # --------------------------------------------------------------------------
    if output_file.endswith("docx"):
        from .libs.exporters.word import export_to_word

        template = config.template
        export_to_word(openvas_info, output_file, template)

    elif output_file.endswith("xlsx"):
        from .libs.exporters.excel import export_to_excel

        export_to_excel(openvas_info, output_file, lang)

    else:
        raise ValueError("Extension not found!")
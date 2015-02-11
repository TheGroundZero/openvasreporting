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

__all__ = ["export_to_excel"]

from collections import Counter

import xlsxwriter

from ..data.parsed_data import Vulnerability
from ..translations import get_translation_path, loader


# ----------------------------------------------------------------------
def export_to_excel(vuln_info, output_file_name, lang="en", template="generic"):
    """
    Export Vulnerability info to excel file.

    :param vuln_info: Vulnerability list info
    :type vuln_info: list(Vulnerability)

    :param output_file_name: filename to save word file,
    :type output_file_name: str

    :param lang: output lang
    :type lang: str

    :param template: Excel template
    :type template: str

    :raises: TypeError
    """
    if not isinstance(vuln_info, list):
        raise TypeError("Expected list, got '%s' instead" % type(vuln_info))
    else:
        for x in vuln_info:
            if not isinstance(x, Vulnerability):
                raise TypeError("Expected Vulnerability, got '%s' instead" % type(x))
    if not isinstance(output_file_name, str):
        raise TypeError("Expected basestring, got '%s' instead" % type(output_file_name))
    else:
        if not output_file_name:
            raise ValueError("output_file_name must has a valid name.")

    if not output_file_name.endswith("xlsx"):
        raise ValueError("Invalid filename. Filename must ends in .xlsx.")

    if template == "generic":
        _export_generic_format(output_file_name, vuln_info, lang)
    else:
        raise ValueError("Unknown format")


# ----------------------------------------------------------------------
def _export_generic_format(output_file_name, vuln_info, lang):
    """
    Export Vulnerability as generic format

    :param vuln_info: Vulnerability list info
    :type vuln_info: list(Vulnerability)

    :param output_file_name: filename to save word file,
    :type output_file_name: str

    :param lang: output lang
    :type lang: str

    :raises: TypeError
    """

    workbook = xlsxwriter.Workbook(output_file_name)

    # Get translation object
    trans = loader(get_translation_path("excel", lang))

    # --------------------------------------------------------------------------
    # File formats
    # --------------------------------------------------------------------------
    format_align_center = workbook.add_format({'align': 'center'})
    format_align_border = workbook.add_format({'border': 1, 'align': 'center'})
    format_sheet_title_content = workbook.add_format(
        {
            'align': 'center',
            'bg_color': "#b7cce2",
            'border': 1,
            'bold': 1
        }
    )
    format_table_titles = workbook.add_format(
        {
            'align': 'center',
            'bold': True,
            'bg_color': "#F2F2F2",
            'border': 1
        }
    )
    format_description = workbook.add_format(
        {
            'align': 'center',
            'bold': True,
            'bg_color': "#F2F2F2",
            'border': 1,
            'valign': 'top'
        }
    )

    # --------------------------------------------------------------------------
    # Summary sheet
    # --------------------------------------------------------------------------
    vuln_levels = Counter()
    vuln_host_by_level = Counter()
    vuln_by_family = Counter()
    for i, vuln in enumerate(vuln_info, 1):
        vuln_levels[vuln.level.lower()] += 1
        vuln_host_by_level[vuln.level.lower()] += len(vuln.hosts)
        vuln_by_family[vuln.family] += 1

    sheet_name = trans["summary"]
    ws = workbook.add_worksheet(sheet_name)

    # Config columns sizes
    ws.set_column("B:B", 25, format_align_center)
    ws.set_column("C:C", 24, format_align_center)
    ws.set_column("D:D", 20, format_align_center)

    # Add titles for vulnerability summary
    # --------------------------------------
    ws.merge_range("B2:D2", trans["vuln summary"], format_sheet_title_content)
    ws.write("B3", trans["level"], format_table_titles)
    ws.write("B4", trans["critical"], format_table_titles)
    ws.write("B5", trans["high"], format_table_titles)
    ws.write("B6", trans["medium"], format_table_titles)
    ws.write("B7", trans["low"], format_table_titles)
    ws.write("B9", "Total", format_table_titles)
    ws.write("C3", trans["vulns number"], format_table_titles)
    ws.write("D3", trans["affected hosts"], format_table_titles)

    # Write vulnerability numbers
    ws.write("C4", vuln_levels["critical"], format_align_border)
    ws.write("C5", vuln_levels["high"], format_align_border)
    ws.write("C6", vuln_levels["medium"], format_align_border)
    ws.write("C7", vuln_levels["low"], format_align_border)
    ws.write("C9", sum(vuln_levels.values()), format_table_titles)

    # Write affected hosts
    ws.write("D4", vuln_host_by_level["critical"], format_align_border)
    ws.write("D5", vuln_host_by_level["high"], format_align_border)
    ws.write("D6", vuln_host_by_level["medium"], format_align_border)
    ws.write("D7", vuln_host_by_level["low"], format_align_border)
    ws.write("D9", sum(vuln_host_by_level.values()), format_table_titles)

    # Add charts
    chart_vulns_summary = workbook.add_chart({'type': 'pie'})
    chart_vulns_summary.add_series({
        'name': 'vulnerability summary by affected hosts',
        'categories': '=%s!B4:B7' % sheet_name,
        'values':     '=%s!D4:D7' % sheet_name,
        'points': [
            {'fill': {'color': '#900077'}},
            {'fill': {'color': '#cc1100'}},
            {'fill': {'color': '#ccab2e'}},
            {'fill': {'color': '#418e35'}},
        ],
    })
    chart_vulns_summary.set_title({'name': trans["chart_vulns_summary"]})
    ws.insert_chart("F2", chart_vulns_summary)

    # Add titles for vulnerability by family
    # --------------------------------------
    ws.merge_range("B19:C19", trans["vuln by family"], format_sheet_title_content)
    ws.write("B20", trans["family"], format_table_titles)
    ws.write("C20", trans["vulns number"], format_table_titles)

    # Write info
    last = 1
    for i, (family, number) in enumerate(iter(vuln_by_family.items()), 21):
        ws.write("B%s" % i, family, workbook.add_format({'border': 1, 'align': 'center', 'text_wrap': 1}))
        ws.write("C%s" % i, number, format_align_border)
        last = i

    ws.write("B%s" % str(last + 2), "Total", format_table_titles)
    ws.write("C%s" % str(last + 2), sum(vuln_by_family.values()), format_table_titles)

    # Add charts
    chart_vulns_by_family = workbook.add_chart({'type': 'pie'})
    chart_vulns_by_family.add_series({
        'name': 'vulnerability summary by family',
        'categories': '=%s!B21:B%s' % (sheet_name, last),
        'values':     '=%s!C21:C%s' % (sheet_name, last),
    })
    chart_vulns_by_family.set_title({'name': trans["chart_vulns_by_family"]})
    ws.insert_chart("F19", chart_vulns_by_family)

    # --------------------------------------------------------------------------
    # Details sheet
    # --------------------------------------------------------------------------
    # Add a sheet by each vuln
    for i, vuln in enumerate(vuln_info, 1):

        # Create worksheet and set title
        if len(vuln.name) <= 30:
            name = vuln.name
        else:
            name = "%s %s" % (trans["vulnerability"], vuln.id)
        w1 = workbook.add_worksheet(name)

        # --------------------------------------------------------------------------
        # Columns formats
        # --------------------------------------------------------------------------
        w1.set_column("B:B", 14, format_align_center)
        w1.set_column("C:C", 14, format_align_center)
        w1.set_column("D:D", 30, format_align_center)
        w1.set_column("E:E", 12, format_align_center)
        w1.set_column("F:F", 13, format_align_center)
        w1.set_column("G:G", 20, format_align_center)

        # --------------------------------------------------------------------------
        # Vulnerability info
        # --------------------------------------------------------------------------
        # Vuln title
        w1.write('B2', trans["title"], format_table_titles)
        w1.merge_range("C2:G2", vuln.name, format_sheet_title_content)

        # Vuln description
        w1.write('B3', trans["description"], format_description)
        w1.merge_range("C3:G3", vuln.description, workbook.add_format({'valign': 'top', 'text_wrap': 1, 'border': 1}))

        # Vuln CVE
        w1.write('B4', "CVEs", format_table_titles)
        cves = ", ".join(vuln.cves)
        cves = cves.upper() if cves != "" else trans["No CVE"]
        w1.merge_range("C4:G4", cves, workbook.add_format({'valign': 'top', 'border': 1, 'align': 'left'}))

        # Vuln CVSS
        w1.write('B5', "CVSS", format_table_titles)
        cvss = vuln.cvss if vuln.cvss != -1.0 else trans["No CVSS"]
        w1.merge_range("C5:G5", cvss, workbook.add_format({'valign': 'top', 'border': 1, 'align': 'left'}))

        # Vuln level
        w1.write('B6', trans["level"], format_table_titles)
        w1.merge_range("C6:G6", trans[vuln.level.lower()], workbook.add_format({'valign': 'top', 'border': 1, 'align': 'left'}))

        # Vuln family
        w1.write('B7', trans["family"], format_table_titles)
        w1.merge_range("C7:G7", vuln.family, workbook.add_format({'valign': 'top', 'border': 1, 'align': 'left'}))

        # Vuln description
        if len(vuln.description) < 200:
            description_height = 20
        else:
            description_height = 80
        w1.set_row(2, description_height, None)

        # --------------------------------------------------------------------------
        # Titles for hosts list
        # --------------------------------------------------------------------------
        w1.write('C9', trans["ip"], format_table_titles)
        w1.write('D9', trans["Host name"], format_table_titles)
        w1.write('E9', trans["Port number"], format_table_titles)
        w1.write('F9', trans["Port protocol"], format_table_titles)
        w1.write('G9', trans["Port description"], format_table_titles)

        # Add Hosts/Port
        for j, (host, port) in enumerate(vuln.hosts, 10):

            # IP
            w1.write("C%s" % j, host.ip)
            w1.write("D%s" % j, host.host_name if host.host_name else "-")

            # Port info
            if port:
                w1.write("E%s" % j, port.number)
                w1.write("F%s" % j, port.protocol)
                w1.write("G%s" % j, port.description)
            else:
                w1.write("E%s" % j, "No port info")


    workbook.close()
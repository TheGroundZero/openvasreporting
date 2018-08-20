# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvas_to_report

import re
import xlsxwriter

from collections import Counter

from .config import Config
from .parsed_data import Vulnerability

__all__ = ["export_to_excel"]


def export_to_excel(vuln_info, output_file):
    """
    Export vulnerabilities info in an Excel file.

    :param vuln_info: Vulnerability list info
    :type vuln_info: list(Vulnerability)

    :param output_file: Filename of the Excel file
    :type output_file: str

    :raises: TypeError
    """
    if not isinstance(vuln_info, list):
        raise TypeError("Expected list, got '{}' instead".format(type(vuln_info)))
    else:
        for x in vuln_info:
            if not isinstance(x, Vulnerability):
                raise TypeError("Expected Vulnerability, got '{}' instead".format(type(x)))
    if not isinstance(output_file, str):
        raise TypeError("Expected basestring, got '{}' instead".format(type(output_file)))
    else:
        if not output_file:
            raise ValueError("output_file_name must has a valid name.")

    if not output_file.endswith("xlsx"):
        raise ValueError("Invalid filename. Filename must ends in .xlsx.")

    workbook = xlsxwriter.Workbook(output_file)

    workbook.set_properties({
        'title': output_file,
        'subject': 'OpenVAS report',
        'author': 'TheGroundZero',
        'category': 'report',
        'keywords': 'OpenVAS, report',
        'comments': 'TheGroundZero (https://github.com/TheGroundZero)'})

    format_sheet_title_content = workbook.add_format({'align': 'center', 'valign': 'middle',
                                                      'font_color': Config.colors()['blue'], 'bold': True, 'border': 1})
    format_table_titles = workbook.add_format({'align': 'center', 'valign': 'middle',
                                               'bold': True, 'font_color': 'white', 'border': 1,
                                               'bg_color': Config.colors()['blue']})
    format_table_cells = workbook.add_format({'align': 'left', 'valign': 'top', 'border': 1})
    format_align_center = workbook.add_format({'align': 'center', 'valign': 'top'})
    format_align_border = workbook.add_format({'align': 'center', 'valign': 'top', 'border': 1})
    format_description = workbook.add_format({'valign': 'top', 'text_wrap': 1, 'border': 1})

    vuln_info.sort(key=lambda key: key.cvss, reverse=True)
    vuln_levels = Counter()
    vuln_host_by_level = Counter()
    vuln_by_family = Counter()

    for i, vuln in enumerate(vuln_info, 1):
        vuln_levels[vuln.level.lower()] += 1
        vuln_host_by_level[vuln.level.lower()] += len(vuln.hosts)
        vuln_by_family[vuln.family] += 1

    # ====================
    # SUMMARY SHEET
    # ====================
    sheet_name = "Summary"
    ws = workbook.add_worksheet(sheet_name)
    ws.set_tab_color(Config.colors()['blue'])

    ws.set_column("B:B", 25, format_align_center)
    ws.set_column("C:C", 24, format_align_center)
    ws.set_column("D:D", 20, format_align_center)

    # --------------------
    # VULN SUMMARY
    # --------------------
    ws.merge_range("B2:D2", "VULNERABILITY SUMMARY", format_sheet_title_content)
    ws.write("B3", "Threat", format_table_titles)
    ws.write("C3", "Vulns number", format_table_titles)
    ws.write("D3", "Affected hosts", format_table_titles)

    ws.write("B4", "Critical", format_sheet_title_content)
    ws.write("B5", "High", format_sheet_title_content)
    ws.write("B6", "Medium", format_sheet_title_content)
    ws.write("B7", "Low", format_sheet_title_content)
    ws.write("B8", "None", format_sheet_title_content)

    ws.write("C4", vuln_levels["critical"], format_align_border)
    ws.write("D4", vuln_host_by_level["critical"], format_align_border)

    ws.write("C5", vuln_levels["high"], format_align_border)
    ws.write("D5", vuln_host_by_level["high"], format_align_border)

    ws.write("C6", vuln_levels["medium"], format_align_border)
    ws.write("D6", vuln_host_by_level["medium"], format_align_border)

    ws.write("C7", vuln_levels["low"], format_align_border)
    ws.write("D7", vuln_host_by_level["low"], format_align_border)

    ws.write("C8", vuln_levels["none"], format_align_border)
    ws.write("D8", vuln_host_by_level["none"], format_align_border)

    ws.write("B9", "Total", format_table_titles)
    ws.write_formula("C9", "=SUM($C$4:$C$8)", format_table_titles)
    ws.write_formula("D9", "=SUM($D$4:$D$8)", format_table_titles)

    # --------------------
    # CHART
    # --------------------
    chart_vulns_summary = workbook.add_chart({'type': 'pie'})
    chart_vulns_summary.add_series({
        'name': 'vulnerability summary by affected hosts',
        'categories': '={}!B4:B8'.format(sheet_name),
        'values': '={}!D4:D8'.format(sheet_name),
        'data_labels': {'value': True, 'position': 'outside_end', 'leader_lines': True},
        'points': [
            {'fill': {'color': Config.colors()['critical']}},
            {'fill': {'color': Config.colors()['high']}},
            {'fill': {'color': Config.colors()['medium']}},
            {'fill': {'color': Config.colors()['low']}},
            {'fill': {'color': Config.colors()['none']}},
        ],
    })
    chart_vulns_summary.set_title({'name': 'Vulnerability summary', 'overlay': False})
    ws.insert_chart("F2", chart_vulns_summary)

    # --------------------
    # VULN BY FAMILY
    # --------------------
    ws.merge_range("B19:C19", "VULNERABILITIES BY FAMILY", format_sheet_title_content)
    ws.write("B20", "family", format_table_titles)
    ws.write("C20", "vulns number", format_table_titles)

    last = 21
    for i, (family, number) in enumerate(iter(vuln_by_family.items()), last):
        ws.write("B{}".format(i), family, workbook.add_format({'border': 1, 'align': 'center', 'text_wrap': 1}))
        ws.write("C{}".format(i), number, format_align_border)
        last = i

    ws.write("B{}".format(str(last + 1)), "Total", format_table_titles)
    ws.write_formula("C{}".format(str(last + 1)), "=SUM($C$21:$C${})".format(last), format_table_titles)

    # --------------------
    # CHART
    # --------------------
    chart_vulns_by_family = workbook.add_chart({'type': 'pie'})
    chart_vulns_by_family.add_series({
        'name': 'vulnerability summary by family',
        'categories': '={}!B21:B{}'.format(sheet_name, last),
        'values': '={}!C21:C{}'.format(sheet_name, last),
        'data_labels': {'value': True, 'position': 'best_fit', 'leader_lines': True},
    })
    chart_vulns_by_family.set_title({'name': 'Vulnerability by family', 'overlay': False})
    ws.insert_chart("F19", chart_vulns_by_family)

    # --------------------
    # VULN SHEETS
    # --------------------
    num = 1
    for i, vuln in enumerate(vuln_info, 1):
        name = re.sub(r"[\[\]\\\'\"&@#():*?/]", "", vuln.name)
        if len(name) > 27:
            name = "{}..{}".format(name[0:15], name[-10:])
        name = "{}_{}".format(str(num).zfill(3), name)
        num += 1
        w1 = workbook.add_worksheet(name)
        w1.set_tab_color(Config.colors()[vuln.level.lower()])

        w1.set_column("B:B", 14, format_align_center)
        w1.set_column("C:C", 14, format_align_center)
        w1.set_column("D:D", 30, format_align_center)
        w1.set_column("E:E", 12, format_align_center)
        w1.set_column("F:F", 13, format_align_center)
        w1.set_column("G:G", 20, format_align_center)

        w1.write('B2', "Title", format_table_titles)
        w1.merge_range("C2:G2", vuln.name, format_sheet_title_content)

        w1.write('B3', "Description", format_table_titles)
        w1.merge_range("C3:G3", vuln.description, format_description)

        w1.write('B4', "CVEs", format_table_titles)
        cves = ", ".join(vuln.cves)
        cves = cves.upper() if cves != "" else "No CVE"
        w1.merge_range("C4:G4", cves, format_table_cells)

        w1.write('B5', "CVSS", format_table_titles)
        cvss = vuln.cvss if vuln.cvss != -1.0 else "No CVSS"
        w1.merge_range("C5:G5", cvss, format_table_cells)

        w1.write('B6', "level", format_table_titles)
        w1.merge_range("C6:G6", vuln.level.lower(), format_table_cells)

        w1.write('B7', "family", format_table_titles)
        w1.merge_range("C7:G7", vuln.family, format_table_cells)

        if len(vuln.description) < 200:
            description_height = 20
        else:
            description_height = 80
        w1.set_row(2, description_height, None)

        w1.write('C9', "IP", format_table_titles)
        w1.write('D9', "Host name", format_table_titles)
        w1.write('E9', "Port number", format_table_titles)
        w1.write('F9', "Port protocol", format_table_titles)
        w1.write('G9', "Port description", format_table_titles)

        for j, (host, port) in enumerate(vuln.hosts, 10):

            w1.write("C{}".format(j), host.ip)
            w1.write("D{}".format(j), host.host_name if host.host_name else "-")

            if port:
                w1.write("E{}".format(j), port.number)
                w1.write("F{}".format(j), port.protocol)
                w1.write("G{}".format(j), port.description)
            else:
                w1.write("E{}".format(j), "No port info")

    workbook.close()

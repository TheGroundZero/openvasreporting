# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvas_to_report

import re

from collections import Counter

from .config import Config
from .parsed_data import Vulnerability


def exporters():
    return {
        'xlsx': export_to_excel,
        'docx': export_to_word
    }

def export_to_excel(vuln_info, output_file="openvas_report"):
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
            raise ValueError("output_file must have a valid name.")

    if output_file.split(".")[-1] != "xlsx":
        output_file = "{}.xlsx".format(output_file)

    import xlsxwriter

    workbook = xlsxwriter.Workbook(output_file)

    workbook.set_properties({
        'title': output_file,
        'subject': 'OpenVAS report',
        'author': 'TheGroundZero',
        'category': 'report',
        'keywords': 'OpenVAS, report',
        'comments': 'TheGroundZero (https://github.com/TheGroundZero)'})

    format_sheet_title_content = workbook.add_format({'align': 'center', 'valign': 'vcenter',
                                                      'font_color': Config.colors()['blue'], 'bold': True, 'border': 1})
    format_table_titles = workbook.add_format({'align': 'center', 'valign': 'vcenter',
                                               'bold': True, 'font_color': 'white', 'border': 1,
                                               'bg_color': Config.colors()['blue']})
    format_table_cells = workbook.add_format({'align': 'left', 'valign': 'top', 'border': 1})
    format_align_center = workbook.add_format({'align': 'center', 'valign': 'top'})
    format_align_border = workbook.add_format({'align': 'center', 'valign': 'top', 'text_wrap': 1, 'border': 1})
    format_description = workbook.add_format({'valign': 'top', 'text_wrap': 1, 'border': 1})
    format_toc = {
        'critical': workbook.add_format({'font_color': Config.colors()['critical'],
                                         'align': 'left', 'valign': 'top', 'border': 1}),
        'high': workbook.add_format({'font_color': Config.colors()['high'],
                                     'align': 'left', 'valign': 'top', 'border': 1}),
        'medium': workbook.add_format({'font_color': Config.colors()['medium'],
                                       'align': 'left', 'valign': 'top', 'border': 1}),
        'low': workbook.add_format({'font_color': Config.colors()['low'],
                                    'align': 'left', 'valign': 'top', 'border': 1}),
        'none': workbook.add_format({'font_color': Config.colors()['none'],
                                     'align': 'left', 'valign': 'top', 'border': 1})
    }

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
    ws_sum = workbook.add_worksheet(sheet_name)
    ws_sum.set_tab_color(Config.colors()['blue'])

    ws_sum.set_column("B:B", 25, format_align_center)
    ws_sum.set_column("C:C", 24, format_align_center)
    ws_sum.set_column("D:D", 20, format_align_center)

    # --------------------
    # VULN SUMMARY
    # --------------------
    ws_sum.merge_range("B2:D2", "VULNERABILITY SUMMARY", format_sheet_title_content)
    ws_sum.write("B3", "Threat", format_table_titles)
    ws_sum.write("C3", "Vulns number", format_table_titles)
    ws_sum.write("D3", "Affected hosts", format_table_titles)

    ws_sum.write("B4", "Critical", format_sheet_title_content)
    ws_sum.write("B5", "High", format_sheet_title_content)
    ws_sum.write("B6", "Medium", format_sheet_title_content)
    ws_sum.write("B7", "Low", format_sheet_title_content)
    ws_sum.write("B8", "None", format_sheet_title_content)

    ws_sum.write("C4", vuln_levels["critical"], format_align_border)
    ws_sum.write("D4", vuln_host_by_level["critical"], format_align_border)

    ws_sum.write("C5", vuln_levels["high"], format_align_border)
    ws_sum.write("D5", vuln_host_by_level["high"], format_align_border)

    ws_sum.write("C6", vuln_levels["medium"], format_align_border)
    ws_sum.write("D6", vuln_host_by_level["medium"], format_align_border)

    ws_sum.write("C7", vuln_levels["low"], format_align_border)
    ws_sum.write("D7", vuln_host_by_level["low"], format_align_border)

    ws_sum.write("C8", vuln_levels["none"], format_align_border)
    ws_sum.write("D8", vuln_host_by_level["none"], format_align_border)

    ws_sum.write("B9", "Total", format_table_titles)
    ws_sum.write_formula("C9", "=SUM($C$4:$C$8)", format_table_titles)
    ws_sum.write_formula("D9", "=SUM($D$4:$D$8)", format_table_titles)

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
    ws_sum.insert_chart("F2", chart_vulns_summary)

    # --------------------
    # VULN BY FAMILY
    # --------------------
    ws_sum.merge_range("B19:C19", "VULNERABILITIES BY FAMILY", format_sheet_title_content)
    ws_sum.write("B20", "family", format_table_titles)
    ws_sum.write("C20", "vulns number", format_table_titles)

    last = 21
    for i, (family, number) in enumerate(iter(vuln_by_family.items()), last):
        ws_sum.write("B{}".format(i), family, format_align_border)
        ws_sum.write("C{}".format(i), number, format_align_border)
        last = i

    ws_sum.write("B{}".format(str(last + 1)), "Total", format_table_titles)
    ws_sum.write_formula("C{}".format(str(last + 1)), "=SUM($C$21:$C${})".format(last), format_table_titles)

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
    ws_sum.insert_chart("F19", chart_vulns_by_family)

    # ====================
    # TABLE OF CONTENTS
    # ====================

    sheet_name = "TOC"
    ws_toc = workbook.add_worksheet(sheet_name)
    ws_toc.set_tab_color(Config.colors()['blue'])

    ws_toc.set_column("A:A", 5)
    ws_toc.set_column("B:B", 8)
    ws_toc.set_column("C:C", 4)
    ws_toc.set_column("D:D", 150)
    ws_toc.set_column("E:E", 5)

    ws_toc.merge_range("B2:D2", "TABLE OF CONTENTS", format_sheet_title_content)
    ws_toc.write("B3", "Level", format_table_titles)
    ws_toc.write("C3", "No.", format_table_titles)
    ws_toc.write("D3", "Vuln Title", format_table_titles)

    # ====================
    # VULN SHEETS
    # ====================
    for i, vuln in enumerate(vuln_info, 1):
        name = re.sub(r"[\[\]\\\'\"&@#():*?/]", "", vuln.name)
        if len(name) > 27:
            name = "{}..{}".format(name[0:15], name[-10:])
        name = "{:03X}_{}".format(i, name)
        ws_vuln = workbook.add_worksheet(name)
        ws_vuln.set_tab_color(Config.colors()[vuln.level.lower()])

        # Add to Table of Contents
        ws_toc.write("B{}".format(i + 3), vuln.level.capitalize(), format_toc[vuln.level.lower()])
        ws_toc.write("C{}".format(i + 3), "{:03X}".format(i), format_table_cells)
        ws_toc.write_url("D{}".format(i + 3), "internal:'{}'!A1".format(name), format_table_cells, string=vuln.name)
        ws_vuln.write_url("A1", "internal:'{}'!A{}".format(ws_toc.get_name(), i + 3), format_align_center,
                          string="<< TOC")
        # / Add to Table of Contents

        ws_vuln.set_column("B:B", 14, format_align_center)
        ws_vuln.set_column("C:C", 14, format_align_center)
        ws_vuln.set_column("D:D", 30, format_align_center)
        ws_vuln.set_column("E:E", 12, format_align_center)
        ws_vuln.set_column("F:F", 13, format_align_center)
        ws_vuln.set_column("G:G", 20, format_align_center)

        ws_vuln.write('B2', "Title", format_table_titles)
        ws_vuln.merge_range("C2:G2", vuln.name, format_sheet_title_content)

        ws_vuln.write('B3', "Description", format_table_titles)
        ws_vuln.merge_range("C3:G3", vuln.description, format_description)

        ws_vuln.write('B4', "CVEs", format_table_titles)
        cves = ", ".join(vuln.cves)
        cves = cves.upper() if cves != "" else "No CVE"
        ws_vuln.merge_range("C4:G4", cves, format_table_cells)

        ws_vuln.write('B5', "CVSS", format_table_titles)
        cvss = vuln.cvss if vuln.cvss != -1.0 else "No CVSS"
        ws_vuln.merge_range("C5:G5", cvss, format_table_cells)

        ws_vuln.write('B6', "Level", format_table_titles)
        ws_vuln.merge_range("C6:G6", vuln.level.capitalize(), format_table_cells)

        ws_vuln.write('B7', "Family", format_table_titles)
        ws_vuln.merge_range("C7:G7", vuln.family, format_table_cells)

        if len(vuln.description) < 200:
            description_height = 20
        else:
            description_height = 80
        ws_vuln.set_row(2, description_height, None)

        ws_vuln.write('C9', "IP", format_table_titles)
        ws_vuln.write('D9', "Host name", format_table_titles)
        ws_vuln.write('E9', "Port number", format_table_titles)
        ws_vuln.write('F9', "Port protocol", format_table_titles)
        ws_vuln.write('G9', "Port description", format_table_titles)

        # Affected hosts
        for j, (host, port) in enumerate(vuln.hosts, 10):

            ws_vuln.write("C{}".format(j), host.ip)
            ws_vuln.write("D{}".format(j), host.host_name if host.host_name else "-")

            if port:
                ws_vuln.write("E{}".format(j), port.number)
                ws_vuln.write("F{}".format(j), port.protocol)
                ws_vuln.write("G{}".format(j), port.description)
            else:
                ws_vuln.write("E{}".format(j), "No port info")

    workbook.close()


def export_to_word(vuln_info, output_file="openvas_report"):
    """
    Export vulnerabilities info in a Word file.

    :param vuln_info: Vulnerability list info
    :type vuln_info: list(Vulnerability)

    :param output_file: Filename of the Excel file
    :type output_file: str

    :raises: NotImplementedError
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
            raise ValueError("output_file must have a valid name.")

    if output_file.split(".")[-1] != "docx":
        output_file = "{}.docx".format(output_file)

    from docx import Document
    from docx.enum.style import WD_STYLE_TYPE
    from docx.oxml.shared import qn, OxmlElement
    from docx.oxml.ns import nsdecls
    from docx.oxml import parse_xml
    from docx.shared import Cm, Pt, RGBColor

    # TODO Move to function to de-duplicate this
    vuln_info.sort(key=lambda key: key.cvss, reverse=True)
    vuln_levels = Counter()
    vuln_host_by_level = Counter()
    vuln_by_family = Counter()

    for i, vuln in enumerate(vuln_info, 1):
        vuln_levels[vuln.level.lower()] += 1
        vuln_host_by_level[vuln.level.lower()] += len(vuln.hosts)
        vuln_by_family[vuln.family] += 1

    # ====================
    # DOCUMENT PROPERTIES
    # ====================
    document = Document()

    doc_prop = document.core_properties
    doc_prop.title = "OpenVAS Report"
    doc_prop.category = "Report"

    # MARGINS
    # --------------------
    for section in document.sections:
        section.top_margin = Cm(2.54)
        section.bottom_margin = Cm(2.54)
        section.left_margin = Cm(2.54)
        section.right_margin = Cm(2.54)

    # FONTS
    # --------------------
    styles = document.styles

    color_blue = RGBColor.from_string(Config.colors()['blue'][1:])

    font_normal = styles['Normal'].font
    font_normal.name = 'Tahoma'
    font_normal.size = Pt(10)

    def add_style(new_style_name, base_style_name, font_size, font_color, font_bold, widow_ctrl):
        style = styles.add_style(new_style_name, WD_STYLE_TYPE.PARAGRAPH)
        style.base_style = styles[base_style_name]
        style.font.name = 'Tahoma'
        style.font.size = font_size
        style.font.bold = font_bold
        style.font.color.rgb = font_color
        style.paragraph_format.widow_control = widow_ctrl
        style.next_paragraph_style = styles['Body Text']
        style.hidden = False
        style.quick_style = True
    
    add_style('Report Title', 'Title', Pt(36), color_blue, True, True)
    add_style('Report Heading TOC', 'Normal', Pt(16), color_blue, True, True)
    add_style('Report Heading 1', 'Heading 1', Pt(16), color_blue, True, True)
    add_style('Report Heading 2', 'Heading 2', Pt(14), color_blue, True, True)
    add_style('Report Heading 3', 'Heading 3', Pt(13), color_blue, True, True)

    document.add_paragraph('OpenVAS Report', style='Report Title')

    # ====================
    # TABLE OF CONTENTS
    # ====================
    # TODO Use ToC Header so it doesn't end up in the ToC
    document.add_paragraph('Table of Contents', style='Report Heading TOC')

    par = document.add_paragraph()
    run = par.add_run()
    fld_char = OxmlElement('w:fldChar')  # creates a new element
    fld_char.set(qn('w:fldCharType'), 'begin')  # sets attribute on element
    instr_text = OxmlElement('w:instrText')
    instr_text.set(qn('xml:space'), 'preserve')  # sets attribute on element
    instr_text.text = r'TOC \o 1-2 \h \z \u'  # change "1-2" depending on heading levels you need

    fld_char2 = OxmlElement('w:fldChar')
    fld_char2.set(qn('w:fldCharType'), 'separate')
    fld_char3 = OxmlElement('w:t')
    fld_char3.text = "# Right-click to update field. #"
    fld_char2.append(fld_char3)

    fld_char4 = OxmlElement('w:fldChar')
    fld_char4.set(qn('w:fldCharType'), 'end')

    r_element = run._r
    r_element.append(fld_char)
    r_element.append(instr_text)
    r_element.append(fld_char2)
    r_element.append(fld_char4)

    document.add_page_break()

    # ====================
    # SUMMARY
    # ====================
    document.add_paragraph('Summary', style='Report Heading 1')
    document.add_paragraph('Symmary info, with graphs, will come here')

    records = (
        ('Critical', vuln_levels["critical"], vuln_host_by_level["critical"]),
        ('High', vuln_levels["high"], vuln_host_by_level["high"]),
        ('Medium', vuln_levels["medium"], vuln_host_by_level["medium"]),
        ('Low', vuln_levels["low"], vuln_host_by_level["low"]),
        ('None', vuln_levels["none"], vuln_host_by_level["none"]),
    )

    table_summary = document.add_table(rows=1, cols=3)
    hdr_cells = table_summary.rows[0].cells
    hdr_cells[0].paragraphs[0].add_run('Threat').bold = True
    hdr_cells[1].paragraphs[0].add_run('Vulns number').bold = True
    hdr_cells[2].paragraphs[0].add_run('Affected hosts').bold = True
    for t, vn, ah in records:
        row_cells = table_summary.add_row().cells
        row_cells[0].text = t
        row_cells[1].text = str(vn)
        row_cells[2].text = str(ah)

    # TODO Add graphs

    # ====================
    # VULN PAGES
    # ====================
    cur_level = ""

    for i, vuln in enumerate(vuln_info, 1):
        # GENERAL
        # --------------------
        level = vuln.level.lower()

        if level != cur_level:
            document.add_paragraph(
                level.capitalize(), style='Report Heading 1').paragraph_format.page_break_before = True
            cur_level = level
        else:
            document.add_page_break()

        title = "[{}] {}".format(level.upper(), vuln.name)
        document.add_paragraph(title, style='Report Heading 2')
    
        table_vuln = document.add_table(rows=4, cols=3)
        table_vuln.autofit = False

        # Color
        col_cells = table_vuln.columns[0].cells
        col_cells[0].merge(col_cells[3])
        color_fill = parse_xml(r'<w:shd {} w:fill="{}"/>'.format(nsdecls('w'), Config.colors()[vuln.level][1:]))
        col_cells[0]._tc.get_or_add_tcPr().append(color_fill)

        for col_cell in col_cells:
            col_cell.width = Cm(0.42)

        # Headers
        hdr_cells = table_vuln.columns[1].cells
        hdr_cells[0].paragraphs[0].add_run('Description').bold = True
        hdr_cells[1].paragraphs[0].add_run('CVEs').bold = True
        hdr_cells[2].paragraphs[0].add_run('CVSS').bold = True
        hdr_cells[3].paragraphs[0].add_run('Family').bold = True

        for hdr_cell in hdr_cells:
            hdr_cell.width = Cm(3.58)

        # Fields
        cves = ", ".join(vuln.cves)
        cves = cves.upper() if cves != "" else "No CVE"

        cvss = str(vuln.cvss) if vuln.cvss != -1.0 else "No CVSS"

        txt_cells = table_vuln.columns[2].cells
        txt_cells[0].text = vuln.description
        txt_cells[1].text = cves
        txt_cells[2].text = cvss
        txt_cells[3].text = vuln.family

        for txt_cell in txt_cells:
            txt_cell.width = Cm(12.51)

        # VULN HOSTS
        # --------------------
        document.add_paragraph('Vulnerable hosts', style='Report Heading 3')

        table_hosts = document.add_table(cols=5, rows=(len(vuln.hosts) + 1))
        hdr_cells = table_hosts.rows[0].cells
        hdr_cells[0].paragraphs[0].add_run('IP').bold = True
        hdr_cells[1].paragraphs[0].add_run('Host name').bold = True
        hdr_cells[2].paragraphs[0].add_run('Port number').bold = True
        hdr_cells[3].paragraphs[0].add_run('Port protocol').bold = True
        hdr_cells[4].paragraphs[0].add_run('Port description').bold = True

        for j, (host, port) in enumerate(vuln.hosts, 1):

            cells = table_hosts.rows[j].cells
            cells[0].text = host.ip
            cells[1].text = host.host_name if host.host_name else "-"
            if port:
                cells[2].text = port.number
                cells[3].text = port.protocol
                cells[4].text = port.description
            else:
                cells[2].text = "No port info"

    document.save(output_file)

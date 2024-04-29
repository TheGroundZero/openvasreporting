# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

import argparse
from typing import Union

from openvasreporting.libs.parsed_data import ResultTree, Vulnerability

from .libs.config import Config, Config_YAML
from .libs.parser import parsers
from .libs.export import implemented_exporters

def main():

    PROG_DESCRIPTION='''OpenVAS report Converter\n
Parses one ore more OpenVAS xml report and creates a xlsx, docx or csv with the results
'''
    CONFIG_FILE_HELP="""path to a .yml file containing all options but INPUT_FILES and OUTPUT_FILE.
if present, all the following options will be ignored and defaults applied 
when not present in this file. a sample of this file can be found in the doc folder\n"""
    REGEX_INCLUDE_HELP="""Path to a file containing a list of regex expressions to include in the report
the regex expressions will be matched against the name of the vulnerability\n"""
    REGEX_EXCLUDE_HELP="""Path to a file containing a list of regex expressions to exclude from the report
the regex expressions will be matched against the name of the vulnerability\n"""


    parser = argparse.ArgumentParser(
        prog="openvasreporting",  # TODO figure out why I need this in my code for -h to show correct name
        description=PROG_DESCRIPTION,
        allow_abbrev=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-i", "--input", nargs="*", dest="input_files", help="OpenVAS XML reports\n", 
                        required=True)
    parser.add_argument("-o", "--output", dest="output_file", help="Output file, no extension\n", 
                        required=False, default="openvas_report")
    parser.add_argument("-c", "--config-file", dest="config_file",help=CONFIG_FILE_HELP, 
                        required=False, default=None)
    parser.add_argument("-l", "--level", dest="min_lvl", 
                        help="Minimal level (c, h, m, l, n)\n", 
                        required=False, choices=['c', 'h', 'm', 'l', 'n'], default='n')
    parser.add_argument("-f", "--format", dest="format", help="Output format (xlsx)\n", 
                        required=False, choices=["xlsx", "docx", "csv"], default="xlsx")
    parser.add_argument("-t", "--template", dest="template", 
                        help="Template file for docx export\n", required=False,
                        default=None)
    parser.add_argument("-T", "--report-type", dest="report_type", help="Report by (v)ulnerability or by (h)ost\n",
                        required=False, choices=['h', 'host', 'v', 'vulnerability', 's', 'summary'], default="vulnerability")
    parser.add_argument("-n", "--network-include", dest="networks_included", 
                        help="Path to a file containing a list of network cidrs, ip ranges and ips to be included in the report\n",
                        required=False, default=None)
    parser.add_argument("-N", "--network-exclude", dest="networks_excluded", 
                        help="Path to a file containing a list of network cidrs, ip ranges and ips to be excluded from the report\n",
                        required=False, default=None)
    parser.add_argument("-r", "--regex_include", dest="regex_included", help=REGEX_INCLUDE_HELP,
                        required=False, default=None)
    parser.add_argument("-R", "--regex_exclude", dest="regex_excluded", help=REGEX_EXCLUDE_HELP,
                        required=False, default=None)
    parser.add_argument("-e", "--cve-include", dest="cve_included", 
                        help="Path to a file containing a list of cve numbers to include in the report\n",
                        required=False, default=None)
    parser.add_argument("-E", "--cve-exclude", dest="cve_excluded",
                        help="Path to a file containing a list of cve numbers to exclude from the report\n",
                        required=False, default=None)
    parser.add_argument("-D", "--danger-exclude", dest="danger_excluded",
                        help="List of letter of threat to exclude\n",
                        required=False, default="")
    args = parser.parse_args()

    if not args.config_file is None:
        config = Config_YAML(args.input_files, args.config_file, args.output_file)
    else:
        config = Config(args.input_files, 
                        args.output_file, 
                        args.min_lvl, 
                        args.format, 
                        args.report_type, 
                        args.template,
                        args.networks_included,
                        args.networks_excluded,
                        args.regex_included,
                        args.regex_excluded,
                        args.cve_included,
                        args.cve_excluded,
                        args.danger_excluded)

    convert(config)


def convert(config:Config):
    """
    Convert the OpenVAS XML to requested format

    :param config: configuration
    :type config: Config

    :raises: TypeError, ValueError, IOError, NotImplementedError
    """
    if not isinstance(config, Config):
        raise TypeError("Expected Config, got '{}' instead".format(type(config)))

    if config.report_type + '-' + config.format not in implemented_exporters().keys():
        raise NotImplementedError("The report by '{}' in format '{}' is not implemented yet.".format(
                                  config.report_type, config.format))
    
    threat_dict = Config.levels()
    config_allowed = list(threat_dict.values())

    # Added a filtrer to not raise an error if a wrong threat type is detected
    for threat in config.threat_excluded:
        if td := threat_dict.get(threat, None):
            config_allowed.remove(td)

    config.threat_included = config_allowed
        
    tmp_openvas_info:Union[list[Vulnerability], ResultTree] = parsers()[config.report_type](config)
    
    # --- Filter All Vulns here to avoid having to do it 3 times --- #

    if isinstance(tmp_openvas_info, ResultTree):
        ...

    else:
        ...
        

        # Remove excluded vuln
        # openvas_info = list(filter(lambda x: Config.cvss_level(x.cvss) in config_allowed, tmp_openvas_info))

    openvas_info = tmp_openvas_info
    
    if len(openvas_info) == 0:
        raise ValueError(f"No vulnerability was found with the following parameters {config.threat_excluded =}")
    
    implemented_exporters()[config.report_type + '-' + config.format](openvas_info, threat_type_list=config_allowed, template=config.template, output_file=config.output_file)


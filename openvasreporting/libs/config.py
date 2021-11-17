# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

"""This file contains data structures"""

import re
import netaddr
import glob

import yaml
from yaml.loader import SafeLoader

class Config(object):
    def __init__(self, input_files, output_file="openvas_report", min_level="none", format="xlsx",
                 report_type="host", template=None, networks_included=None, networks_excluded=None, 
                 regex_included=None, regex_excluded=None, cve_included=None, cve_excluded=None):
        """
        :param input_files: input file path
        :type input_files: list(str)

        :param output_file: output file path and name
        :type output_file: str

        :param min_level: minimal level to add to output
        :type min_level: str

        :param format: output file format
        :type format: str

        :param report_type: report by (v)ulnerability or (h)ost
        :type report_type: str

        :param template: template to use
        :type format: str

        :param networks_excluded: path to file with a list of excluded host ips
        :type networks_excluded: str

        :param networks_included: path to file with a list of included host ips
        :type networks_included: str

        :param regex_excluded: path to file with a list of regex expressions 
             to be excluded when matched against a vulnerability description 
             
        :param regex_included: path to file with a list of regex expressions 
             to be included when matched against a vulnerability description 

        :raises: TypeError, ValueError
        """
        if not isinstance(input_files, list):
            raise TypeError("Expected list, got '{}' instead".format(type(input_files)))
        else:
            for i in input_files:
                if not isinstance(i, str):
                    raise TypeError("Expected str, got '{}' instead".format(type(i)))

        if not isinstance(output_file, str):
            raise TypeError("Expected str, got '{}' instead".format(type(output_file)))
        if not isinstance(min_level, str):
            raise TypeError("Expected str, got '{}' instead".format(type(min_level)))
        if not isinstance(format, str):
            raise TypeError("Expected str, got '{}' instead".format(type(format)))
        if template is not None and not isinstance(template, str):
            raise TypeError("Expected str, got '{}' instead".format(type(template)))
        if report_type is not None and not isinstance(report_type, str):
            raise TypeError("Expected str, got '{}' instead".format(type(report_type)))
        if networks_excluded is not None and not isinstance(networks_excluded, str):
            raise TypeError("Expected str, got '{}' instead".format(type(networks_excluded)))
        if networks_included is not None and not isinstance(networks_included, str):
            raise TypeError("Expected str, got '{}' instead".format(type(networks_included)))
        if regex_excluded is not None and not isinstance(regex_excluded, str):
            raise TypeError("Expected str, got '{}' instead".format(type(regex_excluded)))
        if regex_included is not None and not isinstance(regex_included, str):
            raise TypeError("Expected str, got '{}' instead".format(type(regex_included)))
        if cve_excluded is not None and not isinstance(cve_excluded, str):
            raise TypeError("Expected str, got '{}' instead".format(type(cve_excluded)))
        if cve_included is not None and not isinstance(cve_included, str):
            raise TypeError("Expected str, got '{}' instead".format(type(cve_included)))

        if min_level.lower() in Config.levels().keys():
            min_level = Config.levels()[min_level.lower()]
        else:
            raise ValueError("Invalid value for level parameter, \
                must be one of: c[ritical], h[igh], m[edium], l[low], n[one]")
    
        ifiles = []
        for file in input_files:
            ifiles.extend(glob.glob(file))
        self.input_files = ifiles
        self.output_file = "{}.{}".format(output_file, format) if output_file.split(".")[-1] != format \
            else output_file

        self.min_level = min_level
        self.format = format
        self.template = template

        self.report_type = report_type
        if report_type == 'v' or report_type == 'vulnerability':
            self.report_type = 'vulnerability'
        elif report_type == 'h' or report_type == 'host':
            self.report_type = 'host'
        else:
           raise ValueError("Expected host or vulnerability for report-type parameter but got '{}' instead.".format(report_type))
        
        if not networks_excluded is None:
            with open(networks_excluded) as f:
                lines = f.read().splitlines()
            self.networks_excluded = self.include_networks(lines)
        else:
            self.networks_excluded = None
            
        if not networks_included is None:
            with open(networks_included) as f:
                lines = f.read().splitlines()
            self.networks_included = self.include_networks(lines)
        else:    
            self.networks_included = None

        if not regex_excluded is None:
            with open(regex_excluded) as f:
                lines = f.read().splitlines()
            self.regex_excluded = self.include_regex(lines)
        else:
            self.regex_excluded = None

        if not regex_included is None:
            with open(regex_included) as f:
                lines = f.read().splitlines()
            self.regex_included = self.include_regex(lines)
        else:
            self.regex_included = None

        if not cve_included is None:
            with open(cve_included) as f:
               self.cve_included = f.read().splitlines()
        else:
            self.cve_included = None

        if not cve_excluded is None:
            with open(cve_excluded) as f:
               self.cve_excluded = f.read().splitlines()
        else:
            self.cve_excluded = None

    @staticmethod
    def colors():
        return {
            'blue':     '#183868',
            'critical': '#702da0',
            'high':     '#c80000',
            'medium':   '#ffc000',
            'low':      '#00b050',
            'none':     '#0070c0',
        }

        
    @staticmethod
    def levels():
        return {
            'c': 'critical',
            'h': 'high',
            'm': 'medium',
            'l': 'low',
            'n': 'none'
        }

    @staticmethod
    def thresholds():
        return {
            'critical': 9.0,
            'high':     7.0,
            'medium':   4.0,
            'low':      0.1,
            'none':     0.0
        }

    @staticmethod
    def cvss_color(cvss):
        for key in Config.thresholds():
            if cvss >= Config.thresholds()[key]:
                return Config.colors()[key]
        return None
        
    @staticmethod        
    def cvss_level(cvss):
        for key in Config.thresholds():
            if cvss >= Config.thresholds()[key]:
                return key
        return None
        
    @staticmethod
    def min_levels():
        return {
            'critical': [Config.levels()['c']],
            'high':     [Config.levels()['c'], Config.levels()['h']],
            'medium':   [Config.levels()['c'], Config.levels()['h'], Config.levels()['m']],
            'low':      [Config.levels()['c'], Config.levels()['h'], Config.levels()['m'], Config.levels()['l']],
            'none':     [Config.levels()['c'], Config.levels()['h'], Config.levels()['m'], Config.levels()['l'],
                         Config.levels()['n']]
        }

#
# includes lines from options files networks-includes and networks-excludes
# into a list of netaddr instances for later comparision when parsing and filtering
    def include_networks(self, lines):
        outlines = []
        for ip in lines:
            if ip == '':
                continue
            if '-' in ip:    # ip range?
                _start_ip, _end_ip = ip.split('-')
                try:
                    ip_range = netaddr.IPRange(_start_ip, _end_ip)
                    outlines.append(ip_range)
                except AddrFormatError:
                    raise AddrFormatError("Expected valid ip range, got '{}'-'{}' instead".format(_start_ip, _end_ip))
            else:            # ip or network cdir?
                try:
                    network = netaddr.IPNetwork(ip)
                    outlines.append(network)
                except AddrFormatError:
                    raise AddrFormatError("Expected valid ip address or network cidr, got '{}' instead.".format(ip))

        return outlines

#
# includes lines from options files regex-includes and regex-excludes
# into a list of re.compile(d) instances for later comparision when parsing and filtering
    def include_regex(self, lines):
        outlines = []
        for regex_entry in lines:
            try:
                outlines.append(re.compile(regex_entry, re.IGNORECASE))
            except re.error:
                raise ValueError("Expected valid regex expression, got '{}' instead.".format(regex_entry))

        return outlines

class Config_YAML(Config):
    def __init__(self, input_files, config_file, output_file="openvas_report"):
        """
        :param input_files: input file path
        :type input_files: list(str)

        :param output_file: output file path and name
        :type output_file: str

        :param min_level: minimal level to add to output
        :type min_level: str
        
        :raises: TypeError, ValueError
        """
        if not isinstance(input_files, list):
            raise TypeError("Expected list, got '{}' instead".format(type(input_files)))
        else:
            for i in input_files:
                if not isinstance(i, str):
                    raise TypeError("Expected str, got '{}' instead".format(type(i)))

        if not isinstance(output_file, str):
            raise TypeError("Expected str, got '{}' instead".format(type(output_file)))
        if not isinstance(config_file, str):
            raise TypeError("Expected str, got '{}' instead".format(type(min_level)))

        ifiles = []
        for file in input_files:
            ifiles.extend(glob.glob(file))
        self.input_files = ifiles
        
        # loads configuration .yml file as a dict
        try:
            with open(config_file, 'r') as f:
                yamldict = yaml.load(f, Loader=SafeLoader)
        except FileNotFoundError:
            raise FileNotFoundError("Could Not find '{}'.".format(config_file));
        
        # set options flags from yml or defaults
        if 'level' in yamldict:
            if not yamldict['level'] in ['critical', 'high', 'medium', 'low', 'none']:
                raise ValueError("Invalid value for level parameter, \
                                  must be one of: critical, high, medium, low, none")
            self.min_level = yamldict['level']
        else:
            self.min_level = 'none';
            
        if 'template' in yamldict:
            self.template = yamldict['template']
        else:
            self.template = None
            
        if 'format' in yamldict:
            if not yamldict['format'] in ['xlsx', 'docx', 'csv']:
                raise ValueError("Invalid value for format parameter, must be one of: xlsx, docx, csv")
            self.format = yamldict['format']
        else:
            self.format = 'xlsx'
            
        if 'reporttype' in yamldict:
            if not yamldict['reporttype'] in ['vulnerability', 'host']:
                raise ValueError("Invalid value for report type parameter, must be one of: vulnerability, host")
            self.report_type = yamldict['reporttype']
        else:
            self.report_type = 'vulnerability'
            
        # network filters
        if 'networks' in yamldict:
            if 'includes' in yamldict['networks']:
                self.networks_included = self.include_networks(yamldict['networks']['includes'])
            else:
                self.networks_included = None
            if 'excludes' in yamldict['networks']:
                self.networks_excluded = self.include_networks(yamldict['networks']['excludes'])
            else:
                self.networks_excluded = None
        else:
            self.networks_excluded = None
            self.networks_included = None
            
        # regex filters
        if 'regex' in yamldict:
            if 'includes' in yamldict['regex']:
                self.regex_included = self.include_regex(yamldict['regex']['includes'])
            else:
                self.regex_included = None
            if 'excludes' in yamldict['regex']:
                self.regex_excluded = self.include_regex(yamldict['regex']['excludes'])
            else:
                self.regex_included = None
        else:
            self.regex_excluded = None
            self.regex_included = None
            
        # cve filters
        if 'cve' in yamldict:
            if 'includes' in yamldict['cve']:
                self.cve_included = yamldict['cve']['includes']
            else:
                self.cve_included = None
            if 'excludes' in yamldict['cve']:
                self.cve_excluded = yamldict['cve']['excludes']
            else:
                self.cve_excluded = None
        else:
            self.cve_excluded = None
            self.cve_included = None

        self.output_file = "{}.{}".format(output_file, self.format) if output_file.split(".")[-1] != self.format \
            else output_file
        
    

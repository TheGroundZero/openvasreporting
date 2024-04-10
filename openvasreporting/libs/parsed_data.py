# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

# TODO: Get rid of all the log messages

"""This file contains data structures"""

import re

from .config import Config
import netaddr

import logging
#
# DEBUG

#import logging
#import sys
#logging.basicConfig(stream=sys.stderr, level=logging.DEBUG,
#                    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
#logging.basicConfig(stream=sys.stderr, level=logging.ERROR,
#                    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
dolog = False

# Port object modifed to include result data field
class Port(object):
    """Port information"""

    def __init__(self, number, protocol="tcp", result=""):
        """
        :param number: port number
        :type number: int

        :param protocol: port protocol (tcp, udp, ...)
        :type protocol: basestring

        :param result: port result
        :type result: str

        :raises: TypeError, ValueError
        """
        if not isinstance(number, int):
            raise TypeError("Expected int, got '{}' instead".format(type(number)))
        else:
            if number < 0:
                raise ValueError("Port number must be greater than 0")

        if not isinstance(protocol, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(protocol)))

        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))

        self.number = number
        self.protocol = protocol
        self.result = result

    # Modified to include result in structure
    @staticmethod
    def string2port(info,result):
        """
        Extract port number, protocol and description from an string.
        return a port class with seperate port, protocol and result

        ..note:
            Raises value error if information can't be processed.

        # >>> p=Port.string2port("2000/tcp","result string")
        # >>> print p.number
          2000
        # >>> print p.proto
          "tcp"
        # >>> print p.result
          "result string"

        # >>> p=Port.string2port("general/icmp", "string test")
        # >>> print p.number
          0
        # >>> print p.proto
          "icmp"
        # >>> print p.result
          "string test"

        :param info: raw string with port information
        :type info: basestring

        :param result: raw string with port information
        :type result: basestring

        :return: Port instance
        :rtype: Port

        :raises: ValueError
        """
        if not isinstance(info, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(info)))

        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))

        regex_nr = re.search("([\d]+)(/)([\w]+)", info)
        regex_general = re.search("(general)(/)([\w]+)", info)

        if regex_nr and len(regex_nr.groups()) == 3:
            number = int(regex_nr.group(1))
            protocol = regex_nr.group(3)
        elif regex_general and len(regex_general.groups()) == 3:
            number = 0
            protocol = regex_general.group(3)
        else:
            raise ValueError("Can't parse port input string")

        return Port(number, protocol, result)

    def __eq__(self, other):
        return (
                isinstance(other, Port) and
                other.number == self.number and
                other.protocol == self.protocol and
                other.result == self.result
        )

class ParseVulnerability:
    """
    Parses and analyses a Vulnerability XML Entry 
    """
    def __init__(self, vuln, min_level: str):
        """
        Parses an openvas <result> xml Et.Element.
        
        : param: vuln: <result> openvas xml report element
        : type: xml.etree import ElementTree as Et or xml.etree import cElementTree as Et
        
        : param: min_level: minimal level for inclusion on the report
        : type: one of {c, h, m, l, n}
        
        returns self instance populated with values from <result> subtags
        """
        if not isinstance(min_level, str):
            raise TypeError("expected str, got '{}' instead".format(type(str)))

        nvt_tmp = vuln.find("./nvt")
    
        # --------------------
        #
        # VULN_NAME
        self.vuln_name = nvt_tmp.find("./name").text
    
        if dolog: logging.debug(
            "--------------------------------------------------------------------------------")
        if dolog: logging.debug("- {}".format(self.vuln_name))  # DEBUG
        if dolog: logging.debug(
            "--------------------------------------------------------------------------------")
    
        # --------------------
        #
        # VULN_ID
        self.vuln_id = nvt_tmp.get("oid")
        if not self.vuln_id or self.vuln_id == "0":
            if dolog: logging.debug("  ==> SKIP")  # DEBUG
            raise ValueError("Expected valid <result> openvas xml element, got '{}' instead".format(vuln.text))
        if dolog: logging.debug("* vuln_id:\t{}".format(self.vuln_id))  # DEBUG
    
        # --------------------
        #
        # VULN_CVSS
        self.vuln_cvss = vuln.find("./severity").text
        if self.vuln_cvss is None:
            self.vuln_cvss = 0.0
        self.vuln_cvss = float(self.vuln_cvss)
        if dolog: logging.debug("* vuln_cvss:\t{}".format(self.vuln_cvss))  # DEBUG
    
        # --------------------
        #
        # VULN_LEVEL
        self.vuln_level = "none"
        for level in Config.levels().values():
            if self.vuln_cvss >= Config.thresholds()[level]:
                self.vuln_level = level
                if dolog: logging.debug("* vuln_level:\t{}".format(self.vuln_level))  # DEBUG
                break
    
        if dolog: logging.debug("* min_level:\t{}".format(min_level))  # DEBUG
        if self.vuln_level not in Config.min_levels()[min_level]:
            if dolog: logging.debug("   => SKIP")  # DEBUG
            raise ValueError("Expected min_level in one of 'chmln', got '{}' instead".format(min_level))
    
        # --------------------
        #
        # VULN_HOST
        self.vuln_host = vuln.find("./host").text
        self.vuln_host_name = vuln.find("./host/hostname").text
        if self.vuln_host_name is None:
            self.vuln_host_name = "N/A"
        if dolog: logging.debug("* hostname:\t{}".format(self.vuln_host_name))  # DEBUG
        self.vuln_port = vuln.find("./port").text
        if dolog: logging.debug(
            "* vuln_host:\t{} port:\t{}".format(self.vuln_host, self.vuln_port))  # DEBUG
    
        # --------------------
        #
        # VULN_TAGS
        # Replace double newlines by a single newline
        self.vuln_tags_text = re.sub(r"(\r\n)+", "\r\n", nvt_tmp.find("./tags").text)
        self.vuln_tags_text = re.sub(r"\n+", "\n", self.vuln_tags_text)
        # Remove useless whitespace but not newlines
        self.vuln_tags_text = re.sub(r"[^\S\r\n]+", " ", self.vuln_tags_text)
        vuln_tags_temp = self.vuln_tags_text.split('|')
        self.vuln_tags = dict(tag.split('=', 1) for tag in vuln_tags_temp)
        if dolog: logging.debug("* vuln_tags:\t{}".format(self.vuln_tags))  # DEBUG
    
        # --------------------
        #
        # VULN_THREAT
        self.vuln_threat = vuln.find("./threat").text
        if self.vuln_threat is None:
            self.vuln_threat = Config.levels()["n"]
        else:
            self.vuln_threat = self.vuln_threat.lower()
    
        if dolog: logging.debug("* vuln_threat:\t{}".format(self.vuln_threat))  # DEBUG
    
        # --------------------
        #
        # VULN_FAMILY
        self.vuln_family = nvt_tmp.find("./family").text
    
        if dolog: logging.debug("* vuln_family:\t{}".format(self.vuln_family))  # DEBUG
    
        # --------------------
        #
        # VULN_CVES
        #vuln_cves = nvt_tmp.findall("./refs/ref")
        self.vuln_cves = []
        self.ref_list = []
        for reference in nvt_tmp.findall('./refs/ref'):
            if reference.attrib.get('type') == 'cve':
                self.vuln_cves.append(reference.attrib.get('id'))
            else:
                self.ref_list.append(reference.attrib.get('id'))
        # if dolog: logging.debug("* vuln_cves:\t{}".format(vuln_cves))  # DEBUG
        # if dolog: logging.debug("* vuln_cves:\t{}".format(Et.tostring(vuln_cves).decode()))  # DEBUG
        # if vuln_cves is None or vuln_cves.text.lower() == "nocve":
        #     vuln_cves = []
        # else:
        #     vuln_cves = [vuln_cves.text.lower()]
        self.vuln_references = ' , '.join(self.ref_list)
        if dolog: logging.debug("* vuln_cves:\t{}".format(self.vuln_cves))  # DEBUG
        if dolog: logging.debug("* vuln_references:\t{}".format(self.vuln_references))
        # --------------------
        #
        # VULN_REFERENCES
        # vuln_references = nvt_tmp.find("./xref")
        # if vuln_references is None or vuln_references.text.lower() == "noxref":
        #     vuln_references = []
        # else:
        #     vuln_references = vuln_references.text.lower().replace("url:", "\n")
    
        # if dolog: logging.debug("* vuln_references:\t{}".format(vuln_references))  # DEBUG
    
        # --------------------
        #
        # VULN_DESCRIPTION
        self.vuln_result = vuln.find("./description")
        if self.vuln_result is None or vuln.find("./description").text is None:
            self.vuln_result = ""
        else:
            self.vuln_result = self.vuln_result.text
    
        # Replace double newlines by a single newline
        self.vuln_result = self.vuln_result.replace("(\r\n)+", "\n")
    
        if dolog: logging.debug("* vuln_result:\t{}".format(self.vuln_result))  # DEBUG

    @classmethod
    def check_and_parse_result(cls, vuln, config: Config):
        """
        checks if this vulnerability result element in the openvas xml report
        will be included in the convertion. If so, it instantiates a ParsedVulnerability
        object that will parse the <result> element and returns it.
        for now it checks:
        - if this <result> has a valid nvt-oid
        - if this <result> has a severity level equal or higher than min_lvl
        - check if host_name is in the list of excluded files and return None if so
        - check if host_name is in the list of included only files 
        
        : param: vuln: <result> openvas xml report element
        : type: xml.etree import ElementTree as Et or xml.etree import cElementTree as Et
        
        : param: min_level: minimal level for inclusion on the report
        : type: one of {c, h, m, l, n}
        """
        if not isinstance(config, Config):
            raise TypeError("Expected Config, got '{}' instead".format(type(config)))
            
        
        # nvt has oid?
        vuln_id = vuln.find('./nvt').get('oid')
        if not vuln_id or vuln_id == "0":
            return None

        # is ip included and/or excluded?
        if config.networks_excluded is not None or config.networks_included is not None:
            host_ip = vuln.find('./host').text
            host_ip_addr = netaddr.IPAddress(host_ip)
        
        if config.networks_excluded is not None:
            for ipline in config.networks_excluded:
                if host_ip_addr in ipline:
                    return None

        if config.networks_included is not None:
            _included = False
            for ipline in config.networks_included:
                if host_ip_addr in ipline:
                    _included = True        
            if not _included:
                return None
            
        # check regex expressions inclusion and exclusion
        if config.regex_excluded is not None or config.regex_included is not None:
            vuln_name = vuln.find('./name').text
        
        # does any of regex_excluded matches this vulnerability name?
        if config.regex_excluded is not None:
            for regex_entry in config.regex_excluded:
                if regex_entry.search(vuln_name):
                    return None
                
        # does any of regex_included matches this vulnerability name?
        if config.regex_included is not None:
            _included = False
            for regex_entry in config.regex_included:
                if regex_entry.search(vuln_name):
                    _included = True
            if not _included:
                return None

        # check cve include or exclude
        if config.cve_excluded is not None or config.cve_included is not None:
            cve_list = []
            for r in vuln.findall("./nvt/refs/ref[@type='cve']"):
                cve_list.append(r.attrib.get('id'))

        # does any config.cve_excluded is in this list?
        if config.cve_excluded is not None:
            for cve_entry in config.cve_excluded:
                if cve_entry in cve_list:
                    return None
                    
        # does any cve_include is in this list?
        if config.cve_included is not None:
            _included = False
            for cve_entry in config.cve_included:
                if cve_entry in cve_list:
                    _included = True
            if not _included:
                return None
                    
        # vuln severity >= min_level?
        vuln_cvss = vuln.find('./severity').text
        if vuln_cvss is None:
            vuln_cvss = 0.0
        vuln_cvss = float(vuln_cvss)
        if vuln_cvss >= Config.thresholds()[config.min_level]:
            return cls(vuln, config.min_level)
        
        return None 
      
class Host(object):
    """Host information"""

    def __init__(self, ip, host_name=""):
        """
        :param ip: Host IP
        :type ip: basestring

        :param host_name: Host name
        :type host_name: basestring

        :raises: TypeError
        """
        if not isinstance(ip, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(ip)))
        if not isinstance(host_name, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(host_name)))
 
        self.ip = ip
        self.host_name = host_name
        self.num_vulns = 0
        self.nv = {'critical': 0,
                   'high': 0,
                   'medium': 0,
                   'low': 0,
                   'none': 0
                  }
        self.sum_cvss = 0
        self.higher_cvss = 0
        self.vuln_list = []
 
    def addvulnerability(self, parsed_vuln: ParseVulnerability):
        """
        Creates and adds a new vulnerability from an instance of ParseVulnerability
        
        : param: parsed_vuln: parsed openvas xml <result> element
        : type: ParseVulnerability
        
        raises TypeError
        """
        if not isinstance(parsed_vuln, ParseVulnerability):
            raise TypeError("Expected ParseVulnerability, got '{}' instead".format(type(v)))

        # check if a vulnerability with the same vuln_id (nvt-oid) already exists in the vuln_list
        for v in self.vuln_list:
            if v.vuln_id == parsed_vuln.vuln_id:
                return
            
        v = Vulnerability(parsed_vuln.vuln_id,
                          name=parsed_vuln.vuln_name,
                          threat=parsed_vuln.vuln_threat,
                          tags=parsed_vuln.vuln_tags,
                          cvss=parsed_vuln.vuln_cvss,
                          cves=parsed_vuln.vuln_cves,
                          references=parsed_vuln.vuln_references,
                          family=parsed_vuln.vuln_family,
                          level=parsed_vuln.vuln_level)
        try:
            # added results to port function as will ne unique per port on each host.
            port = Port.string2port(parsed_vuln.vuln_port, parsed_vuln.vuln_result)
        except ValueError:
            port = None
        v.add_vuln_host(self, port)        
        self.vuln_list.append(v)
        self.num_vulns += 1
        self.nv[v.level] += 1
        self.sum_cvss += v.cvss
        if v.cvss > self.higher_cvss:
            self.higher_cvss = v.cvss
    
    def nv_total(self):
        return self.nv['critical'] + self.nv['high'] + self.nv['medium'] + self.nv['low']
                   
    def __eq__(self, other):
        return (
                isinstance(other, Host) and
                other.ip == self.ip and
                other.host_name == self.host_name
        )


class Vulnerability(object):
    """Vulnerability information"""

    def __init__(self, vuln_id, name, threat, **kwargs):
        """
        :param vuln_id: OpenVAS plugin id
        :type vuln_id: basestring

        :param name: Vulnerability name
        :type name: str

        :param threat: Threat type: None, Low, Medium, High
        :type threat: str

        :param cves: list of CVEs
        :type cves: list(str)

        :param cvss: CVSS number value
        :type cvss: float

        :param level: Threat level according to CVSS: None, Low, Medium, High, Critical
        :type level: str

        :param tags: vulnerability tags
        :type tags: dict

        :param references: list of references
        :type references: list(str)

        :param family: Vulnerability family
        :type family: str

        :param result: Vulnerability result
        :type description: str

        :raises: TypeError, ValueError
        """
        # Get info
        cves = kwargs.get("cves", list()) or list()
        cvss = kwargs.get("cvss", -1.0) or -1.0
        level = kwargs.get("level", "None") or "None"
        tags = kwargs.get("tags", dict()) or dict()
        references = kwargs.get("references", "Uknown") or "Unknown"
        family = kwargs.get("family", "Unknown") or "Unknown"
        result = kwargs.get("description", "Unknown") or "Unknown"

        if not isinstance(vuln_id, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(vuln_id)))
        if not isinstance(name, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(name)))
        if not isinstance(threat, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(threat)))
        if not isinstance(family, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(family)))
        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))
        if not isinstance(cves, list):
            raise TypeError("Expected list, got '{}' instead".format(type(cves)))
        else:
            for x in cves:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        if not isinstance(cvss, (float, int)):
            raise TypeError("Expected float, got '{}' instead".format(type(cvss)))
        if not isinstance(level, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(level)))
        if not isinstance(tags, dict):
            raise TypeError("Expected dict, got '{}' instead".format(type(tags)))
        if not isinstance(references, str):
            raise TypeError("Expected string, got '{}' instead".format(type(references)))
        else:
            for x in references:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        self.vuln_id = vuln_id
        self.name = name
        self.cves = cves
        self.cvss = float(cvss)
        self.level = level
        self.description = tags.get('summary', '')
        self.detect = tags.get('vuldetect', '')
        self.insight = tags.get('insight', '')
        self.impact = tags.get('impact', '')
        self.affected = tags.get('affected', '')
        self.solution = tags.get('solution', '')
        self.solution_type = tags.get('solution_type', '')
        self.references = references
        self.threat = threat
        self.family = family
        self.result = result

        # Hosts
        self.hosts = []

    def add_vuln_host(self, host, port):
        """
        Add a host and a port associated to this vulnerability

        :param host: Host instance
        :type host: Host

        :param port: Port instance
        :type port: Port

        :raises: TypeError
        """
        if not isinstance(host, Host):
            raise TypeError("Expected Host, got '{}' instead".format(type(host)))
        if port is not None:
            if not isinstance(port, Port):
                raise TypeError("Expected Port, got '{}' instead".format(type(port)))

        if (host, port) not in self.hosts:
            self.hosts.append((host, port))

    def __eq__(self, other):
        if not isinstance(other, Vulnerability):
            raise TypeError("Expected Vulnerability, got '{}' instead".format(type(other)))

        if (
                other.vuln_id != self.vuln_id or
                other.name != self.name or
                other.cves != self.cves or
                other.cvss != self.cvss or
                other.level != self.level or
                other.description != self.description or
                other.detect != self.detect or
                other.insight != self.insight or
                other.impact != self.impact or
                other.affected != self.affected or
                other.solution != self.solution or
                other.solution_type != self.solution_type or
                other.references != self.references or
                other.threat != self.threat or
                other.family != self.family or
                other.result != self.result
        ):
            return False

        for host, port in self.hosts:
            for o_host, o_port in other.hosts:
                if o_host != host or o_port != port:
                    return False

        return True

class ResultTree(dict):
    """
      A dict of Hosts instances
    """

    def addresult(self, parsed_vuln: ParseVulnerability):
        """
        Adds a new vulnerability to an existing Host instance or creates one 
        
        : param: parsed_vuln: parsed openvas xml <result> element
        : type: ParseVulnerability
        
        raises TypeError
        """
        if not isinstance(parsed_vuln, ParseVulnerability):
            raise TypeError("Expected ParseVulnerability, got '{}' instead".format(type(parsed_vuln)))

        hostip = parsed_vuln.vuln_host
        try:
            self[hostip].addvulnerability(parsed_vuln)
        except KeyError:
            self[hostip] = Host(hostip, parsed_vuln.vuln_host_name)
            self[hostip].addvulnerability(parsed_vuln)
            
    def sortedbysumcvss(self):
        """
        Returns a dict of keys and sum of cvss severity ordered by sum of cvss severity
        """
        temp_dict = {} 
        for key in self:
            temp_dict[key] = (self[key].higher_cvss, self[key].sum_cvss)
        s = list({key: v1 for key, v1 in sorted(temp_dict.items(), key=lambda x: (x[1], x[0]), reverse = True)}.keys())
        return s

    def sortedbynumvulnerabilities(self):
        """
        Returns a dict of keys and number of vulnerabilities ordered by number of vulnerabilities
        """
        temp_dict = {}
        for key in self:
            temp_dict[key] = self[key].num_vulns
#        s = res = {key: val for key, val in sorted(temp_dict.items(), key = lambda ele: ele[1], reverse = True)}
        return {key: val for key, val in sorted(temp_dict.items(), key = lambda ele: ele[1], reverse = True)}

    def sorted_keys_by_rank(self):
        """
        Returns a list of keys of self reverse ordered by rank. 'Rank' here emulates
        the order used at openvas' host tab in the report page of a task: 
        higher_cvss -> # critical vulns -> # high vulns -> # medium vulns -> # low vulns
        """
        temp_list = []
        for key in self:
            temp_list.append((self[key].nv['low'], self[key].nv['medium'], self[key].nv['high'], 
                              self[key].nv['critical'], self[key].higher_cvss, key))
        s = [v[5] for v in sorted(temp_list, 
                                  key = lambda x: (x[4], x[3], x[2], x[1], x[0]), 
                                  reverse=True)]
        return s


    

# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

"""This file contains data structures"""

import re

import netaddr

from .config import Config


def _text(element, path: str, default: str = "") -> str:
    """Text of the sub element at `path`, or `default` when missing or empty."""
    found = element.find(path)
    if found is None or found.text is None:
        return default
    return found.text


def _parse_tags(raw: str) -> dict[str, str]:
    """Parse an OpenVAS 'key=value|key=value' tags string, tolerating bare keys."""
    text = re.sub(r"(\r\n)+", "\r\n", raw)
    text = re.sub(r"\n+", "\n", text)
    text = re.sub(r"[^\S\r\n]+", " ", text)
    tags: dict[str, str] = {}
    for tag in text.split("|"):
        key, _, value = tag.partition("=")
        if key.strip():
            tags[key.strip()] = value
    return tags


INSTALLED_VERSION_RE = re.compile(r"Installed version:[ \t]*([^\r\n]*)")


def installed_version(text: str) -> str:
    """'Installed version:' value of a result text (rest of that line), or ''."""
    match = INSTALLED_VERSION_RE.search(text or "")
    return match.group(1).strip() if match else ""


def level_of(cvss: float) -> str:
    """Severity level name of a CVSS score ('none' for 0 and below)."""
    return Config.cvss_level(cvss) or "none"


# Port object modifed to include result data field
class Port(object):
    """Port information"""

    def __init__(self, number:int, protocol:str="tcp", result:str="", cvss: float | None = None):
        """
        :param number: port number
        :type number: int

        :param protocol: port protocol (tcp, udp, ...)
        :type protocol: basestring

        :param result: port result
        :type result: str

        :param cvss: severity of the result on this port (None when unknown)
        :type cvss: float

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
        self.cvss = cvss

    # Modified to include result in structure
    @staticmethod
    def string2port(info:str, result:str, cvss: float | None = None):
        """
        Extract port number, protocol and description from an string.
        return a port class with seperate port, protocol and result.
        Strings without a port number (e.g. 'package') give number 0 and the
        string itself as protocol.

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

        :raises: TypeError
        """
        if not isinstance(info, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(info)))

        if not isinstance(result, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(result)))

        regex_nr = re.search(r"(\d+)/(\w+)", info)
        regex_general = re.search(r"general/([\w-]+)", info)

        if regex_nr:
            return Port(int(regex_nr.group(1)), regex_nr.group(2), result, cvss)
        if regex_general:
            return Port(0, regex_general.group(1), result, cvss)
        # non network "ports" such as 'package': keep the label as protocol, no number
        return Port(0, info.strip() or "unknown", result, cvss)

    def __eq__(self, other:'Port'):
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
        self.vuln_name: str = _text(nvt_tmp, "./name") or _text(vuln, "./name", "Unknown")
    
    

        # --------------------
        #
        # VULN_VERSION
        desc: str = _text(vuln, "./description")
        self.vuln_version = installed_version(desc)
            

        # --------------------
        #
        # VULN_ID
        self.vuln_id = nvt_tmp.get("oid")
        if not self.vuln_id or self.vuln_id == "0":
            raise ValueError("Expected valid <result> openvas xml element, got '{}' instead".format(vuln.text))
    
        # --------------------
        #
        # VULN_CVSS
        self.vuln_cvss = float(_text(vuln, "./severity", "0.0"))
    
        # --------------------
        #
        # VULN_LEVEL
        self.vuln_level = level_of(self.vuln_cvss)
    
        if self.vuln_level not in Config.min_levels()[min_level]:
            raise ValueError("Expected min_level in one of 'chmln', got '{}' instead".format(min_level))
    
        # --------------------
        #
        # VULN_HOST
        self.vuln_host: str = _text(vuln, "./host").strip()
        self.vuln_host_name: str = _text(vuln, "./host/hostname", "N/A")
        self.vuln_port: str = _text(vuln, "./port")
    
        # --------------------
        #
        # VULN_TAGS
        # Replace double newlines by a single newline
        # Collapse repeated newlines and useless whitespace, tolerate tags without '='
        self.vuln_tags = _parse_tags(_text(nvt_tmp, "./tags"))
    
        # --------------------
        #
        # VULN_THREAT
        self.vuln_threat: str = _text(vuln, "./threat", Config.levels()["n"]).lower()
    
    
        # --------------------
        #
        # VULN_FAMILY
        self.vuln_family: str = _text(nvt_tmp, "./family", "Unknown")
    
    
        # --------------------
        #
        # VULN_CVES
        #vuln_cves = nvt_tmp.findall("./refs/ref")
        self.vuln_cves:list[str] = []
        self.ref_list:list[str] = []
        for reference in nvt_tmp.findall('./refs/ref'):
            ref_id = reference.attrib.get('id')
            if not ref_id:
                continue
            if reference.attrib.get('type') == 'cve':
                self.vuln_cves.append(ref_id)
            else:
                self.ref_list.append(ref_id)
        # if vuln_cves is None or vuln_cves.text.lower() == "nocve":
        #     vuln_cves = []
        # else:
        #     vuln_cves = [vuln_cves.text.lower()]
        self.vuln_references = ' , '.join(self.ref_list)
        # --------------------
        #
        # VULN_REFERENCES
        # vuln_references = nvt_tmp.find("./xref")
        # if vuln_references is None or vuln_references.text.lower() == "noxref":
        #     vuln_references = []
        # else:
        #     vuln_references = vuln_references.text.lower().replace("url:", "\n")
    
    
        # --------------------
        #
        # VULN_DESCRIPTION
        # Replace runs of newlines by a single newline
        self.vuln_result: str = re.sub(r"(\r?\n)+", "\n", desc)
    

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
        nvt = vuln.find('./nvt')
        vuln_id = nvt.get('oid') if nvt is not None else None
        if not vuln_id or vuln_id == "0":
            return None
        host_ip = _text(vuln, './host').strip()
        if not host_ip:
            return None

        # is ip included and/or excluded? (a host name never matches a network)
        if config.networks_excluded is not None or config.networks_included is not None:
            try:
                host_ip_addr = netaddr.IPAddress(host_ip)
            except (netaddr.AddrFormatError, ValueError):
                host_ip_addr = None

        if config.networks_excluded is not None and host_ip_addr is not None:
            if any(host_ip_addr in ipline for ipline in config.networks_excluded):
                return None

        if config.networks_included is not None:
            if host_ip_addr is None or not any(host_ip_addr in ipline for ipline in config.networks_included):
                return None
            
        # check regex expressions inclusion and exclusion
        if config.regex_excluded is not None or config.regex_included is not None:
            vuln_name: str = _text(vuln, './name')
        
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
            cve_list:list[str] = []
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
        vuln_cvss = float(_text(vuln, './severity', '0.0'))
        if vuln_cvss >= Config.thresholds()[config.min_level]:
            return cls(vuln, config.min_level)
        
        return None 
      
class Host(object):
    """Host information"""

    def __init__(self, ip:str, host_name:str=""):
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
            raise TypeError("Expected ParseVulnerability, got '{}' instead".format(type(parsed_vuln)))

        port = Port.string2port(parsed_vuln.vuln_port, parsed_vuln.vuln_result, parsed_vuln.vuln_cvss)

        # same vulnerability (nvt-oid) already known for this host: record an extra port only once
        for v in self.vuln_list:
            if v.vuln_id == parsed_vuln.vuln_id:
                if not any(p.number == port.number and p.protocol == port.protocol for _, p in v.hosts):
                    old_level, old_cvss = v.level, v.cvss
                    v.add_vuln_host(self, port)
                    self.nv[old_level] -= 1
                    self.nv[v.level] += 1
                    self.sum_cvss += v.cvss - old_cvss
                    self.higher_cvss = max(self.higher_cvss, v.cvss)
                return

        v = Vulnerability(parsed_vuln.vuln_id,
                          name=parsed_vuln.vuln_name,
                          version=parsed_vuln.vuln_version,
                          threat=parsed_vuln.vuln_threat,
                          tags=parsed_vuln.vuln_tags,
                          cvss=parsed_vuln.vuln_cvss,
                          cves=parsed_vuln.vuln_cves,
                          references=parsed_vuln.vuln_references,
                          reference_list=parsed_vuln.ref_list,
                          family=parsed_vuln.vuln_family,
                          level=parsed_vuln.vuln_level)
        v.add_vuln_host(self, port)
        self.vuln_list.append(v)
        self.num_vulns += 1
        self.nv[v.level] += 1
        self.sum_cvss += v.cvss
        if v.cvss > self.higher_cvss:
            self.higher_cvss = v.cvss
    
    def nv_total(self):
        return self.nv['critical'] + self.nv['high'] + self.nv['medium'] + self.nv['low']
                   
    def __eq__(self, other:'Host'):
        return (
                isinstance(other, Host) and
                other.ip == self.ip and
                other.host_name == self.host_name
        )

class Vulnerability(object):
    """Vulnerability information"""

    def __init__(self, vuln_id:str, name:str, threat:str, **kwargs):
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

        :param references: references joined with ' , '
        :type references: str

        :param reference_list: the individual reference ids
        :type reference_list: list(str)

        :param family: Vulnerability family
        :type family: str

        :param result: Vulnerability result
        :type description: str

        :raises: TypeError, ValueError
        """
        # Get info
        cves: list[str] = kwargs.get("cves", list()) or list()
        cvss = kwargs.get("cvss")
        cvss = -1.0 if cvss is None else cvss
        level: str = kwargs.get("level", "None") or "None"
        tags: dict = kwargs.get("tags", dict()) or dict()
        references: str = kwargs.get("references", "Unknown") or "Unknown"
        family: str = kwargs.get("family", "Unknown") or "Unknown"
        result: str = kwargs.get("description", "Unknown") or "Unknown"

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
        
        
        self.vuln_id = vuln_id
        self.name = name
        self.cves = cves
        self.cvss = float(cvss)
        self.level = level
        self.description:str = tags.get('summary', '')
        self.detect:str = tags.get('vuldetect', '')
        self.insight:str = tags.get('insight', '')
        self.version:str = kwargs.get("version") or ''
        self.impact:str = tags.get('impact', '')
        self.affected:str = tags.get('affected', '')
        self.solution:str = tags.get('solution', '')
        self.solution_type:str = tags.get('solution_type', '')
        self.references = references
        self.reference_list: tuple[str, ...] = tuple(kwargs.get("reference_list") or ())
        self.threat = threat
        self.family = family
        self.result = result
        # Hosts
        self.hosts:list[tuple[Host, Port]] = []

    def add_vuln_host(self, host:Host, port:Port):
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
            # a vulnerability is as severe as its worst occurrence
            if port is not None and port.cvss is not None and port.cvss > self.cvss:
                self.cvss = port.cvss
                self.level = level_of(port.cvss)

    def __eq__(self, other:'Vulnerability'):
        if not isinstance(other, Vulnerability):
            return NotImplemented

        if (
                other.vuln_id != self.vuln_id or
                other.name != self.name or
                other.cves != self.cves or
                other.cvss != self.cvss or
                other.level != self.level or
                other.description != self.description or
                other.detect != self.detect or
                other.version != self.version or
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

        return self.hosts == other.hosts

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


    


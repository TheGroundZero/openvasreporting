# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

"""This file contains data structures"""

import re


class Port(object):
    """Port information"""

    def __init__(self, number, protocol="tcp"):
        """
        :param number: port number
        :type number: int

        :param protocol: port protocol (tcp, udp, ...)
        :type protocol: basestring

        :raises: TypeError, ValueError
        """
        if not isinstance(number, int):
            raise TypeError("Expected int, got '{}' instead".format(type(number)))
        else:
            if number < 0:
                raise ValueError("Port number must be greater than 0")

        if not isinstance(protocol, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(protocol)))

        self.number = number
        self.protocol = protocol

    @staticmethod
    def string2port(info):
        """
        Extract port number, protocol and description from an string.

        ..note:
            Raises value error if information can't be processed.

        # >>> p=Port.string2port("2000/tcp")
        # >>> print p.number
          2000
        # >>> print p.proto
          "tcp"

        # >>> p=Port.string2port("general/icmp")
        # >>> print p.number
          0
        # >>> print p.proto
          "icmp"

        :param info: raw string with port information
        :type info: basestring

        :return: Port instance
        :rtype: Port

        :raises: ValueError
        """
        if not isinstance(info, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(info)))

        regex_nr = re.search("([\d]+)(/)([\w]+)", info)
        regex_general = re.search("(general)(/)([\w]+)", info)

        if regex_nr and len(regex_nr.groups()) == 3:
            number = int(regex_nr.group(1))
            protocol = regex_nr.group(3)
        elif regex_general and len(regex_general.groups()) == 3:
            number = 0
            protocol = regex_general.group(3)
        else:
            raise ValueError("Can't parse input string")

        return Port(number, protocol)

    def __eq__(self, other):
        return (
                isinstance(other, Port) and
                other.number == self.number and
                other.protocol == self.protocol
        )


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

        :raises: TypeError, ValueError
        """
        # Get info
        cves = kwargs.get("cves", list()) or list()
        cvss = kwargs.get("cvss", -1.0) or -1.0
        level = kwargs.get("level", "None") or "None"
        tags = kwargs.get("tags", dict()) or dict()
        references = kwargs.get("references", list()) or list()
        family = kwargs.get("family", "Unknown") or "Unknown"

        if not isinstance(vuln_id, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(vuln_id)))
        if not isinstance(name, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(name)))
        if not isinstance(threat, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(threat)))
        if not isinstance(family, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(family)))
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
        if not isinstance(references, list):
            raise TypeError("Expected list, got '{}' instead".format(type(references)))
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
                other.family != self.family
        ):
            return False

        for host, port in self.hosts:
            for o_host, o_port in other.hosts:
                if o_host != host or o_port != port:
                    return False

        return True

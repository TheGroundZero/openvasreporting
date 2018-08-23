# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvas_to_report

"""This file contains data structures"""

import re


class Port(object):
    """Port information"""

    def __init__(self, number, protocol="tcp", description=""):
        """
        :param number: port number
        :type number: int

        :param protocol: port protocol (tcp, udp, ...)
        :type protocol: basestring

        :param description: port description
        :type description: basestring

        :raises: TypeError, ValueError
        """
        if not isinstance(number, int):
            raise TypeError("Expected int, got '{}' instead".format(type(number)))
        else:
            if number < 0:
                raise ValueError("Port number must be greater than 0")

        if not isinstance(protocol, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(protocol)))

        if not isinstance(description, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(description)))

        self.number = number
        self.protocol = protocol
        self.description = description

    @staticmethod
    def string2port(info):
        """
        Extract port number, protocol and description from an string.

        ..note:
            Raises value error if information can't be processed.

        # >>> p=Port.string2port("callbook (2000/tcp)")
        # >>> print p.number
          2000
        # >>> print p.desc
          "callbook"
        # >>> print p.proto
          "tcp"

        :param info: raw string with port information
        :type info: basestring

        :return: Port instance
        :rtype: Port

        :raises: ValueError
        """
        if not isinstance(info, str):
            raise TypeError("Expected basestring, got '{}' instead".format(type(info)))

        regex = re.search("([\w\W]+)(\()([\d]+)(/)([\w]+)", info)

        if regex:
            if len(regex.groups()) != 5:
                raise ValueError("Can't parse input string")

            description = regex.group(1).strip()
            number = int(regex.group(3))
            protocol = regex.group(5)

            return Port(number, protocol, description)

        else:
            raise ValueError("Can't parse input string")

    def __eq__(self, other):
        if not isinstance(other, Port):
            return False

        if other.number != self.number:
            return False
        if other.protocol != self.protocol:
            return False
        if other.description != self.description:
            return False

        return True


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
        if not isinstance(other, Host):
            return False

        if other.ip != self.ip:
            return False
        if other.host_name != self.host_name:
            return False

        return True


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

        :param description: vulnerability description
        :type description: basestring

        :param references: list of references
        :type references: list(str)

        :param family: Vulnerability family
        :type family: str

        :raises: TypeError, ValueError
        """
        # Get info
        cves = kwargs.get("cves", list()) or list()
        cvss = kwargs.get("cvss", -1.0)
        level = kwargs.get("level", "Low")
        description = kwargs.get("description", "")
        references = kwargs.get("references", list()) or list()
        family = kwargs.get("family", "unknown") or "unknown"

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
        if description is not None:
            if not isinstance(description, str):
                raise TypeError("Expected basestring, got '{}' instead".format(type(description)))
        else:
            description = name

        if not isinstance(references, list):
            raise TypeError("Expected list, got '{}' instead".format(type(references)))
        else:
            for x in references:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '{}' instead".format(type(x)))

        description = re.sub("([\n\r]*[\s]*[Ss]ummary[:]*[\n\r\s]*)", "", description)
        description = re.sub("[\w][\r\n][\w]", "", description)

        self.vuln_id = vuln_id
        self.name = name
        self.cves = cves
        self.cvss = float(cvss)
        self.level = level
        self.description = description
        self.references = references
        self.threat = threat
        self.family = family

        # Hosts
        self.hosts = []

    def add_host(self, host, port):
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

        if other.cves != self.cves:
            return False
        if other.threat != self.threat:
            return False
        if other.name != self.name:
            return False
        if other.cvss != self.cvss:
            return False
        if other.description != self.description:
            return False
        if other.vuln_id != self.vuln_id:
            return False
        if other.level != self.level:
            return False
        if other.references != self.references:
            return False

        for host, port in self.hosts:
            for o_host, o_port in other.hosts:
                if o_host == host and o_port == port:
                    break
            else:
                return False

        return True

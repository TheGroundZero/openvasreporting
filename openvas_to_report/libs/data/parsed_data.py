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

"""This file contains data structures"""

import re


# --------------------------------------------------------------------------
class Port(object):
    """Port information"""

    # ----------------------------------------------------------------------
    def __init__(self, number, protocol="tcp", description=""):
        """
        :param number: port number
        :type number: int

        :param protocol: port protocol: tcp, udp...
        :type protocol: basestring

        :param description: port description
        :type description: basestring

        :raises: TypeError, ValueError
        """
        if not isinstance(number, int):
            raise TypeError("Expected int, got '%s' instead" % type(number))
        else:
            if number < 0:
                raise ValueError("Port number must be greater than 0")
        if not isinstance(protocol, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(protocol))
        if not isinstance(description, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(description))

        self.number = number
        self.description = description
        self.protocol = protocol
    

    # ----------------------------------------------------------------------
    @staticmethod
    def string2port(info):
        """
        Extract port number, protocol and description from an string.

        ..note:
            Raises value error if information can't be processed.

        >>> p=Port.string2port("callbook (2000/tcp)")
        >>> print p.number
        2000
        >>> print p.description
        "callbook"
        >>> print p.protocol
        "tcp"
        
        :param info: raw string with port information 
        :type info: basestring

        :return: Port instance
        :rtype: Port

        :raises: ValueError
        """
        if not isinstance(info, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(info))
        
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

    # ----------------------------------------------------------------------
    def __eq__(self, other):
        if not isinstance(other, Port):
            return False

        if other.number != self.number:
            return False
        if other.description != self.description:
            return False
        if other.protocol != self.protocol:
            return False

        return True


# --------------------------------------------------------------------------
class Host(object):
    """Host information"""

    # ----------------------------------------------------------------------
    def __init__(self, ip, host_name=""):
        """
        :param ip: Host ip 
        :type ip: basestring
        
        :param host_name: Host name 
        :type host_name: basestring
        
        :raises: TypeError
        """
        if not isinstance(ip, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(ip))
        if not isinstance(host_name, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(host_name))

        self.ip = ip
        self.host_name = host_name

    # ----------------------------------------------------------------------
    def __eq__(self, other):
        if not isinstance(other, Host):
            return False

        if other.ip != self.ip:
            return False
        if other.host_name != self.host_name:
            return False

        return True


# --------------------------------------------------------------------------
class Vulnerability(object):
    """Vulnerability information"""

    # ----------------------------------------------------------------------
    def __init__(self, id, name, threat, **kwargs):
        """
        :param id: OpenVas plugin ID
        :type id: basestring

        :param name: Vulnerability name
        :type name: str
        
        :param threat: threat type: Log, Low, Middle...
        :type threat: str
        
        :param cves: list of CVEs
        :type cves: list(str)
        
        :param cvss: CVSS number value 
        :type cvss: float
        
        :param description: vulnerability description 
        :type description: basestring
        
        :param references: list of references 
        :type references: list(str)
        
        :param level: vulnerability level, as text: log, info, low... 
        :type level: basestring

        :param family: Vulnerability family
        :type family: str

        :raises: TypeError, ValueError
        """
        # Get info
        cves = kwargs.get("cves", [])
        cvss = kwargs.get("cvss", -1.0)
        description = kwargs.get("description", "")
        references = kwargs.get("references", [])
        level = kwargs.get("level", "low")
        family = kwargs.get("family", "unknown")

        if not isinstance(id, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(id))
        if not isinstance(name, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(name))
        if not isinstance(threat, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(threat))
        if not isinstance(family, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(family))
        if not isinstance(cves, list):
            raise TypeError("Expected list, got '%s' instead" % type(cves))
        else:
            for x in cves:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '%s' instead" % type(x))

        if not isinstance(cvss, (float, int)):
            raise TypeError("Expected float, got '%s' instead" % type(cvss))
        if description is not None:
            if not isinstance(description, str):
                raise TypeError("Expected basestring, got '%s' instead" % type(description))
        else:
            description = name

        if not isinstance(references, list):
            raise TypeError("Expected list, got '%s' instead" % type(references))
        else:
            for x in references:
                if not isinstance(x, str):
                    raise TypeError("Expected basestring, got '%s' instead" % type(x))

        if not isinstance(level, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(level))

        # --------------------------------------------------------------------------
        # Adjust description
        # --------------------------------------------------------------------------
        # Adjust text
        description = re.sub("([\n\r]*[\s]*[Ss]ummary[:]*[\n\r\s]*)", "", description)
        description = re.sub("[\w][\r\n][\w]", "", description)

        self.id = id
        self.name = name
        self.cves = cves
        self.cvss = float(cvss)
        self.description = description
        self.references = references
        self.level = level
        self.threat = threat
        self.family = family

        # Hosts
        self.hosts = []

    # ----------------------------------------------------------------------
    def add_host(self, host, port):
        """
        Add a host and port associated to this vulnerability.
        
        :param host: Host instance 
        :type host: Host
        
        :param port: Port instance 
        :type port: Port
        
        :raises: TypeError
        """
        if not isinstance(host, Host):
            raise TypeError("Expected Host, got '%s' instead" % type(host))
        if port is not None:
            if not isinstance(port, Port):
                raise TypeError("Expected Port, got '%s' instead" % type(port))

        self.hosts.append((host, port))

    # ----------------------------------------------------------------------
    def __eq__(self, other):
        if not isinstance(other, Vulnerability):
            raise TypeError("Expected Vulnerability, got '%s' instead" % type(other))

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
        if other.id != self.id:
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
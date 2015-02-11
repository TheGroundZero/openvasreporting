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

import os
import pytest

from ..libs.data.parsed_data import Vulnerability, Host, Port
from ..libs.parsers.openvas_parser import openvas_parser


W_FILE = "openvas_results_tmp.xml"
W_PATH = os.path.abspath(os.path.join(os.getcwd(), W_FILE))


# ----------------------------------------------------------------------
def _create_bad_file():
    """creates bad tmp file"""
    content = '''content_type="text/xml" extension="xml" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" id="62a6b03b-345f-4ef0-8ab2-820b70ddaa13" type="scan">'''

    with open(W_PATH, "w") as f:
        f.write(content)


# ----------------------------------------------------------------------
def _create_xml_file():
    """creates tmp file"""
    content = (
        '<report content_type="text/xml" extension="xml" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"'
        'id="62a6b03b-345f-4ef0-8ab2-820b70ddaa13" type="scan">\n'
        '\t<report id="62a6b03b-345f-4ef0-8ab2-820b70ddaa13">\n'
        '\t\t<report_format/>\n'
        '\t\t<sort>\n'
        '\t\t\t<field>type\n'
        '\t\t\t\t<order>descending</order></field>\n'
        '\t\t</sort>\n'
        '\t\t<filters id="0">hmlgf\n'
        '\t\t\t<term>sort-reverse=type result_hosts_only=1 min_cvss_base= levels=hmlgf autofp=0 show_closed_cves=0'
        'notes=1 overrides=1 first=1 rows=9319 delta_states=gn</term>\n'
        '\t\t\t<phrase/>\n'
        '\t\t\t<autofp>0</autofp>\n'
        '\t\t\t<show_closed_cves>0</show_closed_cves>\n'
        '\t\t\t<notes>1</notes>\n'
        '\t\t\t<overrides>1</overrides>\n'
        '\t\t\t<apply_overrides>1</apply_overrides>\n'
        '\t\t\t<result_hosts_only>1</result_hosts_only>\n'
        '\t\t\t<min_cvss_base/>\n'
        '\t\t\t<filter>High</filter>\n'
        '\t\t\t<filter>Medium</filter>\n'
        '\t\t\t<filter>Low</filter>\n'
        '\t\t\t<filter>Log</filter>\n'
        '\t\t\t<filter>False Positive</filter></filters>\n'
        '\t\t<scan_run_status>Done</scan_run_status>\n'
        '\t\t<task id="914f1567-2e07-4068-ad87-2d46e9fd5624">\n'
        '\t\t\t<name>MEXIS_All_Internal_IPs_172</name>\n'
        '\t\t\t<comment/>\n'
        '\t\t\t<target id="a0d0357a-2a81-4557-bf7f-37df8aed9a38">\n'
        '\t\t\t\t<trash>0</trash>\n'
        '\t\t\t</target>\n'
        '\t\t</task>\n'
        '\t\t<scan_start>2014-04-04T02:13:51Z</scan_start>\n'
        '\t\t<ports max="9319" start="1">\n'
        '\t\t\t<port>X11:1 (6001/tcp)\n'
        '\t\t\t\t<host>172.100.0.1</host>\n'
        '\t\t\t\t<threat>Low</threat></port>\n'
        '\t\t\t<port>X11:2 (6002/tcp)\n'
        '\t\t\t\t<host>172.100.0.1</host>\n'
        '\t\t\t\t<threat>Low</threat></port>\n'
        '\t\t\t<port>dc (2001/tcp)\n'
        '\t\t\t\t<host>172.100.0.1</host>\n'
        '\t\t\t\t<threat>Low</threat></port>\n'
        '\t\t</ports>\n'
        '\t\t<results max="9319" start="1">\n'
        '\t\t\t<result id="b976a6ea-3a45-467b-8ac4-fdf9850f737d">\n'
        '\t\t\t\t<subnet>172.21.1.1</subnet>\n'
        '\t\t\t\t<host>172.21.1.1</host>\n'
        '\t\t\t\t<port>X11:1 (6001/tcp)</port>\n'
        '\t\t\t\t<nvt oid="1.3.6.1.4.1.25623.1.0.10919">\n'
        '\t\t\t\t\t<name>Check open ports</name>\n'
        '\t\t\t\t\t<family>General</family>\n'
        '\t\t\t\t\t<cvss_base>0.0</cvss_base>\n'
        '\t\t\t\t\t<risk_factor>Low</risk_factor>\n'
        '\t\t\t\t\t<cve>NOCVE</cve>\n'
        '\t\t\t\t\t<bid>NOBID</bid>\n'
        '\t\t\t\t\t<tags>cvss_base_vector=AV:N/AC:L/Au:N/C:N/I:N/A:N|summary=This plugin checks if the port scanners '
        'did not kill a service.</tags>\n'
        '\t\t\t\t\t<cert>\n'
        '\t\t\t\t\t\t<warning>database not available</warning>\n'
        '\t\t\t\t\t</cert>\n'
        '\t\t\t\t\t<xref>NOXREF</xref>\n'
        '\t\t\t\t</nvt>\n'
        '\t\t\t\t<threat>Low</threat>\n'
        '\t\t\t\t<description>This port was detected as being open by a port scanner but is now closed.\n'
        'This service might have been crashed by a port scanner or by a plugin\n'
        '\n'
        '</description>\n'
        '\t\t\t\t<original_threat>Low</original_threat>\n'
        '\t\t\t\t<notes/>\n'
        '\t\t\t\t<overrides/>\n'
        '\t\t\t\t</result>\n'
        '\t\t    </results>\n'
        '\t\t</report>\n'
        '</report>'
    )

    with open(W_FILE, "w") as f:
        f.write(content)


# ----------------------------------------------------------------------
def _delete_xml_file():
    """destroy tmp file"""
    os.remove(W_FILE)


# --------------------------------------------------------------------------
# openvas_parser test
# --------------------------------------------------------------------------
class TestOpenvasParser:
    # ----------------------------------------------------------------------
    def test_types(self):
        pytest.raises(TypeError, openvas_parser, None)
        pytest.raises(TypeError, openvas_parser, 0)
        pytest.raises(TypeError, openvas_parser, "")
        pytest.raises(TypeError, openvas_parser, [1])
        pytest.raises(TypeError, openvas_parser, dict())

        pytest.raises(TypeError, openvas_parser, "hello", excluded_hosts="")
        pytest.raises(TypeError, openvas_parser, "hello", excluded_hosts=[0])

        pytest.raises(TypeError, openvas_parser, "hello", scope_hosts="")
        pytest.raises(TypeError, openvas_parser, "hello", scope_hosts=[0])

    # ----------------------------------------------------------------------
    def test_file_format(self):
        _create_bad_file()

        pytest.raises(IOError, openvas_parser, [W_PATH])

        _delete_xml_file()

    # ----------------------------------------------------------------------
    def test_file_results_format(self):
        _create_xml_file()

        assert isinstance(openvas_parser([W_PATH]), list)

        _delete_xml_file()

    # ----------------------------------------------------------------------
    def test_eq_operation(self):
        _create_xml_file()

        # Call for results
        results = openvas_parser([W_PATH])

        # Create objects manually
        host = Host("172.21.1.1")
        port = Port(6001, "tcp", "X11:1")
        vuln = Vulnerability("10919",
                             name="Check open ports",
                             threat="Low",
                             cvss=0.0,
                             level="Low",
                             cves=[],
                             references=[],
                             description="""This port was detected as being open by a port scanner but is now closed.
This service might have been crashed by a port scanner or by a plugin

""")
        vuln.add_host(host, port)

        assert len(results) == 1
        assert results == [vuln]

        _delete_xml_file()

    # ----------------------------------------------------------------------
    def test_results(self):
        _create_xml_file()

        # Call for results
        vuln1 = openvas_parser([W_PATH])[0]

        # Create objects manually
        host = Host("172.21.1.1")
        port = Port(6001, "tcp", "X11:1")
        vuln2 = Vulnerability("10919",
                              name="vuln name",
                              threat="Low",
                              cvss=0.0,
                              level="Low",
                              cves=[],
                              references=[],
                              description="""This port was detected as being open by a port scanner but is now closed.
This service might have been crashed by a port scanner or by a plugin

""")
        vuln2.add_host(host, port)

        assert vuln2.cvss == vuln1.cvss
        assert vuln2.level == vuln1.level
        assert vuln2.cves == vuln1.cves
        assert vuln2.id == vuln1.id
        assert vuln2.references == vuln1.references
        assert vuln2.description == vuln1.description
        for host, port in vuln2.hosts:
            for o_host, o_port in vuln1.hosts:
                assert o_host.ip == host.ip
                assert o_host.host_name == host.host_name
                assert o_port.description == port.description
                assert o_port.number == port.number
                assert o_port.protocol == port.protocol

        # assert isinstance(, list)

        _delete_xml_file()
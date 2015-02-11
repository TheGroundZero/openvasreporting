#!/usr/bin/python
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

import pytest

from ..libs.data.parsed_data import Port, Host, Vulnerability


# --------------------------------------------------------------------------
# Port test
# --------------------------------------------------------------------------
class TestPortData:

    # ----------------------------------------------------------------------
    def test_types(self):

        # Port number
        pytest.raises(TypeError, Port, None)
        pytest.raises(TypeError, Port, "")
        pytest.raises(TypeError, Port, [])
        pytest.raises(TypeError, Port, dict())

        # Port protocol
        pytest.raises(TypeError, Port, 1, None)
        pytest.raises(TypeError, Port, 1, [])
        pytest.raises(TypeError, Port, 1, {})

        # Port description
        pytest.raises(TypeError, Port, 1, "tcp", None)
        pytest.raises(TypeError, Port, 1, "tcp", 0)
        pytest.raises(TypeError, Port, 1, "tcp", [])

    # ----------------------------------------------------------------------
    def test_port_number(self):
        pytest.raises(ValueError, Port, -1)

    # --------------------------------------------------------------------------
    # string2port tests
    # ----------------------------------------------------------------------
    def test_string2port_types(self):
        pytest.raises(TypeError, Port.string2port, None)

    # ----------------------------------------------------------------------
    def test_string2port_invalid_input(self):
        pytest.raises(ValueError, Port.string2port, "callbook (2000")

    # ----------------------------------------------------------------------
    def test_string2port_valid_input(self):
        port = Port(2000, "tcp", "callbook")

        parsed_port = Port.string2port("callbook (2000/tcp)")
        assert parsed_port.number == 2000
        assert parsed_port.description == "callbook"
        assert parsed_port.protocol == "tcp"

        assert Port.string2port("callbook (2000/tcp)") == port


# --------------------------------------------------------------------------
# Host test
# --------------------------------------------------------------------------
class TestHost:

    # ----------------------------------------------------------------------
    def test_types(self):
        pytest.raises(TypeError, Host, None)
        pytest.raises(TypeError, Host, 0)
        pytest.raises(TypeError, Host, [])
        pytest.raises(TypeError, Host, dict())

        pytest.raises(TypeError, Host, "", None)
        pytest.raises(TypeError, Host, "", 0)
        pytest.raises(TypeError, Host, "", [])
        pytest.raises(TypeError, Host, "", dict())


# --------------------------------------------------------------------------
# Vulnerability test
# --------------------------------------------------------------------------
class TestVulnerability:

    # ----------------------------------------------------------------------
    def test_types(self):
        pytest.raises(TypeError, Vulnerability, None, "", "")
        pytest.raises(TypeError, Vulnerability, "", None, "")
        pytest.raises(TypeError, Vulnerability, "", "", None)

        pytest.raises(TypeError, Vulnerability, "", "", "", cves=None)
        pytest.raises(TypeError, Vulnerability, "", "", "", cves=[1])

        pytest.raises(TypeError, Vulnerability, "", "", "", cvss=None)

        pytest.raises(TypeError, Vulnerability, "", "", "", description=1)

        pytest.raises(TypeError, Vulnerability, "", "", "", references=None)
        pytest.raises(TypeError, Vulnerability, "", "", "", references=[1])

        pytest.raises(TypeError, Vulnerability, "", "", "", level=0)
        pytest.raises(TypeError, Vulnerability, "", "", "", level=None)

    # ----------------------------------------------------------------------
    # add_host tests
    # ----------------------------------------------------------------------
    def test_add_host_types(self):
        vuln = Vulnerability("10101", "Vuln name", "Low")

        pytest.raises(TypeError, vuln.add_host, None)

    # ----------------------------------------------------------------------
    def test_add_hosts_correct_inputs(self):
        host = Host("127.0.0.1")
        port = Port(80)

        vuln = Vulnerability("1111", "vuln name", "Low")
        vuln.add_host(host, port)

        assert vuln.hosts == [(host, port)]
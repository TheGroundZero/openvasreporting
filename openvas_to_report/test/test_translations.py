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
import json
import pytest

from ..libs.translations import loader

W_PATH = os.path.abspath(os.path.join(os.getcwd(), "text_file.json"))

# ----------------------------------------------------------------------
@pytest.fixture
def create_file():
    info = {
        "title": "Titulo",
        "description": "Description",
        "ip": "IP",
        "Host name": "Host name",
        "Port number": "Port number",
        "Port protocol": "Port protocol",
        "Port description": "Port description",
        "No port info": "No port info"
    }
    json.dump(info, open(W_PATH, "w"))


# ----------------------------------------------------------------------
def remove_file():
    try:
        os.remove(W_PATH)
    except IOError:
        pass


# --------------------------------------------------------------------------
# loader test
# --------------------------------------------------------------------------
class TestLoader:

    # ----------------------------------------------------------------------
    def test_types(self):
        pytest.raises(TypeError, loader, None)
        pytest.raises(TypeError, loader, 0)

    # ----------------------------------------------------------------------
    def test_empty_input(self):
        pytest.raises(ValueError, loader, "")

    # ----------------------------------------------------------------------
    def test_return_type(self,create_file):
        assert isinstance(loader(W_PATH), dict)
        
        remove_file()
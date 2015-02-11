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


# --------------------------------------------------------------------------
class Config(object):
    """Program configuration"""

    # ----------------------------------------------------------------------
    def __init__(self, input_files, output_file, template=None, lang="en", excluded=None, scope=None):
        """
        :param input_files: input file path
        :type input_files: list(str)

        :param output_file: output file path and name
        :type output_file: str

        :param template: path to template
        :type template: str

        :param lang: language
        :type lang: str

        :param excluded: path to file with excluded hosts.
        :type excluded: str

        :param scope: path to file with scope hosts
        :type scope: str

        :raises: TypeError, ValueError
        """
        if not isinstance(input_files, list):
            raise TypeError("Expected list, got '%s' instead" % type(input_files))
        else:
            for i in input_files:
                if not isinstance(i, str):
                    raise TypeError("Expected basestring, got '%s' instead" % type(i))

        if not isinstance(output_file, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(output_file))
        if template is not None:
            if not isinstance(template, str):
                raise TypeError("Expected basestring, got '%s' instead" % type(template))
        if not isinstance(lang, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(lang))
        if excluded is not None:
            if not isinstance(excluded, str):
                raise TypeError("Expected basestring, got '%s' instead" % type(excluded))
        if scope is not None:
            if not isinstance(scope, str):
                raise TypeError("Expected basestring, got '%s' instead" % type(scope))

        self.input_files = input_files
        self.output_file = output_file
        self.template = template
        self.lang = lang
        self.excluded = excluded
        self.scope = scope
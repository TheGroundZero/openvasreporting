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

__all__ = ["get_translation_path", "loader"]


# ----------------------------------------------------------------------
def get_translation_path(export_format, lang):
    """
    Return the translation path from selected lang.

    >>> print get_translation_path("excel", "en")
    /home/Me/tests/libs/excel/en.json

    :param export_format: type of exporter
    :type export_format: str
    
    :param lang: language
    :type lang: str
    
    :return: path to translation file.
    :rtype: str

    :raises: TypeError, ValueError
    """
    if not isinstance(export_format, str):
        raise TypeError("Expected basestring, got '%s' instead" % type(export_format))
    if not isinstance(lang, str):
        raise TypeError("Expected basestring, got '%s' instead" % type(lang))

    # Filter for security issues
    if any(True for x in ("/", "\\", ".") if x in export_format or x in lang):
        raise ValueError("'.' character is not allowed.")

    if export_format.lower() not in ("excel", "word"):
        raise ValueError("Export format not available")

    module_path = os.sep.join((__file__.split(os.sep)[0:-1]))

    return os.path.join(module_path, export_format, "%s.json" % lang)
    

# ----------------------------------------------------------------------
def loader(filename):
    """
    Load translation from file and return a dictionary with info.
    
    :param filename: filename info 
    :type filename: str
    
    :return: dict object.
    :rtype: dict

    :raises: TypeError, ValueError
    """
    if not isinstance(filename, str):
        raise TypeError("Expected basestring, got '%s' instead" % type(filename))
    if filename == "":
        raise ValueError("Empty filename got.")

    return json.load(open(filename, "rU"))
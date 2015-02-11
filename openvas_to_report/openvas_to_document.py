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


import argparse


# ----------------------------------------------------------------------
def main():

    from .api import convert, Config

    # extensions = ("docx", "xlsx")
    extensions = ("xlsx",)

    parser = argparse.ArgumentParser(description='OpenVAS to Excel converter')
    parser.add_argument('-i', '--openvas-file', nargs="*", dest="openvas_files", help="input openvas XML file", required=True)
    parser.add_argument('-o', '--output-file', dest="output_file", help="output .xlsx file, with extension",
                        required=True)
    parser.add_argument('--template', dest="template", help="template to use", default=None)
    parser.add_argument('--lang', dest="lang", help="language to use", default="es")
    parser.add_argument('--excluded-hosts', dest="excluded_hosts", help="path to file with hosts to exclude", default=None)
    parser.add_argument('--scope-hosts', dest="scope_hosts", help="path to file with scope hosts", default=None)

    args = parser.parse_args()

    if args.output_file.split(".")[-1] not in extensions:
        print("\n\t[!] Invalid output file extension. Valid extensions are: %s\n" % ", ".join(extensions))
        exit(1)

    config = Config(args.openvas_files,
                    args.output_file,
                    args.template,
                    args.lang,
                    args.excluded_hosts,
                    args.scope_hosts)

    convert(config)


if __name__ == "__main__" and __package__ is None:
    # --------------------------------------------------------------------------
    #
    # INTERNAL USE: DO NOT MODIFY THIS SECTION!!!!!
    #
    # --------------------------------------------------------------------------
    import sys
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(1, parent_dir)
    import openvas_to_report
    __package__ = str("openvas_to_report")
    del sys, os

    main()

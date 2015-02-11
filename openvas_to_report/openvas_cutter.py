#!/usr/bin/python
# -*- coding: utf-8 -*-
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

    from .api import crop, Config

    parser = argparse.ArgumentParser(description='Filter OpenVAS XML files.')
    parser.add_argument('-i', '--openvas-file', dest="openvas_files", help="openvas XML file", required=True)
    parser.add_argument('-o', '--output-file', dest="output_file", help="filtered openvas XML file", required=True)
    parser.add_argument('--exclude-hosts', dest="excluded_hosts", help="path to file with hosts to exclude", default=None)
    parser.add_argument('--scope-hosts', dest="scope_hosts", help="path to file with scope hosts", default=None)

    args = parser.parse_args()

    # Check restrictions
    if args.scope_hosts is not None and args.excluded_hosts is not None:
        raise ValueError("Scope and excluded can't be set simultaneously")

    if args.excluded_hosts:
        excluded_hosts = [x.strip().replace("\n", "").replace("\t", "").replace("\r", "") for x in open(args.excluded_hosts, "rU").readlines()]
    else:
        excluded_hosts = None

    if args.scope_hosts:
        scope_hosts = [x.strip().replace("\n", "").replace("\t", "").replace("\r", "") for x in open(args.scope_hosts, "rU").readlines()]
    else:
        scope_hosts = None

    config = Config(args.openvas_files,
                    args.output_file,
                    args.template,
                    args.lang,
                    excluded_hosts,
                    scope_hosts)

    crop(config)


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

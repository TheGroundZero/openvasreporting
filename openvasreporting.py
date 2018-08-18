# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvas_to_report

import argparse

from libs.config import Config
from libs.export import export_to_excel
from libs.parser import openvas_parser


def main():
    parser = argparse.ArgumentParser(description="OpenVAS to Excel converter")
    parser.add_argument('-i', '--input', nargs="*", dest="input_files", help="OpenVAS XML reports", required=True)
    parser.add_argument('-o', '--output', dest="output_file", help="Output .xslx file, no extension", required=True)
    parser.add_argument('-l', '--level', dest="min_level", help="Minimal level (c, h, m, l, n)",
                        required=False, default='n')

    args = parser.parse_args()

    if args.output_file.split(".")[-1] != "xlsx":
        args.output_file = args.output_file + ".xlsx"

    min_lvl = args.min_level.lower()[0]

    if min_lvl in Config.levels().keys():
        min_lvl = Config.levels()[min_lvl]
    else:
        raise ValueError("Invalid value for level parameter, \
        must be one of: c[ritical], h[igh], m[edium], l[low], n[one]")

    config = Config(args.input_files, args.output_file, min_lvl)

    convert(config)


def convert(config):
    """
    Convert the OpenVAS XML to an Excel file

    :param config: configuration
    :type config: Config

    :raises: TypeError, ValueError, IOError
    """
    if not isinstance(config, Config):
        raise TypeError("Expected Config, got '{}' instead".format(type(config)))

    openvas_info = openvas_parser(config.input_files, config.min_level)

    export_to_excel(openvas_info, config.output_file)


if __name__ == "__main__" and __package__ is None:
    import sys
    import os

    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(1, parent_dir)
    import openvasreporting

    __package__ = str("openvasreporting")
    del sys, os

    main()

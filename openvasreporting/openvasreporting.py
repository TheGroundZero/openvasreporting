# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvas_to_report

import argparse

from .libs.config import Config
from .libs.parser import openvas_parser
from .libs.export import exporters


def main():
    parser = argparse.ArgumentParser(
        prog="openvasreporting",  # TODO figure out why I need this in my code for -h to show correct name
        description="OpenVAS report converter",
        allow_abbrev=True
    )
    parser.add_argument("-i", "--input", nargs="*", dest="input_files", help="OpenVAS XML reports", required=True)
    parser.add_argument("-o", "--output", dest="output_file", help="Output file, no extension", required=False,
                        default="openvas_report")
    parser.add_argument("-l", "--level", dest="min_level", help="Minimal level (c, h, m, l, n)", required=False,
                        default="n")
    parser.add_argument("-f", "--format", dest="filetype", help="Output format (xlsx)", required=False, default="xlsx")

    args = parser.parse_args()

    min_lvl = args.min_level.lower()[0]

    if min_lvl in Config.levels().keys():
        min_lvl = Config.levels()[min_lvl]
    else:
        raise ValueError("Invalid value for level parameter, \
        must be one of: c[ritical], h[igh], m[edium], l[low], n[one]")

    if args.filetype not in exporters().keys():
        raise ValueError("Filetype not supported, got {}, expecting one of {}".format(args.filetype,
                                                                                      exporters().keys()))

    config = Config(args.input_files, args.output_file, min_lvl, args.filetype)

    convert(config)


def convert(config):
    """
    Convert the OpenVAS XML to requested filetype

    :param config: configuration
    :type config: Config

    :raises: TypeError, ValueError, IOError, NotImplementedError
    """
    if not isinstance(config, Config):
        raise TypeError("Expected Config, got '{}' instead".format(type(config)))

    if config.filetype not in exporters().keys():
        raise NotImplementedError("Filetype not supported, got {}, expecting one of {}".format(config.filetype,
                                                                                               exporters().keys()))

    openvas_info = openvas_parser(config.input_files, config.min_level)

    exporters()[config.filetype](openvas_info, config.output_file)

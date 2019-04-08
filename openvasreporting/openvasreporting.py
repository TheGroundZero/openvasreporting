# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvasreporting

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
    parser.add_argument("-l", "--level", dest="min_lvl", help="Minimal level (c, h, m, l, n)", required=False,
                        default="none")
    parser.add_argument("-f", "--format", dest="filetype", help="Output format (xlsx)", required=False, default="xlsx")
    parser.add_argument("-t", "--template", dest="template", help="Template file for docx export", required=False)

    args = parser.parse_args()

    config = create_config(args.input_files, args.output_file, args.min_lvl, args.filetype, args.template)

    convert(config)


def create_config(input_files, output_file="openvas_report", min_lvl="none", filetype="xlsx", template=None):
    """
    Create config file to be used by converter.

    :param input_files: input XML file(s) to be converted
    :type input_files: list(str)

    :param output_file: output filename for report
    :type output_file: str

    :param min_lvl: minimal threat level to be included in the report
    :type min_lvl: str

    :param filetype: filetype of the output file
    :type filetype: str

    :param template: template to be used in case of export to docx filetype
    :type template: str

    :raises: ValueError

    :return: config file to be passed to converter
    :rtype: Config
    """

    min_lvl = check_level(min_lvl.lower()[0])

    check_filetype(filetype)

    if template is not None:
        return Config(input_files, output_file, min_lvl, filetype, template)
    else:
        return Config(input_files, output_file, min_lvl, filetype)


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

    exporters()[config.filetype](openvas_info, config.template, config.output_file)


def check_level(min_lvl):
    """
    Check if min_lvl is a correct level

    :param min_lvl: min_lvl
    :return: min_lvl

    :raises: ValueError
    """
    if min_lvl in Config.levels().keys():
        return Config.levels()[min_lvl]
    else:
        raise ValueError("Invalid value for level parameter, \
            must be one of: c[ritical], h[igh], m[edium], l[low], n[one]")


def check_filetype(filetype):
    """
    Check if filetype is a correct filetype

    :param filetype: filetype
    :return:

    :raises: ValueError
    """
    if filetype not in exporters().keys():
        raise ValueError("Filetype not supported, got {}, expecting one of {}".format(filetype,
                                                                                      exporters().keys()))

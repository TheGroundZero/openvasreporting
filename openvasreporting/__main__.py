# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvas_to_report
from openvasreporting.openvasreporting import main

__author__ = 'TheGroundZero (https://github.com/TheGroundZero)'

if __name__ == '__main__':
    if __package__ is None:
        from os import sys, path

        sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
        del sys, path

    main()

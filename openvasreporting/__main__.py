# -*- coding: utf-8 -*-
#
#
# Project name: OpenVAS Reporting: A tool to convert OpenVAS XML reports into Excel files.
# Project URL: https://github.com/TheGroundZero/openvas_to_report
from openvasreporting.openvasreporting import main

__author__ = 'TheGroundZero (https://github.com/TheGroundZero)'

if __name__ == "__main__":
    if __package__ is None:
        import sys
        import os

        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(1, parent_dir)

        del sys, os

    main()

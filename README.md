# OpenVAS Reporting:  

[![GitHub version](https://badge.fury.io/gh/TheGroundZero%2Fopenvasreporting.svg)](https://badge.fury.io/gh/TheGroundZero%2Fopenvasreporting)
[![License](https://img.shields.io/github/license/TheGroundZero/openvasreporting.svg)](https://github.com/TheGroundZero/openvasreporting/blob/master/LICENSE)
[![Docs](https://readthedocs.org/projects/openvas-reporting/badge/?version=latest&style=flat)](https://openvas-reporting.stijncrevits.be)
[![Known Vulnerabilities](https://snyk.io/test/github/TheGroundZero/openvasreporting/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/TheGroundZero/openvasreporting?targetFile=requirements.txt)
[![codecov](https://codecov.io/gh/TheGroundZero/openvasreporting/branch/master/graph/badge.svg)](https://codecov.io/gh/TheGroundZero/openvasreporting)
[![Requirements Status](https://requires.io/github/TheGroundZero/openvasreporting/requirements.svg?branch=master)](https://requires.io/github/TheGroundZero/openvasreporting/requirements/?branch=master)
<!-- 
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/openvasreporting.svg)](https://pypi.org/project/openvasreporting/)
[![PyPI - Format](https://img.shields.io/pypi/format/openvasreporting.svg)](https://pypi.org/project/openvasreporting/)
-->

A tool to convert [OpenVAS](http://www.openvas.org/) XML into reports.

![Report example screenshot](docs/_static/img/OpenVASreporting.png?raw=true)

*Read the full documentation at [https://openvas-reporting.stijncrevits.be](https://openvas-reporting.stijncrevits.be)*

I forked [OpenVAS2Report](https://github.com/cr0hn/openvas_to_report) since it didn't manage to convert all reports I threw at it
and because I wanted to learn how to use Python for working with XML and creating Excel files.  
Also, OpenVAS mixes their own threat levels with the [CVSS](https://www.first.org/cvss/) scoring, the latter of which I prefer to use in my reports.

Looking for a fix and providing an actual fix through a pull request would have been too much work,
so I chose to fork the repo and try my own thing.  
I reorganised some of the files, removed some functionality and added some extra, and rewrote some functions.

At this moment in time, the script only output .xlsx documents in one format, this may (not) change in the future.


## Requirements

 - [Python](https://www.python.org/) version 3
 - [XlsxWriter](https://xlsxwriter.readthedocs.io/)
 - [Python-docx](https://python-docx.readthedocs.io)


## Installation

    # install requirements
    apt(-get) install python3 python3-pip # Debian, Ubuntu
    yum -y install python3 python3-pip    # CentOS
    dnf install python3 python3-pip       # Fedora
    pip3 install -r requirements.txt
    # clone repo
    git clone git@github.com:TheGroundZero/openvas_to_report.git


## Usage

    python3 -m openvasreporting -i [OpenVAS xml file(s)] [-o [Output file]] [-f [Output format]] [-l [minimal threat level (n, l, m, h, c)]]

### Parameters

| Short param | Long param | Description     | Required | Default value  |
| :---------: | :--------- | :-------------- | :------: | :------------- |
| -i          | --input    | Input file(s)   | YES      | n/a            |
| -o          | --output   | Output filename | No       | openvas_report |
| -f          | --format   | Output format   | No       | xlsx           |
| -l          | --level    | Minimal level   | No       | n              |


## Examples

### Create Excel report from 1 OpenVAS XML report using default settings

    python3 -m openvasreporting -i openvasreport.xml -f xlsx

### Create Excel report from multiple OpenVAS reports using default settings

    # wildcard select
    python3 -m openvasreporting -i *.xml -f xlsx
    # selective
    python3 -m openvasreporting -i openvasreport1.xml -i openvasreport2.xml -f xlsx

### Create Excel report from multiple OpenVAS reports, reporting only threat level high and up

    python3 -m openvasreporting -i *.xml -o excelreport -f xlsx -l h

## Result

The final report (in Excel format) will then look something like this:

![Report example screenshot - Summary](docs/_static/img/screenshot-report.png?raw=true)
![Report example screenshot - ToC](docs/_static/img/screenshot-report1.png?raw=true)
![Report example screenshot - Vuln desc](docs/_static/img/screenshot-report2.png?raw=true)

Worksheets are sorted according to CVSS score and are colored according to the vulnerability level.

## Ideas

Some of the ideas I still have for future functionality:

 - list vulnerabilities per host
 - make pip installer
 - filter by host (scope/exclude) as in OpenVAS2Report
 - export to other formats (CSV, PDF)
 - select threat levels individually (e.g. none and low; but not med, high and crit)
 

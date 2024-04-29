# OpenVAS Reporting:  

[![GitHub version](https://badge.fury.io/gh/TheGroundZero%2Fopenvasreporting.svg)](https://badge.fury.io/gh/TheGroundZero%2Fopenvasreporting)
[![License](https://img.shields.io/github/license/TheGroundZero/openvasreporting.svg)](https://github.com/TheGroundZero/openvasreporting/blob/master/LICENSE)
[![Docs](https://readthedocs.org/projects/openvas-reporting/badge/?version=latest&style=flat)](https://openvas-reporting.sequr.be)
[![PyPI - Version](https://img.shields.io/pypi/v/OpenVAS-Reporting.svg)](https://pypi.org/project/OpenVAS-Reporting/)
[![PyPI - Format](https://img.shields.io/pypi/format/OpenVAS-Reporting.svg)](https://pypi.org/project/OpenVAS-Reporting/)  
[![Total alerts](https://img.shields.io/lgtm/alerts/g/TheGroundZero/openvasreporting.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/TheGroundZero/openvasreporting/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/TheGroundZero/openvasreporting.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/TheGroundZero/openvasreporting/context:python)
[![Known Vulnerabilities](https://snyk.io/test/github/TheGroundZero/openvasreporting/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/TheGroundZero/openvasreporting?targetFile=requirements.txt)
[![codecov](https://codecov.io/gh/TheGroundZero/openvasreporting/branch/master/graph/badge.svg)](https://codecov.io/gh/TheGroundZero/openvasreporting)
[![Requirements Status](https://requires.io/github/TheGroundZero/openvasreporting/requirements.svg?branch=master)](https://requires.io/github/TheGroundZero/openvasreporting/requirements/?branch=master)

A tool to convert [OpenVAS](http://www.openvas.org/) XML into reports.

![Report example screenshot](docs/_static/img/OpenVASreporting.png?raw=true)

*Read the full documentation at [https://openvas-reporting.sequr.be](https://openvas-reporting.sequr.be)*

# LOOKING FOR MAINTAINERS

**THIS PROJECT IS NO LONGER ACTIVELY MAINTAINED!**

**PULL REQUESTS FOR MINOR CHANGES MAY STILL BE ACCEPTED.  
CHANGES IN OPENVAS MAY (and likely will) BREAK THIS TOOL. I WILL NOT PROVIDE SUPPORT FOR THAT.**

---

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

    # Install Python3 and pip3
    apt(-get) install python3 python3-pip # Debian, Ubuntu
    yum -y install python3 python3-pip    # CentOS
    dnf install python3 python3-pip       # Fedora
    # Clone repo
    git clone https://github.com/TheGroundZero/openvasreporting.git
    # Install required python packages
    cd openvasreporting
    pip3 install pip --upgrade
    pip3 install build --upgrade
    python -m build
    # Install module
    pip3 install dist/OpenVAS_Reporting-X.x.x-py3-xxxx-xxx.whl
    

Alternatively, you can install the package through the Python package installer 'pip'.  
This currently has some issues (see #4)

    # Install Python3 and pip3
    apt(-get) install python3 python3-pip # Debian, Ubuntu
    yum -y install python3 python3-pip    # CentOS
    dnf install python3 python3-pip       # Fedora
    # Install the package
    pip3 install OpenVAS-Reporting


## Usage

    # When working from the Git repo
    python3 -m openvasreporting -i [OpenVAS xml file(s)] [-o [Output file]] [-f [Output format]] [-l [minimal threat level (n, l, m, h, c)]] [-t [docx template]]
    # When using the pip package
    openvasreporting -i [OpenVAS xml file(s)] [-o [Output file]] [-f [Output format]] [-l [minimal threat level (n, l, m, h, c)]] [-t [docx template]]

### Parameters

| Short param | Long param        | Description          | Required | Default value                              |
| :---------: | :---------------: | :------------------: | :------: | :----------------------------------------- |
| -i          | --input           | Input file(s)        | YES      | n/a                                        |
| -o          | --output          | Output filename      | No       | openvas\_report                             |
| -c          | --config-file     | .yml configuration   | No       | None                                       |
| -f          | --format          | Output format        | No       | xlsx                                       |
| -l          | --level           | Minimal level        | No       | n                                          |
| -T          | --report-type     | Report by            | No       | vulnerability                              |
|             |                   | vulnerability        |          |                                            |
|             |                   | or by host           |          |                                            |
| -t          | --template        | Docx template        | No       | openvasreporting/src/openvas-template.docx |
| -n          | --network-include | file with networks   | No       | None                                       |
|             |                   | to include           |          |                                            |
| -N          | --network-exclude | file with networks   | No       | None                                       |
|             |                   | to exclude           |          |                                            |
| -r          | --regex-include   | file with regex to   | No       | None                                       |
|             |                   | to include from name |          |                                            |
| -R          | --regex-exclude   | file with regex to   | No       | None                                       |
|             |                   | to exclude from name |          |                                            |
| -e          | --cve-include     | file with CVEs to    | No       | None                                       |
|             |                   | to include from name |          |                                            |
| -E          | --cve-exclude     | file with CVEs to    | No       | None                                       |
|             |                   | to exclude from name |          |                                            |
| -D          | --danger-exclude  | First letter of      | No       | None                                       |
|             |                   | threats to exclude   |          |                                            |

## Filtering options

The `-n`/`-N`/`-r`/`-R`/`-e`/`-E` options will read a file with one option per line.
Networks accepts CIDRs, IP Ranges or IPs.
Regex accept any valid regex expression and will be case insensitive matched against the name of the vulnerability.
CVEs are inserted in the `CVE-YYYY-nnnnn` format.

The `-c` option will read a .yml file with all configurations.
If the `-c` option is used, any other options but input and output filenames are ignored.
There is a sample of a configuration file in the `docs/` folder

## Examples

### Create Excel report from 1 OpenVAS XML report using default settings

    python3 -m openvasreporting -i openvasreport.xml -f xlsx

### Create Excel report from multiple OpenVAS reports using default settings

    # wildcard select
    python3 -m openvasreporting -i *.xml -f xlsx
    # selective
    python3 -m openvasreporting -i openvasreport1.xml -i openvasreport2.xml -f xlsx

### Create Word report from multiple OpenVAS reports, reporting only threat level high and up, use custom template

    python3 -m openvasreporting -i *.xml -o docxreport -f docx -l h -t "/home/user/myOpenvasTemplate.docx"

## Result

The final report (in Excel format) will then look something like this:

![Report example screenshot - Summary](docs/_static/img/screenshot-report.png?raw=true)
![Report example screenshot - ToC](docs/_static/img/screenshot-report1.png?raw=true)
![Report example screenshot - Vuln desc](docs/_static/img/screenshot-report2.png?raw=true)

Worksheets are sorted according to CVSS score and are colored according to the vulnerability level.

## Ideas

Some of the ideas I still have for future functionality:

 - list vulnerabilities per host ==DONE==
 - filter by host (scope/exclude) as in OpenVAS2Report ==DONE==
 - select threat levels individually (e.g. none and low; but not med, high and crit)
 - import other formats (not only XML), e.g. CSV as suggested in [this issue](https://github.com/TheGroundZero/openvasreporting_server/issues/3)

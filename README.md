![Logo OpenVAS Reporting](openvasreporting/doc/img/logo.png?raw=true)

# OpenVAS Reporting:  
## A tool to convert OpenVAS XML reports into Excel files.

I forked [OpenVAS2Report](https://github.com/cr0hn/openvas_to_report) since it didn't manage to convert all reports I threw at it
and because I wanted to learn how to use Python for working with XML and creating Excel files.  
Also, OpenVAS mixes their own threat levels with the CVSS scoring, the latter of which I prefer to use in my reports.

Looking for a fix and providing an actual fix through a pull request would have been too much work,
so I chose to fork the repo and try my own thing.  
I reorganised some of the files, removed some functionality and added some extra, and rewrote some functions.

At this moment in time, the script only output .xlsx documents in one format, this may (not) change in the future.

## Requirements

 - Python version 3
 - [XlsxWriter](https://xlsxwriter.readthedocs.io/)

## Installation

    # install requirements
    apt(-get) install python3 python3-pip # Debian, Ubuntu
    yum -y install python3 python3-pip    # CentOS
    dnf install python3 python3-pip       # Fedora
    pip3 install -r requirements.txt
    # clone repo
    git clone git@github.com:TheGroundZero/openvas_to_report.git

## Usage

    python3 -m openvasreporting -i [OpenVAS xml file(s)] -o [Report output file.xlsx] [-l [minimal threat level (n, l, m, h, c)]]

### Create Excel report from 1 OpenVAS XML report using default settings

    python3 openvasreporting.py -i openvasreport.xml -o excelreport.xlsx

### Create Excel report from multiple OpenVAS reports using default settings

    # wildcard select
    python3 openvasreporting.py -i *.xml -o excelreport.xlsx
    # selective
    python3.7 openvasreporting.py -i openvasreport1.xml -i openvasreport2.xml -o excelreport.xlsx

### Create Excel report from multiple OpenVAS reports, reporting only threat level high and up

    python3 openvasreporting.py -i *.xml -o excelreport.xlsx -l h

## Result

The final report will then look something like this:

![Report example screenshot](openvasreporting/doc/img/screenshot-report.png?raw=true)
![Report example screenshot](openvasreporting/doc/img/screenshot-report2.png?raw=true)

Worksheets are sorted according to CVSS score and are colored according to the vulnerability level.

## Ideas

Some of the ideas I still have for future functionality:

 - list vulnerabilities per host
 - make pip installer
 - filter by host (scope/exclude) as in OpenVAS2Report
 - export to other formats (CSV, Word, PDF)
 - select threat levels individually (e.g. none and low; but not med, high and crit)
 

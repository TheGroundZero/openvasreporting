Changelog
=========

1.6.0  - New Features:

       - Included option (--host-include) to define a file with a list of host.domain (hostname) that will be included from the report.

       - Included option (--host-exclude) to define a file with a list of host.domain (hostname) that will be excluded from the report.

       - In the config-file, the keyworks 'hostnames' as been add with children keyworks includes/excludes to set included and excluded host.domain from the report.

       -Refeactor:

       - Few PEP8 refactoring along some files as been made. But few remains to do.


1.5.0  - New Features:

       - Included option (--config-file) to define a .yaml file with all options but input and output filenames.
         if this option is used all other options are ignored. any options not present in this file will be set to default

       - Included option (--report-type) to define the type of report and created two new types of reports:
         - a report summarizing the hosts with the highest number of vulnerabilities and sum of all its cvss severities and including a tab for each host listing each vulnerability
         - a csv report ordered by host with all vulnerabilities (same fields as the by vulnerability type)
           (I don't believe it's worth creating a .docx version of this report, so I'm not creating it)

       - Included option (--network-exclude) to define a file with a list of ips or ipcidrs or range of ips (one by line) that will be excluded from the report

       - Included option (--network-include) to define a file with a list of ips or ipcidrs or range of ips (one by line) that will be included in the report

       - Included option (--regex-include) to define a file with a list of regex expressions to include in the report
         the regex expressions will be matched against the name of the vulnerability

       - Included option (--regex-exclude) to define a file with a list of regex expressions to exclude in the report
         the regex expressions will be matched against the name of the vulnerability

       - Included option (--cve-include) to define a file with a list of CVE numbers to include in the report

       - Included option (--cve-exclude) to define a file with a list of CVE numbers to exclude from the report

       -Fixes:

       - Major code refactor to include the new reports and the new options

       - Fix module packaging and shell script executions now run ok (import 'main' in top source __init__.py so the egg may be found) 

       - Converted module packaging to python3.6+ packaging using setup.cfg e pyproject.toml

       - Removed package top dir setup.py and requirements.txt files that are not used anymore

       - Updated README.md to reflect those changes

1.4.2  - Fixed "ValueError: Unknown format code 'f' for object of type 'str'"

1.4.1  - Small bugfixes and code refactoring

1.4.0  - Use Word template for report building

1.3.1  - Add charts to Word document using matplotlib. Some code clean-up and small lay-out changes in Excel.

1.3.0  - Fix retrieval of description and other useful info by parsing <tags> instead of <description>

1.2.3  - Implement https://github.com/cr0hn/openvas_to_report/pull/12

1.2.2  - Fix bug where port info was not correctly extracted

1.2.1  - Fix bug where affected hosts were added on wrong row in Excel export

1.2.0  - Functional export to Word document (.docx). Includes some formatting. TODO: graphs

1.1.0a - Support for exporting to Word document (.docx). Limited formatting, needs more testing

1.0.1a - Small updates, preparing for export to other formats

1.0.0  - First official release, supports export to Excel with graphs, ToC and worksheet per vulnerability

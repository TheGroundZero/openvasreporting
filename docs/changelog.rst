Changelog
=========

1.6.0  - New Features:

       - Add Vulnerability version to report

       -Fixes:

       - Refactor code to help future developpement

       - Class, function and variable are now typed

       - Remove useless part of the script that where not used

1.5.0  - Added args options to personnalize IP and CVE to keep/ignore

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

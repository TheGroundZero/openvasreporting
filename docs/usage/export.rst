Command line usage
==================

.. code-block:: bash

   # When working from the Git repo
   python3 -m openvasreporting -i *.xml [-i ...] [-c config.yml] [-o openvas_report] [-f xlsx] [-l none] [-t "openvasreporting/src/openvas-template.docx"] [-T vulnerability] [-n included_networks] [-N excluded-networks] [-r included-regex] [-R excluded-regex] [-e included-cve] [-E excluded-cve]
   # When using the pip package
   openvasreporting -i *.xml [-i ...] [-c config.yml] [-o openvas_report] [-f xlsx] [-l none] [-t "openvasreporting/src/openvas-template.docx"] [-T vulnerability] [-n included_networks] [-N excluded-networks] [-r included-regex] [-R excluded-regex] [-e included-cve] [-E excluded-cve]

\-i, --input
   | Mandatory
   | Selects the OpenVAS XML report file(s) to be used as input.
   | Accepts one or more inputs, including wildcards

\-o, --output
   | Optional
   | Name of the output file, without extension.
   | Defaults to: openvas_report

\-c, --config-file
   | Optional
   | Path to a .yml file containing the configuration (format, level, type, filters)
   | If this option is used all other options (but input and output files) will be ignored
   | Defaults to: None
   
\-f, --format
   | Optional
   | Type of output file.
   | Valid values are: xlsx, docx, csv
   | Defaults to: xlsx

\-l, --level
   | Optional
   | Minimal severity level of finding before it's included in the report.
   | Valid values are: c(ritical), h(igh), m(edium), l(low), n(one)
   | Defaults to: none

\-t, --template
   | Optional, only used with '-f docx'
   | Template document for docx export. Document must contain formatting for styles used in export.
   | Valid values are: path to a docx file
   | Defaults to: openvasreporting/src/openvas-template.docx

\-T, --report-type
   | Optional 
   | Selects if will list hosts by vulnerability (v) or vulnerabilities by host (h)
   | Valid values are: v, h, vulnerabiity, host
   | Defaults to: vulnerability

\-e, --network-include
   | Optional
   | path to a file containing a list of ips, ipcidrs or ipaddrs (one per line) that 
   | will be included in the report
   | Defaults to: all hosts with appropriate level will be included

   
\-E, --network-exclude
   | Optional
   | path to a file containing a list of ips, ipcidrs or ipaddrs (one per line) that 
   | will be excluded from the report
   | Defaults to: no excluded hosts

\-r, --regex-include
   | Optional
   | path to a file containing a list of regex expressions that will be matched against
   | the name of the vulnerability field to be filtered into the report
   | Defaults to: all vulnerabilities will be included
   
\-R, --regex-exclude
   | Optional
   | path to a file containing a list of regex expressions that will be matched against
   | the name of the vulnerability field to be filtered out of the report
   | Defaults to: no excluded vulnerabilities

\-e, --cve-include
   | Optional
   | path to a file containing a list of CVEs (format CVEYYYY-nnn...) that will be 
   | filtered into the report
   | Defaults to: all vulnerabilities with -l level will be included
   
\-C, --cve-exclude
   | Optional
   | path to a file containing a list of CVEs (format CVEYYYY-nnn...) that will be
   | filtered out of the report
   | Defaults to: no excluded hosts


.. todo::
   [Feature] Export to other formats (PDF, [proper] CSV)


.. toctree::
   :caption: Export formats
   :maxdepth: 1

   export-excel
   export-word
   export-csv
   export-excel-host
   export-csv-host

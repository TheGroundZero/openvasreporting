Command line usage
==================

.. code-block:: bash

   # When working from the Git repo
   python3 -m openvasreporting -i *.xml [-i ...] [-o openvas_report] [-f xlsx] [-l none] [-t "openvasreporting/src/openvas-template.docx"]
   # When using the pip package
   OpenVAS-Reporting -i *.xml [-i ...] [-o openvas_report] [-f xlsx] [-l none] [-t "openvasreporting/src/openvas-template.docx"]

\-i, --input
   | Mandatory
   | Selects the OpenVAS XML report file(s) to be used as input.
   | Accepts one or more inputs, including wildcards

\-o, --output
   | Optional
   | Name of the output file, without extension.
   | Defaults to: openvas_report

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

\-r, -b, --report-type
   | Optional 
   | Selects if will list hosts by vulnerability (v) or vulnerabilities by host (h)
   | Valid values are: v, h
   | Defaults to: v

\-e, --network-exclude
   | Optional
   | path to a file containing a list of ips, ipcidrs or ipaddrs (one per line) that 
   | will be excluded from the report
   | Defaults to: no excluded hosts

\-s, --network-include
   | Optional
   | path to a file containing a list of ips, ipcidrs or ipaddrs (one per line) that 
   | will be included in the report
   | Defaults to: all hosts with appropriate level will be included

   
\-t, --template
   | Optional, only used with '-f docx'
   | Template document for docx export. Document must contain formatting for styles used in export.
   | Valid values are: path to a docx file
   | Defaults to: openvasreporting/src/openvas-template.docx


.. todo::
   [Feature] Export to other formats (PDF, [proper] CSV)

.. todo::
   [Feature] List vulnerabilities per host

.. todo::
   [Feature] Filter by host (scope/exclude) as in OpenVAS2Report


.. toctree::
   :caption: Export formats
   :maxdepth: 1

   export-excel
   export-word
   export-csv
   export-excel-by-host
   export-csv-by-host

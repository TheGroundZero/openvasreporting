Export to Excel
---------------

.. code-block:: bash

   python3 -m openvasreporting -i *.xml [-o openvas_report] [-l none] [-f xlsx]

\-i, --input
   | Mandatory
   | Selects the OpenVAS XML report file(s) to be used as input.

\-o, --output
   | Optional
   | Name of the output file, without extension.
   | Defaults to: openvas_report

\-l, --level
   | Optional
   | Minimal severity level of finding before it's included in the report.
   | Valid values are: c(ritical), h(igh), m(edium), l(low), n(one)
   | Defaults to: none.

\-f, --format
   | Optional
   | Type of output file.
   | Valid values are: xlsx
   | Defaults to: xlsx


Examples
^^^^^^^^

Create Excel report from 1 OpenVAS XML report using default settings
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i openvasreport.xml

   $ ls
   openvas_report.xlsx
   openvasreport.xml

Create Excel report from multiple OpenVAS XML report using default settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i *.xml
   # OR
   python3 openvasreporting.py -i openvasreport.xml -i openvasreport1.xml -i openvasreport2.xml

   $ ls
   openvas_report.xlsx
   openvasreport.xml
   openvasreport1.xml
   openvasreport2.xml

Create Excel report from 1 OpenVAS XML report, reporting only severity level high and up
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i openvasreport.xml -l h

   $ ls
   openvas_report.xlsx # contains severity levels high and critical
   openvasreport.xml


Result
^^^^^^

The final report will look similar to this:

.. image:: /_static/img/screenshot-report.png
   :alt: Report example screenshot - Summary
   :width: 30%

.. image:: /_static/img/screenshot-report1.png
   :alt: Report example screenshot - Table of Contents
   :width: 30%

.. image:: /_static/img/screenshot-report2.png
   :alt: Report example screenshot - Vulnerability description
   :width: 30%

Worksheets are sorted according to CVSS score and are colored according to the vulnerability level.
Export to Excel
---------------

By default (or when passing the --format xlsx parameter), the tool will export reports in Excel (xlsx) format.

This report contains a summary sheet, table of contents, and a sheet per vulnerability containing vulnerability details
and a list of affected hosts.

Examples
^^^^^^^^

Create Excel report from 1 OpenVAS XML report using default settings
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i openvasreport.xml

Create Excel report from multiple OpenVAS XML report using default settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i *.xml
   # OR
   python3 openvasreporting.py -i openvasreport.xml -i openvasreport1.xml -i openvasreport2.xml [-i ...]

Create Excel report from 1 OpenVAS XML report, reporting only severity level high and up
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i openvasreport.xml -o openvas_report -f xlsx -l h


Result
^^^^^^

The final report will look similar to this:

.. image:: ../_static/img/screenshot-report.png
   :alt: Report example screenshot - Summary
   :width: 30%

.. image:: ../_static/img/screenshot-report1.png
   :alt: Report example screenshot - Table of Contents
   :width: 30%

.. image:: ../_static/img/screenshot-report2.png
   :alt: Report example screenshot - Vulnerability description
   :width: 30%

Worksheets are sorted according to CVSS score and are colored according to the vulnerability level.
Export to Excel by Host
-----------------------

By default (or when passing the --format xlsx parameter), the tool will export reports in Excel (xlsx) format sorted by vulnerability. If you add [--report-type host] parameter, it will generate a report sorted by Host.

This report contains a summary sheet, table of contents, and a sheet per Host containing vulnerability details.

Examples
^^^^^^^^

Create Excel report from 1 OpenVAS XML report, sorted by host, using default settings 
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -T host

Create Excel report from multiple OpenVAS XML report, sorted by host, using default settings
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -T host
   # OR
   openvasreporting -i openvasreport.xml -i openvasreport1.xml -i openvasreport2.xml [-i ...] -T HOST

Create Excel report from 1 OpenVAS XML report, sorted by host, reporting only severity level high and up
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -o openvas_report -f xlsx -l h -T  HOST


Result
^^^^^^

The final report will look similar to this:

.. image:: ../_static/img/screenshot-report-h.png
   :alt: Report example screenshot - Summary
   :width: 30%

.. image:: ../_static/img/screenshot-report-h1.png
   :alt: Report example screenshot - Table of Contents
   :width: 30%

.. image:: ../_static/img/screenshot-report-h2.png
   :alt: Report example screenshot - Vulnerability description
   :width: 30%

Vulnerability detail worksheets are sorted according to CVSS score and are colored according to the threat level.

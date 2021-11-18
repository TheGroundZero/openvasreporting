Export to Comma Separated Values sorted by Host
-----------------------------------------------

When passing the --format csv parameter, the tool will export reports in Comma Separated Values (CSV) format. If you use [-T host] parameter, the list will be sorted by host.

The CSV format is optimized for import in Excel.

Examples
^^^^^^^^

Create CSV report from 1 OpenVAS XML report, sorted by host, using default settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -f csv -T host

Create CSV report from multiple OpenVAS XML report, sorted by host, using default settings
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -f csv -T host
   # OR
   openvasreporting -i openvasreport.xml -i openvasreport1.xml -i openvasreport2.xml [-i ...] -f csv -T host

Create CSV report from 1 OpenVAS XML report, sorted by host and reporting only severity level high and up
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -o openvas_report -f csv -l h -T host


Result
^^^^^^

The final report will look similar to this:

.. todo::
   [DOCS] Add examples of CSV report

Hosts are sorted according to number of CVSS score in each level (descending)

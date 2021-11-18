Export to Comma Separated Values
--------------------------------

When passing the --format csv parameter, the tool will export reports in Comma Separated Values (CSV) format.
The CSV format is optimized for import in Excel.

Examples
^^^^^^^^

Create CSV report from 1 OpenVAS XML report using default settings
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -f csv

Create CSV report from multiple OpenVAS XML report using default settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -f csv
   # OR
   openvasreporting -i openvasreport.xml -i openvasreport1.xml -i openvasreport2.xml [-i ...] -f csv

Create CSV report from 1 OpenVAS XML report, reporting only severity level high and up
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -o openvas_report -f csv -l h


Result
^^^^^^

The final report will look similar to this:

.. todo::
   [DOCS] Add examples of CSV report

Vulnerabilities are sorted according to CVSS score (descending) and vulnerability name (ascending).

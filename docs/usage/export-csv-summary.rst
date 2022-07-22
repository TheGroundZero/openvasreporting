Export to Comma Separated Values sorted by Host
-----------------------------------------------

When passing the --format csv parameter, the tool will export reports in Comma Separated Values (CSV) format. If you use [-T summary] parameter, an executive report will be generated.

The report is suitable for later processing/inclusion in monitoring tools.

The CSV format is optimized for import in Excel.

Examples
^^^^^^^^

Create CSV report from 1 OpenVAS XML report, using default settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -f csv -T summary

Create CSV report from multiple OpenVAS XML report, using default settings
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -f csv -T summary
   # OR
   openvasreporting -i openvasreport.xml -i openvasreport1.xml -i openvasreport2.xml [-i ...] -f csv -T summary

Create CSV report from 1 OpenVAS XML report, and reporting only severity level high and up
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -o openvas_report -f csv -l h -T summary


Result
^^^^^^

The final report will look similar to this:

.. code-block:: bash
   
   level,count,host_count
   critical,11,152
   high,19,71
   medium,22,134
   low,2,49
   none,0,0

Export to Word
--------------

When passing the --format docx parameter, the tool will export reports in Word (docx) format.

This report contains a summary sheet, table of contents, and a sheet per vulnerability containing vulnerability details
and a list of affected hosts.

Examples
^^^^^^^^

Create Word report from 1 OpenVAS XML report using default settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i openvasreport.xml -f docx

Create Word report from multiple OpenVAS XML report using default settings
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i *.xml -f docx
   # OR
   python3 openvasreporting.py -i openvasreport.xml -i openvasreport1.xml -i openvasreport2.xml [-i ...] -f docx

Create Word report from 1 OpenVAS XML report, reporting only severity level high and up
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i openvasreport.xml -o openvas_report -f docx -l h

Create Word report using a different template
"""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   python3 openvasreporting.py -i openvasreport.xml -o openvas_report -f docx -t /home/user/myOpenvasTemplate.docx

The custom template document must contain a definition for the following styles:

- Title (default)
- Heading 1 (default)
- Heading 4 (default)
- OV-H1toc (custom format for Heading 1, included in Table of Contents)
- OV-H2toc (custom format for Heading 2, included in Table of Contents)
- OV-Finding (custom format for finding titles, included in Table of Contents)


Result
^^^^^^

The final report will look similar to this:

.. todo::
   [DOCS] Add screenshots of Word report

Vulnerabilities are sorted according to CVSS score (descending) and vulnerability name (ascending).
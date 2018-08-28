Command line usage
==================

.. code-block:: bash

   python3 -m openvasreporting -i *.xml [-i ...] [-o openvas_report] [-l none] [-f xlsx]

\-i, --input
   | Mandatory
   | Selects the OpenVAS XML report file(s) to be used as input.
   | Accepts one or more inputs, including wildcards

\-o, --output
   | Optional
   | Name of the output file, without extension.
   | Defaults to: openvas_report

\-l, --level
   | Optional
   | Minimal severity level of finding before it's included in the report.
   | Valid values are: c(ritical), h(igh), m(edium), l(low), n(one)
   | Defaults to: none

\-f, --format
   | Optional
   | Type of output file.
   | Valid values are: xlsx
   | Defaults to: xlsx


.. todo::
   Export to other formats (Word [docx], PDF, [proper] CSV)


.. toctree::
   :caption: Export formats
   :maxdepth: 1

   export-excel
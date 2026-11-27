Export to HTML
--------------

When passing the --format html parameter, the tool exports a single, self-contained HTML file
(logo, styles and script are embedded: it opens offline and can be attached to an e-mail).

The report has three tabs:

- **Summary**: scan information (task, scan period, source files), number of vulnerabilities and
  affected hosts per severity level, a severity chart, the 10 most exposed hosts and the
  vulnerabilities per family. Printing the page (or "Print to PDF") outputs this summary only.
- **By vulnerability**: vulnerabilities sorted by CVSS score, with a search box (name, CVE, OID,
  IP, family) and severity filters. Selecting a vulnerability shows its details and every affected
  host / port with the raw scan result; clicking an IP opens that host in the "By host" tab.
- **By host**: hosts ranked like the OpenVAS host tab, each listing its vulnerabilities, linked to
  the vulnerability details.

The HTML report always contains both views: the ``-T/--report-type`` option has no effect.

All text coming from the scan is HTML-escaped, and a Content-Security-Policy only allows the
report's own script to run.

Examples
^^^^^^^^

Create HTML report from 1 OpenVAS XML report using default settings
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -f html

Create HTML report from multiple OpenVAS XML reports, reporting only severity level medium and up
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -o openvas_report -f html -l m

Use a custom layout
"""""""""""""""""""

The default template is ``openvasreporting/src/html/report.html.j2`` (the author and title are set on
its first lines). To use your own layout without touching the installed package, copy it, edit it and
pass it with ``-t``. The script is always the packaged ``report.js``: it is the only script allowed by
the report's Content-Security-Policy.

.. code-block:: bash

   cp "$(python3 -c 'import openvasreporting, os; print(os.path.dirname(openvasreporting.__file__))')/src/html/report.html.j2" myreport.html.j2
   openvasreporting -i openvasreport.xml -f html -t myreport.html.j2

Templates are rendered in a Jinja2 sandbox with autoescaping enabled: a template cannot run Python code,
and every value coming from the scan is escaped. Bidirectional control characters in scan data are shown
as ``[U+202E]``-style markers so that a host cannot disguise its name.

Using Filters
-------------

You can filter the vulnerabilities that will be presented in you report using one of the filtering options. You can filter:
- networks cidrs, ip ranges and any individual ip using the options **-n/--network-include** and **-N/--network-exclude**;
- regex expressions that will be matched against the vulnerability names using the options **-r/--regex-include** and **-R/--regex-exclude** - The matches will be case insensitive;
- CVEs numbers in the format CVEYYYY-nnn... using the options **-e/--cve-include** and **-E/--cve-exclude**;
When passing the --format csv parameter, the tool will export reports in Comma Separated Values (CSV) format.

All these options receive the path to a .txt file containing one filtering option by line.


Examples
^^^^^^^^

Create xlsx report from multiple OpenVAS XML Report filtering by network 
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -n ./branch_1.txt -N ./branch_1_ipaliases.txt

Contents of *branch_1.txt* could be:

.. code-block:: txt

   172.16.168.0/24
   172.16.0.1-172.16.0.3
   172.16.1.1

Contents of *branch_1_ipaliases.txt* could be:

.. code-block:: txt

   172.16.168.234
   172.16.168.236-239
   172.16.168.15

Create xlsx report, sorted by host, filtering by regex
""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -T host -R ./regex_defender.txt

Contents of *regex_defender.txt* could be:

.. code-block:: txt

   defender

Create xlss report from 1 OpenVAS XML report, filtering by CVE
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -e ./cisa_nov_2021.txt

Contents of *cisa_nov_2021.txt* could be

.. code-block:: txt

   CVE-2021-27104
   CVE-2021-27102
   CVE-2021-27101
   [...]
   CVE-2020-10189
   CVE-2019-8394
   CVE-2020-29583

Of course, you can mix filtering options:
"""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i *.xml -r ./regex_defender.txt -e ./cisa_nov_2021.txt


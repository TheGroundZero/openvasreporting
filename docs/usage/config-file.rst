.YML Configuration File
--------------------------------

You can use the **-c/--config-file** option to define a .yml file to be loaded with all the configuration to execute **openvasreporting** but input and output filenames.

If you use this option, all other configuration options but input and output filenames will be ignored and if not defined in the .yml configuration file will be set to default.

Sample Configuration File:
""""""""""""""""""""""""""

.. code-block:: yml

   level:
     medium
   
   format:
     xlsx
   
   reporttype:
     host
   
   networks:
     includes:
       - 10.0.0.0/8
       - 172.16.0.0/12
       - 192.168.0.0/16
     excludes:
       - 172.16.168.234
       - 172.16.168.236-172.16.168.239
       - 172.20.16.120

   hostnames:
     includes:
      - server1.mylocaldomain
      - server2.mylocaldomain

     excludes:
      - myhomelaptop
      - desktop1.mylocaldomain
   
   regex:
     excludes:
       - defender
   
   # I use this section to filter out recent ms patches not put in production yet. Or to filter in CVEs from the CISA Active Exploit bulletin
   cve:
     excludes:
       - CVE-2021-1971

Using this configuration file, the resulting report would be restricted to level medium and up, will be an Excel report, will be sorted by host, will filter in only rfc1918 local networks but will filter out some IP Ranges and IPs and will exclude CVE2021-1971.

Examples
^^^^^^^^

Create report using above sample config:
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

.. code-block:: bash

   openvasreporting -i openvasreport.xml -c ./config_defender_out_by_host.yml


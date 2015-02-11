Openvas2Report Manual
=====================

.. _openvas_to_document_man:

What's this tool?
-----------------

In few words: with this tools you can convert the OpenVAS XML report to beautiful Excel file.

Basic usage
-----------

The more simple usage is with only one file as input.

.. note::

    If you haven't a XML as example, you can get one in folder :file:`examples`.

This pictures shows the example XML file:

.. figure:: ../../images/airplay_xml.png


To run only write:

.. code-block:: bash

    > openvas_to_document -i my_openvas_report.xml -o generated_excel.xslx

After running you got this Excel:


.. figure:: ../../images/excel1.png


.. figure:: ../../images/excel2.png

Also, you can specify more than one XML report as input:

.. code-block:: bash

    > openvas_to_document-i my_openvas_report_1.xml -i my_openvas_report_2.xml -o generated_excel.xslx

.. _advanced_usage:

Advanced usage
--------------

If you want to exclude some hosts from report, you can use two aproaches:

#. Using a scope filter.
#. Specify a list of hosts to exclude.

Setting a filter
++++++++++++++++

Is you only want to include certain hosts in your Excel report, you only must create a .txt file with your scope:

.. code-block:: bash

    > echo 10.0.0.1 > my_scope.txt
    > echo 10.0.1.23 >> my_scope.txt

Then use it as a parameter in the tools:

.. code-block:: bash

    > openvas_to_document -i my_openvas_report.xml -o generated_excel.xslx --scope-hosts my_scope.txt

Simple right? :)

Excluding hosts
+++++++++++++++

The second approach is to create a black list. As in the previous case, we'll define our file:

.. code-block:: bash

    > echo 127.0.0.1 > excluded.txt
    > echo 192.168.0.3 >> excluded.txt

And then, use it:

.. code-block:: bash

     > openvas_to_document -i my_openvas_report.xml -o generated_excel.xslx --exclude-hosts excluded.txt


Openvas Cutter
==============

.. _openvas_cutter_man:


What's this tool?
-----------------

There are some times that you need to exclude some hosts from the XML. For example: If you must to deliver the XML report, but it contains some hosts that are out of scope.

This tools can help us. It remove host information from the original XML file, and generates a new XML file without this information.

Basic usage
-----------

The usage si very simple. Only need to specify the input file/s and the new output file:

.. note::

    If you haven't a XML as example, you can get one in folder :file:`examples`.


To run only write:

.. code-block:: bash

    > openvas_cutter -i my_openvas_report.xml -o my_openvas_report_filtered.xml

Advanced usage
--------------

Advanced filer works as same as :samp:`openvas_to_document` tool. You can read it in: :ref:`advanced_usage`.
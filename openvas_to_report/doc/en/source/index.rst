.. OpenVAS2Report documentation master file, created by
   sphinx-quickstart on Wed Feb 11 01:21:33 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to OpenVAS2Report's documentation!
==========================================

.. figure:: ../../images/logo.png
    :align: left
    :scale: 80%

What's OpenVAS 2 Report
-----------------------

The idea is very simple:

#. Take an OpenVAS report, in it horrible XML format.
#. Convert it into an beautiful Excel, ready to give to your boss.


Why?
====

I'm security auditor and I really hate to pass OpenVAS XML report into to and Excel document. This is a work for a monkey, not for a human! (Yes: security auditors are humans too. I know, I know. It's incredible)

So I started to develop this project and I thought share it for help other auditors that also hate make a monkey's work.


Available tools
---------------

This package are composed by 2 tools:

+ **openvas_to_document**: This is the main program. You can use it to generate the Excel file.
+ **openvas_cutter**: This is a facility for filter and crop some information from OpenVAS XML report.

A picture is worth a 1000 words From XML. Using :samp:`openvas_to_document.py` you can obtain this Excel file:

.. image:: ../../images/excel1.png

As a library
------------

Also, you can use the tool as a library and import them it in your own code. It has BSD license, Feel free to use!

Content Index
-------------

.. toctree::
   :maxdepth: 2

   quickstart
   openvas_to_document
   openvas_cutter
   as_a_library
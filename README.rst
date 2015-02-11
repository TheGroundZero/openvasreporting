==============
OpenVAS2Report
==============

.. figure:: openvas_to_report/doc/images/logo.png
    :align: left
    :scale: 80%

*OpenVAS XML report to human-friendly converter*

:Code:          https://github.com/cr0hn/openvas2report
:Issues:        https://github.com/cr0hn/openvas2report/issues
:Documentation HTML [EN]: http://openvas2report.readthedocs.org
:Python version:   Python 3

What's OpenVAS2Report?
======================

The idea is very simple:

# Take an OpenVAS report, in it horrible XML format.
# Convert it into an beautiful Excel, ready to give to your boss.

Why?
====

I'm security auditor and I really hate to pass OpenVAS XML report into to and Excel document. This is a work for a monkey, not for a human! (Yes: security auditors are humans too. I know, I know. It's incredible)

So I started to develop this project and I thought share it for help other auditors that also hate make a monkey's work.

OpenVAS to in two words
=======================

This package are composed by 2 tools:

+ **openvas_to_document**: This is the main program. You can use it to generate the Excel file.
+ **openvas_cutter**: This is a facility for filter and crop some information from OpenVAS XML report.
+ **as a library**: Also, you can use the tool as a library and import them it in your own code. It has BSD license, Feel free to use!

A picture is worth a 1000 words From XML. Using openvas_to_document you can obtain this Excel file:

.. image:: openvas_to_report/doc/images/excel1.png


Future
======

I'm have not enough time, but in a future, I'll write the module to export the results in a Word.

Bugs and errors
===============

If you find some bugs, please, open a ticket using github issues. And, If you send me a patch I'll be very happy :)

And if you want to help me... A beer may be a great idea :)


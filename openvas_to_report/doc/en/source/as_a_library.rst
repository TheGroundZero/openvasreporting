OpenVAS2Report as a library
===========================

.. _openvas_library_man:

You can user openvas2Report as a library. It's easy.

Configuration object
--------------------

All the actions in package has a common configuration object called :samp:`Config`. We need to configure it before to run.


This code display the Config objects and mark the parameters accepted:

.. literalinclude:: ../../../libs/data/config.py
    :lines: 32-57
    :linenos:
    :emphasize-lines: 8-24

The code is auto-explained. Then, we import them from :file:`openvas_to_report.api`:

.. code-block:: python

    from openvas_to_report.api import Config

    config = Config(["openvas_report1.xml", "openvas_report2.xml"],
                    "results.xslx",
                    "en",
                    "excluded_hosts.txt",
                    "scope_host.txt")

Run actions
-----------

I called action to these tasks or functions that you also can run in command line way.

After instance the config object, we can call actions:

.. code-block:: python

    from openvas_to_report.api import Config, convert, crop

    # Convert to Excel
    config_convert = Config(["openvas_report1.xml", "openvas_report2.xml"],
                            "results.xslx",
                            "en")

    convert(config)

    # Crop XML file
    config_convert = Config(["openvas_report1.xml", "openvas_report2.xml"],
                            "results_filtered.xml")

    crop(config)
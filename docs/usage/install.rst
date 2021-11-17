************
Installation
************

You can install this package directly from source by cloning the Git repository.

.. code-block:: bash

   # Install pip
   apt(-get) install python3 python3-pip # Debian, Ubuntu
   yum -y install python3 python3-pip    # CentOS
   dnf install python3 python3-pip       # Fedora

   # Clone repo
   git clone git@github.com:TheGroundZero/openvasreporting.git

   # Install requirements
   cd openvasreporting
   pip3 install -r requirements.txt
   pip3 install build --upgrade
   pip3 install pip --upgrade
   python -m build .
   pip3 install dist/Openvas_Reporting[...].whl

Alternatively, you can install the package through the Python package installer 'pip'.

.. code-block:: bash

   # Install pip
   apt(-get) install python3 python3-pip # Debian, Ubuntu
   yum -y install python3 python3-pip    # CentOS
   dnf install python3 python3-pip       # Fedora

   # Install the package
   pip install OpenVAS-Reporting

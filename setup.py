# from distutils.core import setup, find_packages
from setuptools import setup, find_packages

files = ["libs/translations/excel/*.json"]

setup(
    name='openvas_to_report',
    version='1.0.0',
    packages=find_packages(),
    url='https://github.com/cr0hn/openvas_to_report',
    install_requires=["xlsxwriter"],
    license='BSD',
    author='cr0hn',
    package_data={'openvas_to_report': files},
    author_email='cr0hn<-at->cr0hn.com',
    description='OpenVAS2Report: A set of tools to manager OpenVAS XML report files.',
    entry_points={'console_scripts': [
        'openvas_to_report = openvas_to_report.openvas_to_document:main',
        'openvas_cutter = openvas_to_report.openvas_cutter:main',
    ]},
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
    ]
)

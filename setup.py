#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name='OpenVAS Reporting',
    version='1.0.1a',
    description='Convert OpenVAS XML report files to Excel reports.',
    long_description='file: README.md',
    author='TheGroundZero',
    author_email='2406013+TheGroundZero@users.noreply.github.com',
    url='https://github.com/TheGroundZero/openvas_to_report',
    packages=find_packages(exclude=['tests', 'tests.*', 'venv', '*git*']),
    requires=['xlsxwriter'],
    entry_points={
        'console_scripts': [
            'openvas_reporting = openvasreporting:main'
        ]
    },
    project_urls={
        'Source Code': 'https://github.com/TheGroundZero/openvas_to_report',
        'Documentation': 'https://github.com/TheGroundZero/openvas_to_report/blob/master/README.md',
        'Issues': 'https://github.com/TheGroundZero/openvas_to_report/issues/'
    },
    license='GPL-3.0-or-later',
    keywords='OpenVAS OpenVAS-reports Excel xlsxwriter xlsx reporting reports report',
)

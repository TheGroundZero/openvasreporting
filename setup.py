#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name='OpenVAS Reporting',
    version='1.0',
    packages=find_packages(exclude=["tests", "tests.*" "venv"]),
    description='Convert OpenVAS XML report files to Excel reports.',
    author='TheGroundZero',
    author_email='2406013+TheGroundZero@users.noreply.github.com',
    url='https://github.com/TheGroundZero/openvas_to_report',
    project_urls={
        'Source Code': 'https://github.com/TheGroundZero/openvas_to_report',
        'Documentation': 'https://github.com/TheGroundZero/openvas_to_report/blob/master/README.md',
        'Issues': 'https://github.com/TheGroundZero/openvas_to_report/issues/'
    },
    requires=['xlsxwriter'],
    license='BSD',
    keywords='OpenVAS OpenVAS-reports Excel xlsxwriter xlsx reporting reports report'
)

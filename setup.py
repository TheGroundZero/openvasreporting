#!/usr/bin/env python

from setuptools import setup, find_packages

with open('README.md') as f:
    long_description = f.read()

setup(
    name='OpenVAS Reporting',
    description='A tool to convert OpenVAS XML into reports.',
    version='1.0.1b',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='TheGroundZero (@DezeStijn)',
    author_email='2406013+TheGroundZero@users.noreply.github.com',
    url='https://github.com/TheGroundZero/openvas_to_report',
    packages=find_packages(exclude=['tests', 'tests.*', 'venv', '*git*']),
    requires=['xlsxwriter'],
    entry_points={
        'console_scripts': [
            'openvasreporting = openvasreporting:main'
        ]
    },
    project_urls={
        'Source Code': 'https://github.com/TheGroundZero/openvas_to_report',
        'Documentation': 'https://openvas-reporting.stijncrevits.be',
        'Issues': 'https://github.com/TheGroundZero/openvas_to_report/issues/',
    },
    license='GPL-3.0-or-later',
    keywords='OpenVAS OpenVAS-reports Excel xlsxwriter xlsx reporting reports report',
)

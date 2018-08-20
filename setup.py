#!/usr/bin/env python

from setuptools import setup, find_packages


setup(
    name='OpenVAS Reporting',
    version='1.0dev',
    packages=find_packages(exclude=["tests", "tests.*" "venv", "*git*"]),
    description='Convert OpenVAS XML report files to Excel reports.',
    long_description='file: README.md',
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
    keywords='OpenVAS OpenVAS-reports Excel xlsxwriter xlsx reporting reports report',
    entry_points={
        'console_scripts': [
            'openvas_reporting = openvasreporting:main'
        ]
    },
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
)

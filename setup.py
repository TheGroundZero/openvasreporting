#!/usr/bin/env python

from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

# Classifiers see https://pypi.org/classifiers/
setup(
    name='OpenVAS Reporting',
    description='A tool to convert OpenVAS XML into reports.',
    version='1.2.2',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='TheGroundZero (@DezeStijn)',
    author_email='2406013+TheGroundZero@users.noreply.github.com',
    url='https://github.com/TheGroundZero/openvasreporting',
    packages=['openvasreporting'],
    install_requires=['xlsxwriter>=1.0.0', 'python-docx>=0.8.7'],
    python_requires='~=3.7',
    entry_points={
        'console_scripts': ['openvasreporting = openvasreporting:main']
    },
    project_urls={
        'Source Code': 'https://github.com/TheGroundZero/openvasreporting',
        'Documentation': 'https://openvas-reporting.stijncrevits.be',
        'Issues': 'https://github.com/TheGroundZero/openvas_to_report/issues/',
    },
    license='GPL-3.0-or-later',
    keywords='OpenVAS OpenVAS-reports Excel xlsxwriter xlsx reporting reports report',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Framework :: Sphinx',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Other Audience',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Topic :: Documentation :: Sphinx',
        'Topic :: Internet :: Log Analysis',
        'Topic :: Security',
    ],
)

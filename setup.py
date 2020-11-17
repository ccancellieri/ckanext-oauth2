#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of FAO GCIAP Authentication CKAN Extension.
# Copyright (c) 2020 UN FAO
# Author: Carlo Cancellieri - geo.ccancellieri@gmail.com
# License: GPL3

import re

from setuptools import setup, find_packages

from ckanext.gcIAP import __version__, __description__


PYPI_RST_FILTERS = (
    # Remove travis ci badge
    (r'.*travis-ci\.org/.*', ''),
    # Remove pypip.in badges
    (r'.*pypip\.in/.*', ''),
    (r'.*crate\.io/.*', ''),
    (r'.*coveralls\.io/.*', ''),
)


def rst(filename):
    '''
    Load rst file and sanitize it for PyPI.
    Remove unsupported github tags:
     - code-block directive
     - travis ci build badge
    '''
    content = open(filename).read()
    for regex, replacement in PYPI_RST_FILTERS:
        content = re.sub(regex, replacement, content)
    return content


# long_description = '\n'.join((
#     rst('README.md'),
#     rst('CHANGELOG.rst'),
#     ''
# ))

setup(
    name='ckanext-gcIAP',
    version=__version__,
    description=__description__,
    long_description='''
    The GCIAP extension allows site visitors to login through a GCP Identity Aware Proxy server.
    ''',
    keywords='CKAN, GCIAP',
    author='Carlo Cancellieri',
    author_email='geo.ccancellieri@gmail.com',
    url='https://bitbucket.org/cioapps/fao-maps-ckan-authentication/',
    download_url='https://bitbucket.org/cioapps/fao-maps-ckan-authentication/src/v' + __version__,
    license='',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext'],
    include_package_data=True,
    zip_safe=False,
    setup_requires=[
        'nose>=1.3.0'
    ],
    install_requires=[
        'pyjwt==1.7.1',
    ],
    tests_require=[
    ],
    test_suite='nosetests',
    entry_points={
        'ckan.plugins': [
            'gcIAP = ckanext.gcIAP.plugin:GCIAPPlugin',
        ],
        'nose.plugins': [
            'pylons = pylons.test:PylonsPlugin'
        ]
    },
    classifiers=[
        "Development Status :: 0 - Alpha",
        "Environment :: Web Environment",
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Session',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
)

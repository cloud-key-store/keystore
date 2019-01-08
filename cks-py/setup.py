#!/usr/bin/env python

from builtins import str
from distutils.core import setup
import re, sys

from ez_setup import use_setuptools
use_setuptools()
from setuptools import setup, find_packages

VERSION = str(1)
(AUTHOR, EMAIL) = ("Arseny Kurnikov", "arseny.kurniko@aalto")
URL = "https://github.com/cloud-key-store"
LICENSE = "Apache"

if '--format=wininst' in sys.argv:
  SCRIPTS = ['scripts/server.pyw', 'scripts/client.pyw']
else:
  SCRIPTS = ['scripts/server', 'scripts/client']

setup(name="cks",
      version=VERSION.lower(),
      description="Cloud key store Python prototype",
      long_description = """
Cloud Key Store
===============

Summary
-------

Cloud Key Store is a service to store private cryptographic keys,
and perform crypto operations upon requests. The real implementation
utilizes Trusted Hardware (Intel SGX). This is the Python prototype
that provides the same API and is used for testing.

Installation
------------

Run::

   python setup.py install

Use of virtualenv is recommended to not install the package system-wide.

""",
      license=LICENSE,
      author=AUTHOR,
      author_email=EMAIL,
      keywords="cloud gpg",
      url=URL,
      packages=find_packages(exclude=["ez_setup"]),
      scripts=SCRIPTS,
      include_package_data = False,
      install_requires = [], # FIXME
      classifiers = ["Development Status :: 2 - Pre-Alpha",
                     "Intended Audience :: Developers",
                     "Intended Audience :: End Users/Desktop",
                     "License :: OSI Approved :: Apache Software License",
                     "Operating System :: OS Independent",
                     "Programming Language :: Python",
                     "Topic :: Security :: Cryptography",
                     ],
       )

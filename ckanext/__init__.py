# -*- coding: utf-8 -*-

# This file is part of FAO Firebase Authentication CKAN Extension.
# Copyright (c) 2020 UN FAO
# Author: Carlo Cancellieri - geo.ccancellieri@gmail.com
# License: GPL3

# this is a namespace package
try:
    import pkg_resources
    pkg_resources.declare_namespace(__name__)
except ImportError:
    import pkgutil
    __path__ = pkgutil.extend_path(__path__, __name__)

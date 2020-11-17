# This file is part of FAO GCIAP Authentication CKAN Extension.
# Copyright (c) 2020 UN FAO
# Author: Carlo Cancellieri - geo.ccancellieri@gmail.com
# License: GPL3


from __future__ import unicode_literals

import logging

from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.lib.base as base
import ckan.plugins.toolkit as toolkit
import gcIAP

import requests
import os
from urllib2 import Request, urlopen

from six.moves.urllib.parse import urljoin

log = logging.getLogger(__name__)


class GCIAPController(base.BaseController):

    def __init__(self):
        self.GCIAPHelper = gcIAP.GCIAPHelper()

    def login(self):
        log.debug('login')
        
        # TODO redirect to the previous page... (environ??)
        pp=self.GCIAPHelper._get_previous_page(self.GCIAPHelper.ckan_url)
        log.debug('previous page: '+pp)
        # toolkit.redirect_to(pp.encode('utf-8'))
        
        self.GCIAPHelper.challenge(pp)

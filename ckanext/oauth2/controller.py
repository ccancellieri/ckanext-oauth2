# -*- coding: utf-8 -*-
# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import logging
import constants

from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.lib.base as base
import ckan.plugins.toolkit as toolkit
import oauth2

import requests
import os
from urllib2 import Request, urlopen
from ckanext.oauth2.plugin import _get_previous_page

from six.moves.urllib.parse import urljoin

log = logging.getLogger(__name__)


class OAuth2Controller(base.BaseController):

    def __init__(self):
        self.oauth2helper = oauth2.OAuth2Helper()

    def login(self):
        log.debug('login')
        
        # TODO redirect to the previous page... (environ??)
        pp=_get_previous_page("https://data.review.fao.org/ckan")
        log.debug('previous page: '+pp)
        # toolkit.redirect_to(pp.encode('utf-8'))
        
        self.oauth2helper.challenge(pp)

    def callback(self):
        log.debug("-----CALLBACK---")
        try:
            
            # authorization_header = "x-goog-iap-jwt-assertion".lower()
            authorization_header = "authorization"
            apikey = toolkit.request.headers.get(authorization_header, '')
            if authorization_header == "authorization":
                if apikey.startswith('Bearer '):
                    apikey = apikey[7:].strip()
            
    #        authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", 'Authorization').lower()
            log.debug("-----AUTH_HEADER_KEY---"+authorization_header)
            for h in toolkit.response.headers:
                log.debug("----HEADERS:---"+h)
            
            
#        apikey = toolkit.request.headers.get(self.oauth2helper.authorization_header, '')
            user_name = None
            log.debug("-----CALLBACK---3"+apikey)

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
            if apikey:
                token = {'access_token': apikey}
                
                log.debug("-----CALLBACK---1")
                # token = self.oauth2helper.get_token()
                log.debug("-----CALLBACK---2")
                user_name = self.oauth2helper.token_identify(token)
                log.debug("-----CALLBACK---3")
                self.oauth2helper.remember(user_name)
                log.debug("-----CALLBACK---4")
                self.oauth2helper.update_token(user_name, token)
                log.debug("-----CALLBACK---5---")

        except Exception as e:

            session.save()

            # If the callback is called with an error, we must show the message
            error_description = toolkit.request.GET.get('error_description')
            if not error_description:
                if e.message:
                    error_description = e.message
                elif hasattr(e, 'description') and e.description:
                    error_description = e.description
                elif hasattr(e, 'error') and e.error:
                    error_description = e.error
                else:
                    error_description = type(e).__name__
            log.exception("-----CALLBACK---EXC")
            
            toolkit.response.status_int = 302
#            redirect_url = oauth2.get_came_from(toolkit.request.params.get('state'))
#            redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
# TODO check REDIRECT
            toolkit.response.location = self.oauth2helper.ckan_url
            helpers.flash_error(error_description)

        came_from = self.oauth2helper._get_previous_page(self.oauth2helper.ckan_url)
	    log.debug('previous page: '+came_from)
        toolkit.redirect_to(came_from.encode('utf-8'))

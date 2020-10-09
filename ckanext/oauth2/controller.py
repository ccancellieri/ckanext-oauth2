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

log = logging.getLogger(__name__)


class OAuth2Controller(base.BaseController):

    def __init__(self):
        self.oauth2helper = oauth2.OAuth2Helper()

    def login(self):
        log.debug('login')

        # Log in attemps are fired when the user is not logged in and they click
        # on the log in button

        # Get the page where the user was when the loggin attemp was fired
        # When the user is not logged in, he/she should be redirected to the dashboard when
        # the system cannot get the previous page
        came_from_url = _get_previous_page(constants.INITIAL_PAGE)

        self.oauth2helper.challenge(came_from_url)

    def _login(self):
        log.debug('login')

        res = urlopen(Request(self.oauth2helper.authorization_endpoint.encode('utf-8')))
#        res = requests.get(self.oauth2helper.authorization_endpoint.encode('utf-8'))
#                    headers=headers)

        for h in res.headers:
            log.debug("----HEADERS:---"+h)

        environ = toolkit.request.environ
#        if u'repoze.who.plugins' in environ:
#                pth = getattr(environ[u'repoze.who.plugins'],u'')
        for e in environ:
#            log.debug("........u:"+environ.get(u'user'))
            log.debug("--------ENVIRON:"+e)
        authorization_header = "x-goog-iap-jwt-assertion".lower()
#        authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", 'Authorization').lower()

        apikey = toolkit.request.headers.get(authorization_header, '')
#        apikey = toolkit.request.headers.get(self.oauth2helper.authorization_header, '')
        user_name = None


        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {'access_token': apikey}
                user_name = self.oauth2helper.identify(token)
                for e in environ:
                   log.debug("--------ENVIRON:"+e)
                #self.oauth2helper.remember(user_name)
                #self.oauth2helper.update_token(user_name, token)
                #self.oauth2helper.redirect_from_callback()
                #environ['repoze.who.identity']['repoze.who.userid']=user_name
            except Exception:
                log.exception("-----------EXCEPTION")
                pass

        toolkit.redirect_to("https://data.review.fao.org/ckan".encode('utf-8'))

        # Get the params that were posted to /user/login.
        params = toolkit.request.params

	for p in params:
            log.debug("-------------Req:---"+p)

    def callback(self):
        log.debug("-----CALLBACK---")
        try:
            log.debug("-----CALLBACK---1")
            #token = self.oauth2helper.get_token()
            
            log.debug("-----CALLBACK---2")
            #user_name = self.oauth2helper.identify(token)
            
            authorization_header = "x-goog-iap-jwt-assertion".lower()
    #        authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", 'Authorization').lower()
            log.debug("-----AUTH_HEADER_KEY---"+authorization_header)
            for h in toolkit.response.headers:
                log.debug("----HEADERS:---"+h)
            
            apikey = toolkit.request.headers.get(authorization_header, '')
#        apikey = toolkit.request.headers.get(self.oauth2helper.authorization_header, '')
            user_name = None
            log.debug("-----CALLBACK---3"+apikey)


        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
            if apikey:
                token = {'access_token': apikey}
                user_name = self.oauth2helper.identify(token)
 #                for e in environ:
 #                   log.debug("--------ENVIRON:"+e)
                log.debug("-----CALLBACK---11")
                self.oauth2helper.remember(user_name)
                #self.oauth2helper.update_token(user_name, token)
                log.debug("-----CALLBACK---31")
                #environ['repoze.who.identity']['repoze.who.userid']=user_name

            self.oauth2helper.redirect_from_callback()

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
            redirect_url = oauth2.get_came_from(toolkit.request.params.get('state'))
            redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
            toolkit.response.location = redirect_url
            helpers.flash_error(error_description)

    def _callback(self):
        log.debug("-----CALLBACK---")
        try:
            log.debug("-----CALLBACK---1")
            token = self.oauth2helper.get_token()
            log.debug("-----CALLBACK---2")
            user_name = self.oauth2helper.identify(token)
            log.debug("-----CALLBACK---3")
            self.oauth2helper.remember(user_name)
            log.debug("-----CALLBACK---4")
            self.oauth2helper.update_token(user_name, token)
            log.debug("-----CALLBACK---5")
            self.oauth2helper.redirect_from_callback()
            log.debug("-----CALLBACK---6")

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
            redirect_url = oauth2.get_came_from(toolkit.request.params.get('state'))
            redirect_url = '/' if redirect_url == constants.INITIAL_PAGE else redirect_url
            toolkit.response.location = redirect_url
            helpers.flash_error(error_description)

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
import oauth2
import os
import requests
from functools import partial
from ckan import plugins
from ckan.common import g
from ckan.plugins import toolkit

import ckan.model as model

log = logging.getLogger(__name__)


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)




class OAuth2Plugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IConfigurer)

    def __init__(self, name=None):
        log.debug('Init Firebase extension')
        self.oauth2helper = oauth2.OAuth2Helper()

    def before_map(self, m):
        log.debug('Setting up the redirections to the Firebase service')

        m.connect('/user/login',
                  controller='ckanext.oauth2.controller:OAuth2Controller',
                  action='login')

        # We need to handle petitions received to the Callback URL
        # since some error can arise and we need to process them
        # m.connect(self.oauth2helper.redirect_back_path,#'/oauth2/callback',
        #           controller='ckanext.oauth2.controller:OAuth2Controller',
        #           action='callback')

        #########################################################
        ### TODO disable the following paths!!!

        # Redirect the user to the OAuth service register page
        if self.register_url:
            m.redirect('/user/register', self.register_url)

        # Redirect the user to the OAuth service reset page
        if self.reset_url:
            m.redirect('/user/reset', self.reset_url)

        # Redirect the user to the OAuth service reset page
        if self.edit_url:
            m.redirect('/user/edit/{user}', self.edit_url)
        #########################################################
        
        return m

    def identify(self):
        log.debug('identify')
        environ = toolkit.request.environ
        
        user_name = self.bearer()
        # log in the user using session.
        if not user_name and 'repoze.who.identity' in environ:
            user_name = environ['repoze.who.identity']['repoze.who.userid']
            log.info('User %s logged using session' % user_name)
        
#        if toolkit.c.usertoken:
#            user_name = toolkit.c.usertoken
#            log.info('User %s logged using token' % user_name)
        # TODO shared session or use DB if using CLUSTER

        # If we have been able to log in the user (via API or Session)
        if user_name:
            log.debug("-------------Username from repoze: "+ user_name)
            if self.oauth2helper.check_user_token_exp(user_name):
                g.user = None
                #TODO needed?
#                toolkit.c.user = None
#                environ['repoze.who.identity']['repoze.who.userid'] = None
                return self.oauth2helper.renew_token(user_name)
            else:
                g.user = user_name
#                toolkit.c.user = user_name
#                toolkit.c.usertoken = user_name
                log.warn("-------------Username and token valid: "+user_name)
        else:
            g.user = None
#            toolkit.c.user = user_name
#            toolkit.c.usertoken = user_name

    def bearer(self):
        log.debug("-------------BEARER")
        # authorization_header = "x-goog-iap-jwt-assertion".lower()
        authorization_header = "authorization"
        apikey = toolkit.request.headers.get(authorization_header, '')
        if authorization_header == "authorization":
            if apikey.startswith('Bearer '):
                apikey = apikey[7:].strip()

#        for e in toolkit.request.environ:
#            log.debug("environ: "+e+" v: "+toolkit.request.environ[e])
#        log.debug("-----AUTH_HEADER_KEY---"+authorization_header)
#        for h in toolkit.response.headers:
#            log.debug("----HEADERS:---"+h)

        user_name = None
        log.debug("-------------APIKEY: "+apikey)

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            token = {'access_token': apikey}
            user_name = self.oauth2helper.token_identify(token)
            self.oauth2helper.update_token(user_name, token)
            self.oauth2helper.remember(user_name)
        return user_name

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset
        }

    def update_config(self, config):
        # Update our configuration
        self.register_url = os.environ.get("CKAN_OAUTH2_REGISTER_URL", config.get('ckan.oauth2.register_url', None))
        self.reset_url = os.environ.get("CKAN_OAUTH2_RESET_URL", config.get('ckan.oauth2.reset_url', None))
        self.edit_url = os.environ.get("CKAN_OAUTH2_EDIT_URL", config.get('ckan.oauth2.edit_url', None))
        self.authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", config.get('ckan.oauth2.authorization_header', 'Authorization')).lower()

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, 'templates')

# This file is part of FAO Firebase Authentication CKAN Extension.
# Copyright (c) 2020 UN FAO
# Author: Carlo Cancellieri - geo.ccancellieri@gmail.com
# License: GPL3

import logging
import firebase
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




class FirebasePlugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IConfigurer)

    def __init__(self, name=None):
        log.debug('Init Firebase extension')
        self.FirebaseHelper = firebase.FirebaseHelper()

    def before_map(self, m):
        log.debug('Setting up the redirections to the Firebase service')

        m.connect('/user/login',
                  controller='ckanext.firebase.controller:firebaseController',
                  action='login')

        # Redirect the user to the Firebase resest service
        if self.reset_url:
            m.redirect('/user/reset', self.reset_url)

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
            if self.FirebaseHelper.check_user_token_exp(user_name):
                g.user = None
                #TODO needed?
#                toolkit.c.user = None
#                environ['repoze.who.identity']['repoze.who.userid'] = None
                return self.FirebaseHelper.renew_token(user_name)
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

        # This API Key is not the one of CKAN, it's the one provided by the firebase Service
        if apikey:
            token = {'access_token': apikey}
            user_name = self.FirebaseHelper.token_identify(token)
            self.FirebaseHelper.update_token(user_name, token)
            self.FirebaseHelper.remember(user_name)
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
        self.reset_url = os.environ.get("CKAN_FIREBASE_RESET_URL", config.get('ckan.firebase.reset_url', None))
        self.authorization_header = os.environ.get("CKAN_FIREBASE_AUTHORIZATION_HEADER", config.get('ckan.firebase.authorization_header', 'Authorization')).lower()

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, 'templates')

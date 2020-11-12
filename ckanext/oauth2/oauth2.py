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

import base64
import ckan.model as model
import db
import json
import logging
from six.moves.urllib.parse import urljoin
import os

from base64 import b64encode, b64decode
from ckan.plugins import toolkit
from oauthlib.oauth2 import InsecureTransportError
import requests
from requests_oauthlib import OAuth2Session
import six
from ckan.plugins import toolkit
import jwt

import constants
from datetime import datetime

log = logging.getLogger(__name__)


def generate_state(url):
    return b64encode(bytes(json.dumps({constants.CAME_FROM_FIELD: url})))


def get_came_from(state):
    return json.loads(b64decode(state)).get(constants.CAME_FROM_FIELD, '/')


REQUIRED_CONF = ("authorization_endpoint", "token_endpoint", "client_id", "client_secret", "profile_api_url", "profile_api_user_field", "profile_api_mail_field")


class OAuth2Helper(object):

    def __init__(self):

        self.verify_https = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '') == ""
        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.jwt_enable = six.text_type(os.environ.get('CKAN_OAUTH2_JWT_ENABLE', toolkit.config.get('ckan.oauth2.jwt.enable',''))).strip().lower() in ("true", "1", "on")

        self.legacy_idm = six.text_type(os.environ.get('CKAN_OAUTH2_LEGACY_IDM', toolkit.config.get('ckan.oauth2.legacy_idm', ''))).strip().lower() in ("true", "1", "on")
        self.authorization_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_AUTHORIZATION_ENDPOINT', toolkit.config.get('ckan.oauth2.authorization_endpoint', ''))).strip()
        self.token_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_TOKEN_ENDPOINT', toolkit.config.get('ckan.oauth2.token_endpoint', ''))).strip()
        self.profile_api_url = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_URL', toolkit.config.get('ckan.oauth2.profile_api_url', ''))).strip()
        self.client_id = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_ID', toolkit.config.get('ckan.oauth2.client_id', ''))).strip()
        self.client_secret = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_SECRET', toolkit.config.get('ckan.oauth2.client_secret', ''))).strip()
        self.scope = six.text_type(os.environ.get('CKAN_OAUTH2_SCOPE', toolkit.config.get('ckan.oauth2.scope', ''))).strip()
        self.rememberer_name = six.text_type(os.environ.get('CKAN_OAUTH2_REMEMBER_NAME', toolkit.config.get('ckan.oauth2.rememberer_name', 'auth_tkt'))).strip()
        self.profile_api_user_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_USER_FIELD', toolkit.config.get('ckan.oauth2.profile_api_user_field', ''))).strip()
        self.profile_api_fullname_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD', toolkit.config.get('ckan.oauth2.profile_api_fullname_field', ''))).strip()
        self.profile_api_mail_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_MAIL_FIELD', toolkit.config.get('ckan.oauth2.profile_api_mail_field', ''))).strip()
        self.profile_api_groupmembership_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD', toolkit.config.get('ckan.oauth2.profile_api_groupmembership_field', ''))).strip()
        self.sysadmin_group_name = six.text_type(os.environ.get('CKAN_OAUTH2_SYSADMIN_GROUP_NAME', toolkit.config.get('ckan.oauth2.sysadmin_group_name', ''))).strip()
	self.redirect_uri = urljoin(urljoin(toolkit.config.get('ckan.site_url', 'http://localhost:5000'), toolkit.config.get('ckan.root_path')+'/'), constants.REDIRECT_URL)
#        self.authorization_header = os.environ.get("CKAN_OAUTH2_AUTHORIZATION_HEADER", config.get('ckan.oauth2.authorization_header', 'Authorization')).lower()
#	self.redirect_uri = toolkit.config.get('ckan.site_url', 'http://localhost:5000') + toolkit.config.get('ckan.root_path')+'/'+ constants.REDIRECT_URL
	    
        self.ckan_url = urljoin(toolkit.config.get('ckan.site_url', 'http://localhost:5000'), toolkit.config.get('ckan.root_path'))
        
        ## proxy-backend url which is proxied by the GCIP IAP
        self.authorization_endpoint = six.text_type(toolkit.config.get('ckan.firebase.authorization_endpoint', 'https://data.review.fao.org/ckan-auth')).strip()
        ## local ckan ip used to redirect back the call from proxy-backend (shipping the jwt token)
        self.local_ip = six.text_type(toolkit.config.get('ckan.firebase.local_ip', 'http://localhost')).strip()
        ## path mapped by the controller which will register/identify the user after the challenge (callback)
        self.redirect_back_path = six.text_type(toolkit.config.get('ckan.firebase.redirect_back_path', '/oauth2/callback')).strip()
        

# toolkit.config.get('ckan.site_url', 'http://localhost:5000'), toolkit.config.get('ckan.root_path')
        
        #" https://data.review.fao.org/ckan-auth ?redirect_uri= https://10.128.0.18 /ckan /oauth2/callback"
        
        # Init db
        db.init_db(model)

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def challenge(self, came_from=None):
        if not came_from:
            came_from = self._get_previous_page(self.ckan_url)
        log.debug("CAME_FROM: "+came_from)
# woraround: can't pass throught the loadbalancer... (it wipe out jwt token)
	came_from = came_from.replace(toolkit.config.get('ckan.site_url'),self.local_ip)

#        auth_url=self.authorization_endpoint+'?redirect_uri='+self.local_ip+toolkit.config.get('ckan.root_path')+self.redirect_back_path+'&came_from='+came_from
        auth_url=self.authorization_endpoint+'?redirect_uri='+came_from
        #auth_url=self.authorization_endpoint
#+came_from
#+self.local_ip+toolkit.config.get('ckan.root_path')+came_from
        
        log.debug('Challenge: Redirecting challenge to page {0}'.format(auth_url))
        
        return toolkit.redirect_to(auth_url.encode('utf-8'))

    def token_identify(self, token):
        
        def flatten_dict(d):
            def expand(key, value):
                if isinstance(value, dict):
                    return [ (key + '.' + k, v) for k, v in flatten_dict(value).items() ]
                else:
                    return [ (key, value) ]
            items = [ item for k, v in d.items() for item in expand(k, v) ]
            return dict(items)

        access_token = bytes(token['access_token'])
        try:
            # TODO VALIDATION
            # https://cloud.google.com/iap/docs/signed-headers-howto#iap_validate_jwt-python
            user_data = jwt.decode(access_token, verify=False)
            log.debug("JWT:"+str(user_data))
        except Exception as e:
#jwt.ExpiredSignatureError:
            log.exception('Unable to validate JWT token: '+str(e))
            raise
            
        user = self.user_json(flatten_dict(user_data))
        
        self.update_token(user.name, token)
        log.info('Token for user %s has been updated properly' % user.name)
        
        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        return user.name

    def user_json(self, user_data):
        email = user_data[self.profile_api_mail_field]
        user_name = user_data[self.profile_api_user_field]

        # In CKAN can exists more than one user associated with the same email
        # Some providers, like Google and FIWARE only allows one account per email
        user = None
        users = model.User.by_email(email)
        if len(users) == 1:
            user = users[0]

        # If the user does not exist, we have to create it...
        if user is None:
            user = model.User(email=email)

        # Now we update his/her user_name with the one provided by the OAuth2 service
        # In the future, users will be obtained based on this field
        user.name = user_name

        # Update fullname
        if self.profile_api_fullname_field != "" and self.profile_api_fullname_field in user_data:
            user.fullname = user_data[self.profile_api_fullname_field]

        # Update sysadmin status
        if self.profile_api_groupmembership_field != "" and self.profile_api_groupmembership_field in user_data:
            user.sysadmin = self.sysadmin_group_name in user_data[self.profile_api_groupmembership_field]

        return user

    def _get_rememberer(self, environ):
        plugins = environ.get('repoze.who.plugins', {})
        return plugins.get(self.rememberer_name)

    def _get_previous_page(self, default_page):
        from urlparse import urlparse
        log.debug("GET_PREVIOUS_PAGE: "+str(toolkit.request))

        for p in toolkit.request.params:
            log.debug("req_param: "+p+" v: "+toolkit.request.params[p])
        log.debug("req_url: "+toolkit.request.url)
        for h in toolkit.request.headers:
            log.debug("header_param: "+h+" v: "+toolkit.request.headers[h])

#        log.debug("GET_PREVIOUS_PAGE: "+str(toolkit.request))
        if 'came_from' not in toolkit.request.params:
            came_from_url = toolkit.request.headers.get('Referer', default_page)
            log.debug("__get_previous_page: using Referer header: "+ came_from_url)
        else:
            came_from_url = toolkit.request.params.get('came_from', default_page)
            log.debug("__get_previous_page: using came_from param: "+ came_from_url)
        came_from_url_parsed = urlparse(came_from_url)

        # Avoid redirecting users to external hosts
        if came_from_url_parsed.netloc != '' and came_from_url_parsed.netloc != toolkit.request.host:
            came_from_url = default_page

        # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
        # he/she must be redirected to the dashboard
        pages = ['/', '/user/logged_out_redirect']
        if came_from_url_parsed.path in pages:
            came_from_url = default_page

        log.debug("__get_previous_page: FINALLY: "+ came_from_url)
        return came_from_url

    def remember(self, user_name):
        '''
        Remember the authenticated identity.

        This method simply delegates to another IIdentifier plugin if configured.
        '''
        log.debug('Repoze OAuth remember')
        environ = toolkit.request.environ
        rememberer = self._get_rememberer(environ)
        identity = {'repoze.who.userid': user_name}
        log.debug("-------------UID:"+user_name)
        headers = rememberer.remember(environ, identity)
        
        return self.stream_url(headers)

    def stream_url(self, headers):
        #import flask
#        url = flask.request.args.get('url')
        url = toolkit.request.headers.get('Referer')
#r= requests.get(url)
        response = toolkit.request.response
#response = flask.make_response()
#        response.data = r.content
        response.headers = headers
#        response.headers['Content-Type'] = r.headers['Content-Type']
        # Preserve filename if possible
#        if 'Content-Disposition' in r.headers:
#            response.headers['Content-Disposition'] = r.headers['Content-Disposition'].replace("attachment;", "inline;")
        
        return response 

    def get_stored_token(self, user_name):
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if user_token:
            return {
                'access_token': user_token.access_token
            }
    
    # returns true if expired
    def check_token_exp(self, decoded_token):
        log.debug("-----Token expiration: "+str(datetime.utcfromtimestamp(decoded_token['exp'])))
        log.debug("-----Current time: "+str(datetime.utcnow()))
        # return datetime.utcfromtimestamp(decoded_token['exp']) > datetime.utcnow()
#        return True
        return datetime.fromtimestamp(decoded_token['exp']) < datetime.utcnow()


    def check_user_token_exp(self, user_name):
        log.debug("-------------GETSTOREDTOKEN")
        user_token = self.get_stored_token(user_name)
        if not user_token:
            log.warn("Missing stored token")
            return False
        access_token = user_token['access_token']
        decoded_token = jwt.decode(access_token, verify=False)
        return self.check_token_exp(decoded_token)
    
    def update_token(self, user_name, token):

        user_token = db.UserToken.by_user_name(user_name=user_name)

        # Create the user if it does not exist
        if not user_token:
            user_token = db.UserToken()
            user_token.user_name = user_name

        # Save the new token
        user_token.access_token = token['access_token']
        
        model.Session.add(user_token)
        model.Session.commit()

        
    def renew_token(self, user_name):
        # DO NOT TRAP -> DOES NOT REDIRECT
        # try:
        log.warning("-------> METHOD: ->"+toolkit.request.environ['REQUEST_METHOD'])
        if toolkit.request.environ['REQUEST_METHOD'] == 'POST':
            log.warning("It's a POST request NOT redirecting...."+self.ckan_url+toolkit.request.path)
        else:
            log.warning("Redirecting...."+self.ckan_url+toolkit.request.path)
       # pp=self._get_previous_page(self.ckan_url)
            return self.challenge(self.ckan_url+toolkit.request.path)
#        return self.challenge(self.ckan_url+toolkit.request.path)
        # except Exception as e:
        #     log.exception("-----------EXCEPTION-"+str(e))
    #logout
                    # g.user = ''
                    # toolkit.c.user = ''
                    
                #pp = environ['HTTP_REFERER']
#ERRORS?                pp=toolkit.url_for(toolkit.request.path, _external=True)
#                log.debug('previous page: '+pp)
                    
#                    auth_url='https://data.review.fao.org/ckan-auth/?gcp-iap-mode=SESSION_REFRESHER'
# TODO redirect to the previous page... (environ??)
	#	return toolkit.redirect_to(controller='ckanext.oauth2.controller:OAuth2Controller', action='login')
                    #return toolkit.redirect_to(controller='ckanext.oauth2.controller:OAuth2Controller', action='login')
                    # toolkit.get_action('login')(toolkit.c)
    #     token = self.get_stored_token(user_name)
    #     if token:
    #         client = OAuth2Session(self.client_id, token=token, scope=self.scope)
    #         try:
    #             token = client.refresh_token(self.token_endpoint, client_secret=self.client_secret, client_id=self.client_id, verify=self.verify_https)
    #         except requests.exceptions.SSLError as e:
    #             # TODO search a better way to detect invalid certificates
    #             if "verify failed" in six.text_type(e):
    #                 raise InsecureTransportError()
    #             else:
    #                 raise
    #         self.update_token(user_name, token)
    #         log.info('Token for user %s has been updated properly' % user_name)
    #         return token
    #     else:
    #         log.warn('User %s has no refresh token' % user_name)

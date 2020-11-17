# This file is part of FAO Firebase Authentication CKAN Extension.
# Copyright (c) 2020 UN FAO
# Author: Carlo Cancellieri - geo.ccancellieri@gmail.com
# License: GPL3


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
import requests
import six
from ckan.plugins import toolkit

import jwt
from datetime import datetime

log = logging.getLogger(__name__)

CAME_FROM_FIELD = 'came_from'

def generate_state(url):
    return b64encode(bytes(json.dumps({CAME_FROM_FIELD: url})))


def get_came_from(state):
    return json.loads(b64decode(state)).get(CAME_FROM_FIELD, '/')


REQUIRED_CONF = ("authorization_endpoint", "profile_api_user_field", "profile_api_mail_field")


class FirebaseHelper(object):

    def __init__(self):

        #self.authorization_endpoint = six.text_type(toolkit.config.get('ckan.firebase.authorization_endpoint', 'https://data.review.fao.org/ckan-auth')).strip()
        self.authorization_endpoint = six.text_type(os.environ.get('CKAN_FIREBASE_AUTHORIZATION_ENDPOINT', toolkit.config.get('ckan.firebase.authorization_endpoint', ''))).strip()

        self.rememberer_name = six.text_type(os.environ.get('CKAN_FIREBASE_REMEMBER_NAME', toolkit.config.get('ckan.firebase.rememberer_name', 'auth_tkt'))).strip()
        
        #self.authorization_header = os.environ.get("CKAN_FIREBASE_AUTHORIZATION_HEADER", config.get('ckan.firebase.authorization_header', 'Authorization')).lower()

        # self.redirect_uri = urljoin(urljoin(toolkit.config.get('ckan.site_url', 'http://localhost:5000'), toolkit.config.get('ckan.root_path')+'/'), constants.REDIRECT_URL)
        self.ckan_url = urljoin(toolkit.config.get('ckan.site_url', 'http://localhost:5000'), toolkit.config.get('ckan.root_path'))
        ## proxy-backend url which is proxied by the GCIP IAP
        ## local ckan ip used to redirect back the call from proxy-backend (shipping the jwt token)
        self.local_ip = six.text_type(toolkit.config.get('ckan.firebase.local_ip', 'http://localhost')).strip()
        
        self.profile_api_user_field = six.text_type(os.environ.get('CKAN_FIREBASE_PROFILE_API_USER_FIELD', toolkit.config.get('ckan.firebase.profile_api_user_field', ''))).strip()
        self.profile_api_fullname_field = six.text_type(os.environ.get('CKAN_FIREBASE_PROFILE_API_FULLNAME_FIELD', toolkit.config.get('ckan.firebase.profile_api_fullname_field', ''))).strip()
        self.profile_api_mail_field = six.text_type(os.environ.get('CKAN_FIREBASE_PROFILE_API_MAIL_FIELD', toolkit.config.get('ckan.firebase.profile_api_mail_field', ''))).strip()
        self.profile_api_groupmembership_field = six.text_type(os.environ.get('CKAN_FIREBASE_PROFILE_API_GROUPMEMBERSHIP_FIELD', toolkit.config.get('ckan.firebase.profile_api_groupmembership_field', ''))).strip()
        self.sysadmin_group_name = six.text_type(os.environ.get('CKAN_FIREBASE_SYSADMIN_GROUP_NAME', toolkit.config.get('ckan.firebase.sysadmin_group_name', ''))).strip()
	            
        # Init db
        db.init_db(model)

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required Firebase Auth conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def challenge(self, came_from=None):
        if not came_from:
            came_from = self._get_previous_page(self.ckan_url)
        log.debug("CAME_FROM: "+came_from)
        # woraround: can't pass throught the loadbalancer... (it wipe out jwt token)
        came_from = came_from.replace(toolkit.config.get('ckan.site_url'),self.local_ip)

        auth_url=self.authorization_endpoint+'?redirect_uri='+came_from
        
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


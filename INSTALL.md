To install the plugin, **enter your virtualenv** and install the package using `pip` as follows:

```
pip install ckanext-firebase
```

Add the following to your CKAN `.ini` (generally `/etc/ckan/default/production.ini`) file:

```
ckan.plugins = firebase <other-plugins>

## OAuth2 configuration

ckan.firebase.register_url = https://YOUR_OAUTH_SERVICE/users/sign_up
ckan.firebase.reset_url = https://YOUR_OAUTH_SERVICE/users/password/new
ckan.firebase.edit_url = https://YOUR_OAUTH_SERVICE/settings
ckan.firebase.authorization_endpoint = https://YOUR_OAUTH_SERVICE/authorize
ckan.firebase.token_endpoint = https://YOUR_OAUTH_SERVICE/token
ckan.firebase.profile_api_url = https://YOUR_OAUTH_SERVICE/user
ckan.firebase.client_id = YOUR_CLIENT_ID
ckan.firebase.client_secret = YOUR_CLIENT_SECRET
ckan.firebase.scope = profile other.scope
ckan.firebase.rememberer_name = auth_tkt
ckan.firebase.profile_api_user_field = JSON_FIELD_TO_FIND_THE_USER_IDENTIFIER
ckan.firebase.profile_api_fullname_field = JSON_FIELD_TO_FIND_THE_USER_FULLNAME
ckan.firebase.profile_api_mail_field = JSON_FIELD_TO_FIND_THE_USER_MAIL
ckan.firebase.authorization_header = FIREBASE_HEADER
```

> **Note**: In case you are using FIWARE as OAuth2 provider, this is the concrete OAuth2 configuration you should use (e.g. using FIWARE Lab):
>
> ```
> ## OAuth2 configuration
> ckan.firebase.register_url = https://account.lab.fiware.org/users/sign_up
> ckan.firebase.reset_url = https://account.lab.fiware.org/users/password/new
> ckan.firebase.edit_url = https://account.lab.fiware.org/idm/settings
> ckan.firebase.authorization_endpoint = https://account.lab.fiware.org/firebase/authorize
> ckan.firebase.token_endpoint = https://account.lab.fiware.org/firebase/token
> ckan.firebase.profile_api_url = https://account.lab.fiware.org/user
> ckan.firebase.client_id = YOUR_CLIENT_ID
> ckan.firebase.client_secret = YOUR_CLIENT_SECRET
> ckan.firebase.scope = all_info
> ckan.firebase.profile_api_user_field = id
> ckan.firebase.profile_api_fullname_field = displayName
> ckan.firebase.profile_api_mail_field = email
> ckan.firebase.authorization_header = Authorization
> ```
>
> And this is an example for using Google as OAuth2 provider:
>
> ```
> ## OAuth2 configuration
> ckan.firebase.authorization_endpoint = https://accounts.google.com/o/firebase/auth
> ckan.firebase.token_endpoint = https://accounts.google.com/o/firebase/token
> ckan.firebase.profile_api_url = https://www.googleapis.com/firebase/v1/userinfo
> ckan.firebase.client_id = YOUR_CLIENT_ID
> ckan.firebase.client_secret = YOUR_CLIENT_SECRET
> ckan.firebase.scope = openid email profile
> ckan.firebase.profile_api_user_field = email
> ckan.firebase.profile_api_fullname_field = name
> ckan.firebase.profile_api_mail_field = email
> ckan.firebase.authorization_header = Authorization
> ```

You can also use environment variables to configure this plugin, the name of the environment variables are:

- `CKAN_FIREBASE_REGISTER_URL`
- `CKAN_FIREBASE_RESET_URL`
- `CKAN_FIREBASE_EDIT_URL`
- `CKAN_FIREBASE_AUTHORIZATION_ENDPOINT`
- `CKAN_FIREBASE_TOKEN_ENDPOINT`
- `CKAN_FIREBASE_PROFILE_API_URL`
- `CKAN_FIREBASE_CLIENT_ID`
- `CKAN_FIREBASE_CLIENT_SECRET`
- `CKAN_FIREBASE_SCOPE`
- `CKAN_FIREBASE_REMEMBERER_NAME`
- `CKAN_FIREBASE_PROFILE_API_USER_FIELD`
- `CKAN_FIREBASE_PROFILE_API_FULLNAME_FIELD`
- `CKAN_FIREBASE_PROFILE_API_MAIL_FIELD`
- `CKAN_FIREBASE_AUTHORIZATION_HEADER`

**Additional notes**:
* This extension only works when your CKAN instance is working over HTTPS, since OAuth 2.0 depends on it. You can follow the [Starting CKAN over HTTPs tutorial](https://github.com/conwetlab/ckanext-firebase/wiki/Starting-CKAN-over-HTTPs) to learn how to do that. 
* You can run the extension to connect to a OAuth2 server using HTTP, or to a server using an invalid certificate (e.g. a self-signed one), by editing the file `/etc/apache2/envvars` and adding the following environment variable, or directly exporting the variable in the shell if you are executing development server with "paster serve ..." :
```
export OAUTHLIB_INSECURE_TRANSPORT=True
```
* The callback URL that you should set on your OAuth 2.0 is: `https://YOUR_CKAN_INSTANCE/firebase/callback`, replacing `YOUR_CKAN_INSTANCE` by the machine and port where your CKAN instance is running.
* If you are connecting to FIWARE KeyRock v6 or v5, you have to set `ckan.firebase.legacy_idm` to `true`.

Refer to this document for integration between CKAN and WSO2-IS IDM using firebase with settings:
https://github.com/conwetlab/ckanext-firebase/wiki/Integration-between-WSO2-IS-and-CKAN-using-Oauth2

gcIAP CKAN extension
=====================


ckan.plugins = gcIAP ...
## gcIAP configuration
# local ip of the machine
# we need that to perform internal redirection to skip the LB
ckan.gcIAP.local_ip= https://10.128.0.18

# Used to login:
# must be an nginx IAP proxied endpoint:
# location /ckan-auth {
#    proxy_set_header X-Goog-Iap-Jwt-Assertion $HTTP_X-Goog-IAP-Jwt-Assertion;
#    proxy_pass $arg_redirect_uri;
# }
ckan.gcIAP.authorization_endpoint = https://data.review.fao.org/ckan-auth

# Used to logout
ckan.gcIAP.reset_url= https://data.review.fao.org/ckan-auth?gcp-iap-mode=GCIP_SIGNOUT

# the header used to get the JWT token (default: X-Goog-Iap-Jwt-Assertion )
ckan.gcIAP.authorization_header = X-Goog-Iap-Jwt-Assertion

# the flatten path of the field in the token to use as username
ckan.gcIAP.profile_api_user_field = gcip.email
# the flatten path of the field in the token to use as name
ckan.gcIAP.profile_api_fullname_field = gcip.firebase.name
# the flatten path of the field in the token to use as email
ckan.gcIAP.profile_api_mail_field = gcip.email

#ckan.gcIAP.profile_api_groupmembership_field
#ckan.gcIAP.sysadmin_group_name
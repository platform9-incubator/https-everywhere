# Setting up keystone 'tokenless' TLS client authentication

The configuration, tools and documentation in this directory show how to configure keystone to accept x509 client certificates to authenticate connections from clients. The configuration is described in the OpenStack docs [here](https://docs.openstack.org/keystone/pike/advanced-topics/configure_tokenless_x509.html).

Steps include:
* installing mod_ssl for use by httpd
* creating a new VirtualHost in httpd to accept cert-authenticated connections
* configure keystone
* create an identity provider to translate cert info into an identity
* configuring client middleware to use certs instead of username/password

## Install mod_ssl
This one's easy:
```bash
[~] # yum install mod_ssl
...
# rename the default 443 virtual host that's automatically installed with mod_ssl:
[~] # mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.orig
```

## Create a new VirtualHost to serve keystone with cert authenication
```apache
# /etc/httpd/conf.d/tokenless-keystone-main.conf
Listen 5001

NameVirtualHost test-du-hinf-rde-994.platform9.horse:5001
WSGIPythonHome /opt/pf9/openstack-keystone
WSGISocketPrefix /var/run/keystone_tokenless
WSGIRestrictEmbedded On


<VirtualHost test-du-hinf-rde-994.platform9.horse:5001>
    # standard stuff, similar to our normal plaintext port 5000 vhost
    ServerName test-du-hinf-rde-994.platform9.horse:5001
    WSGIScriptAlias / /var/www/cgi-bin/keystone/main
    WSGIProcessGroup keystone_tokenless
    WSGIDaemonProcess keystone_tokenless user=keystone group=keystone processes=2 threads=10 display-name=httpd_tokenless_main

    <Directory "/var/www/cgi-bin/keystone">
        Options Indexes FollowSymLinks
        Order allow,deny
        Allow from all
    </Directory>

    ErrorLog /var/log/keystone/tokenless-error.log
    LogLevel debug
    CustomLog /var/log/keystone/tokenless-access.log combined

    # SSL stuff
    SSLEngine on

    # for server authentication using our .horse DigiCert cert
    SSLCertificateFile    /etc/pf9/certs/web/cert.pem
    SSLCertificateKeyFile /etc/pf9/certs/web/key.pem

    # our .horse DigiCert cert is signed by an intermediate cert, which is included
    # in the cert pem file. Unlike nginx, apache will not automatically present it
    # unless we include the intermediate cert in the 'chain' file configuration.
    SSLCertificateChainFile /etc/pf9/certs/web/cert.pem

    # File containing CA certificates that have signed the client certs we plan to
    # accept. In this example, we're using the same CA we currently use to validate
    # comms-to-switcher connections (CN=hostagent)
    SSLCACertificateFile /etc/pf9/certs/ca/cert.pem

    # tell apache to include information about the cert in the CGI environment. Keystone
    # depends on the fact that the subject DN shows up in the SSL_CLIENT_S_DN_CN and
    # the issuer shows up in SSL_CLIENT_I_DN
    SSLOptions +StdEnvVars

    # turn on client cert validation
    SSLVerifyClient optional
</VirtualHost>
```

## Configure Keystone to Authenticate without Tokens
```dosini
#...
[tokenless_auth]

#
# From keystone
#

# The list of distinguished names which identify trusted issuers of client
# certificates allowed to use X.509 tokenless authorization. If the option is
# absent then no certificates will be allowed. The format for the values of a
# distinguished name (DN) must be separated by a comma and contain no spaces.
# Furthermore, because an individual DN may contain commas, this configuration
# option may be repeated multiple times to represent multiple values. For
# example, keystone.conf would include two consecutive lines in order to trust
# two different DNs, such as `trusted_issuer = CN=john,OU=keystone,O=openstack`
# and `trusted_issuer = CN=mary,OU=eng,O=abc`. (multi valued)
#trusted_issuer =
# PF9: This is the subject DN for our CA
trusted_issuer = CN=test-du-hinf-rde-994

# The federated protocol ID used to represent X.509 tokenless authorization.
# This is used in combination with the value of `[tokenless_auth]
# issuer_attribute` to find a corresponding federated mapping. In a typical
# deployment, there is no reason to change this value. (string value)
#protocol = x509

# The name of the WSGI environment variable used to pass the issuer of the
# client certificate to keystone. This attribute is used as an identity
# provider ID for the X.509 tokenless authorization along with the protocol to
# look up its corresponding mapping. In a typical deployment, there is no
# reason to change this value. (string value)
#issuer_attribute = SSL_CLIENT_I_DN
```

## Create a keystone identity provider to a cert subject into an identity
### Curl commands
```bash
# hash the issue DN. hash.py is included in the code:
[~] ./hash.py CN=test-du-hinf-rde-994
DN = CN=test-du-hinf-rde-994
600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7

# create an identity provider whose name is the hash
[~] curl -i -XPUT -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d '{"identity_provider": {"description": "Stores keystone IDP identities.","enabled": true}}' http://localhost:5000/keystone/v3/OS-FEDERATION/identity_providers/600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7

HTTP/1.1 201 Created
Date: Tue, 13 Nov 2018 19:13:26 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_wsgi/3.4 Python/2.7.5
Vary: X-Auth-Token
x-openstack-request-id: req-16d1505f-23df-4018-b695-2ead1ed3fd56
Content-Length: 540
Content-Type: application/json

{"identity_provider": {"remote_ids": [], "enabled": true, "id": "600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7", "links": {"self": "https://test-du-hinf-rde-994.platform9.horse/keystone/v3/OS-FEDERATION/identity_providers/600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7", "protocols": "https://test-du-hinf-rde-994.platform9.horse/keystone/v3/OS-FEDERATION/identity_providers/600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7/protocols"}, "description": "Stores keystone IDP identities."}}

# create a 'protocol' for the provider
[~] curl -i -H "X-Auth-Token: $TOKEN" -H "Content-Type: application/json" -d '{"protocol": {"mapping_id": "tlsuser_cn"}}' -XPUT http://localhost:8080/keystone/v3/OS-FEDERATION/identity_providers/600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7/protocols/x509

HTTP/1.1 201 Created
Server: nginx/1.12.2
Date: Tue, 13 Nov 2018 19:44:10 GMT
Content-Type: application/json
Content-Length: 427
Connection: keep-alive
Vary: X-Auth-Token
x-openstack-request-id: req-6ceba7e1-af8b-41ed-a7c1-44358ea87c8a
Access-Control-Allow-Credentials: true
Access-Control-Expose-Headers: X-Subject-Token

{"protocol": {"mapping_id": "tlsuser_cn", "id": "x509", "links": {"self": "https://test-du-hinf-rde-994.platform9.horse/keystone/v3/OS-FEDERATION/identity_providers/600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7/protocols/x509", "identity_provider": "https://test-du-hinf-rde-994.platform9.horse/keystone/v3/OS-FEDERATION/identity_providers/600492665f769df62b9aec1dc2966c572c3de26507278a26388600fd20b1f4b7"}}}

# create the tlsuser_cn mapping (explanation of the mapping below)
[~] curl -i -XPUT -H "x-auth-token: $TOKEN" -H 'content-type: application/json' -d @mapping.json http://localhost:5000/keystone/v3/OS-FEDERATION/mappings/tlsuser_cn

HTTP/1.1 201 Created
Date: Tue, 13 Nov 2018 19:37:22 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_wsgi/3.4 Python/2.7.5
Vary: X-Auth-Token
x-openstack-request-id: req-1c14ece8-0abe-4c10-9a8c-65b458558f26
Content-Length: 289
Content-Type: application/json

{"mapping": {"rules": [{"local": [{"user": {"domain": {"name": "default"}, "type": "local", "name": "{0}"}}], "remote": [{"type": "SSL_CLIENT_S_DN_CN"}]}], "id": "tlsuser_cn", "links": {"self": "https://test-du-hinf-rde-994.platform9.horse/keystone/v3/OS-FEDERATION/mappings/tlsuser_cn"}}}

```
### The mapping file.
This maps the CN from the Subject to an existing 'local' user. If we didn't want to create this user, we could leave out 'local' and an ephemeral SSO-like user would be created whose permissions would need to be determined by a group mappping
```json
{
     "mapping": {
         "rules": [
             {
                 "local": [
                     {
                        "user": {
                            "name": "{0}",
                            "domain": {
                                "name": "default"
                            },
                            "type": "local"
                        }
                     }
                ],
                "remote": [
                    {
                        "type": "SSL_CLIENT_S_DN_CN"
                    }
                ]
            }
        ]
    }
}
```
### Test it with curl
```bash
curl -H "X-Project-Domain-ID: default" -H "X-Project-Name: service" --key /etc/pf9/certs/hostagent/key.pem --cert /etc/pf9/certs/hostagent/cert.pem https://test-du-hinf-rde-994.platform9.horse:5001/v3/users
{"users":...}
```
Success!

## Configure client middleware
We'll use glance and nova as examples
### Glance
```dosini
# /etc/glance/glance-api.conf
...
[keystone_authtoken]
...
auth_section = keystone_tokenless
certfile = /etc/pf9/certs/hostagent/cert.pem
keyfile = /etc/pf9/certs/hostagent/key.pem

# see https://docs.openstack.org/keystoneauth/latest/authentication-plugins.html#tokenless-auth
[keystone_tokenless]
auth_type = v3tokenlessauth
auth_url = https://test-du-hinf-rde-994.platform9.horse:5001/v3
user_domain_name = default
project_name = service
project_domain_name = default
region_name = RegionOne
```
### Nova
```dosini
[keystone_authtoken]
...
certfile = /etc/pf9/certs/hostagent/cert.pem
keyfile = /etc/pf9/certs/hostagent/key.pem
identity_uri = https://test-du-hinf-rde-994.platform9.horse:5001/v3
auth_url = https://test-du-hinf-rde-994.platform9.horse:5001/v3

# see https://docs.openstack.org/keystoneauth/latest/authentication-plugins.html#tokenless-auth
auth_type = v3tokenlessauth
#auth_url = https://test-du-hinf-rde-994.platform9.horse:5001/v3
#certfile = /etc/pf9/certs/hostagent/cert.pem
#keyfile = /etc/pf9/certs/hostagent/key.pem
#cafile = /etc/pf9/certs/ca/cert.pem
user_domain_name = default
project_name = service
project_domain_name = default
region_name = RegionOne
```

At this point you should be able to delete the `glance` and `nova` users, and still use the openstack clients to list flavors, images, etc.

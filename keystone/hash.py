#!/usr/bin/env python

import hashlib
import sys

print 'DN = %s' % sys.argv[1]
issuer_dn = sys.argv[1]
#issuer_dn = 'emailAddress=john@openstack.com,CN=john,OU=keystone,
#    O=openstack,L=Sunnyvale,ST=California,C=US'
hashed_idp = hashlib.sha256(issuer_dn)
idp_id = hashed_idp.hexdigest()
print(idp_id)

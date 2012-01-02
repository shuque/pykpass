#!/usr/local/bin/python
#

import kpass

USERNAME         = "foo"
PASSWORD_GOOD    = "spam"
PASSWORD_BAD     = "ham"
SERVICE          = "sname"
#SERVICE         = None
#HOSTNAME        = "blah.xyz.com"
HOSTNAME         = None
KT_PATHNAME      = "FILE:/path/to/my/file.keytab"
KT_BAD           = "FILE:/tmp/blah6873254834"

try:

    print ">>> Called with correct username/password:"
    print kpass.kpass(USERNAME, PASSWORD_GOOD, SERVICE, HOSTNAME, KT_PATHNAME)

    print ">>> Called with incorrect password:"
    print kpass.kpass(USERNAME, PASSWORD_BAD, SERVICE, HOSTNAME, KT_PATHNAME)

    print ">>> Called with bad keytab file:"
    print kpass.kpass(USERNAME, PASSWORD_GOOD, SERVICE, HOSTNAME, KT_BAD)

except kpass.KpassError, diag:

    print "Exception: %s: %s" % (diag.__class__.__name__, str(diag))
    

#!/usr/local/bin/python
#

from kpass import kpass, KpassError

USERNAME         = "foo"
PASSWORD         = "spam"
SERVICE          = "sname"
#HOSTNAME        = "blah.xyz.com"
HOSTNAME         = None
KT_PATHNAME      = "FILE:/path/to/my/file.keytab"


try:
    rc = kpass(USERNAME, PASSWORD, SERVICE, HOSTNAME, KT_PATHNAME)
except KpassError, diag:
    print "Error: %s" % str(diag)
else:
    if (rc == 1):
        print "Authentication success"
    else:
        print "Authentication failure"
        

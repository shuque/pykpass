"""
Python extension for Kerberos 5 password verification.

This Python extension module provides a simple function called
kpass() to perform password verification using Kerberos 5. It is 
intended for use by applications that cannot use the Kerberos 
protocol natively, but need to authenticate users against the 
Kerberos database. If it must be run on a system that receives a 
username and password over the network, steps should be taken to 
ensure that these are passed to that system in a cryptographically
secure manner.

kpass() attempts to obtain credentials for the given username and 
password from the Kerberos AS, then obtain credentials for a local 
service from the Kerberos TGS to verify the authenticity of the AS 
response. The python 'None' type can be passed as the 3rd (service)
and 4th (host) arguments to use the default service name (host) 
and the fully canonicalized primary hostname of the system that the 
function is executed on. The fifth argument can also be 'None' to
use the system's default keytab file (usually FILE:/etc/krb5.keytab).

kpass() returns 1 if password verification is successful, 0 if the 
username or password is incorrect and raises a custom exception of
KpassError if a system error is encountered.

kpass() relies on obtaining Kerberos realm and KDC information 
from the invoking environment. Typically it will get this from
the system's Kerberos configuration file (krb5.conf) and/or DNS
records. One quick way to override the default environment is to
create a custom krb5.conf file and setting the pathname to this 
file as the value of the KRB5_CONFIG environment variable.
"""

import _kpass

VERSION = "0.5"

KpassError = _kpass.KpassError

def kpass(*args):
    """kpass(username, password, service, host, kt_pathname) -> int"""
    return _kpass.kpass(*args)


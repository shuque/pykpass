/*
 * kpass.c: Kerberos 5 Password Verification function
 *
 * Written by: Shumon Huque <shuque@upenn.edu>
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <krb5.h>

#include "kpass.h"

#define TKT_LIFETIME     30             /* 30 seconds */
#define USE_MEMORY_CC                   /* use in-memory ccache */

static char rcsid[] = "$Id: kpass.c,v 1.5 2011/06/14 01:53:26 shuque Exp $";

/*
 * static variable to hold error message returned via exceptions
 */

static char kpass_error_message[256];

/*
 * this is used by the Python wrapper function (wrap_kpass) to 
 * obtain the Kerberos error message.
 */

char *obtain_errormsg(void) {
    return kpass_error_message;
}

/*
 * Check a Kerberos function's return value; if any error occurred, 
 * save the descriptive error message, which will be used later by
 * the module's Python exception class.
 */

#ifndef HEIMDAL
#define FAIL(err, tag) \
	if (err) { \
            (void) snprintf(kpass_error_message, 256, "%s %s", \
                            error_message(err), tag); \
	    goto cleanup; \
	}
#else                     /* Heimdal: use krb5_get_err_text */
#define FAIL(err, tag) \
	if (err) { \
            (void) snprintf(kpass_error_message, 256, "%s %s", \
                            krb5_get_err_text(context, err), tag); \
	    goto cleanup; \
	}
#endif

/*
 * Kerberos password verification. Attempt to obtain credentials for a given
 * username and password from Kerberos AS, then obtain credentials for a local
 * service from Kerberos TGS to verify the authenticity of the AS response.
 *
 * Arguments:
 *	username, password	The username and password to verify.
 *	service, host		A local service whose key will be used to
 *                              verify the authenticity of the Kerberos 
 *                              credentials. Specifying host as NULL
 *                              says use my primary hostname.
 *	kt_pathname		Path of the keytab file, or NULL to use default
 *				keytab. (Typical form "FILE:/abs/path/name".)
 *
 * Return -1 if an error occurs, 0 if the username or password is incorrect,
 * or 1 if password verification is successful.
 */


int kpass(username, password, service, host, kt_pathname)
     char *username;
     char *password;
     char *service;
     char *host;
     char *kt_pathname;
{
    krb5_error_code               err;
    krb5_context                  context;
    krb5_auth_context             auth_context = NULL;
    krb5_creds                    credentials;
    krb5_principal                user_principal,
	                          service_principal;
    krb5_keytab                   keytab = NULL;
    krb5_ccache                   ccache;
    char                          ccache_name[L_tmpnam + 8];
    krb5_get_init_creds_opt       gic_options;
    krb5_verify_init_creds_opt    vic_options;
    krb5_data                     apreq_pkt;
    char                          myhostname[256], sprinc[256];

    int                           have_ccache = 0,
	                          have_user_principal = 0,
	                          have_service_principal = 0,
	                          have_keytab = 0,
	                          have_credentials = 0,
                                  success = -1;

    apreq_pkt.data = NULL;

    err = krb5_init_context(&context);
    FAIL(err, "from krb5_init_context");

#ifdef NEED_INIT_ETS
    krb5_init_ets(context);
#endif

#ifndef HEIMDAL
    /* Disable replay cache.  Requires MIT Kerberos 1.4.x or later */
    if (getenv("KRB5RCACHETYPE") == NULL)
        putenv("KRB5RCACHETYPE=none");
#endif

#ifdef USE_MEMORY_CC
    (void) memset(ccache_name, 0, sizeof(ccache_name));
    (void) strcpy(ccache_name, "MEMORY:");
    (void) tmpnam(&ccache_name[7]);
    err = krb5_cc_resolve(context, ccache_name, &ccache);
    FAIL(err, "from krb5_cc_resolve");
#else
    err = krb5_cc_default(context, &ccache);
    FAIL(err, "from cc_default");
#endif
    have_ccache = 1;

    err = krb5_parse_name(context, username, &user_principal);
    FAIL(err, "from krb_parse_name");
    have_user_principal = 1;

    err = krb5_cc_initialize(context, ccache, user_principal);
    FAIL(err, "from krb_cc_initialize");

    (void) memset( (char *)&credentials, 0, sizeof(credentials) );
    if (!host) {
        (void) gethostname(myhostname, sizeof(myhostname));
        snprintf(sprinc, sizeof(sprinc), "%s/%s", service, myhostname);
    } else
        snprintf(sprinc, sizeof(sprinc), "%s/%s", service, host);

    krb5_get_init_creds_opt_init(&gic_options);
    krb5_get_init_creds_opt_set_tkt_life(&gic_options, TKT_LIFETIME);

    err = krb5_get_init_creds_password(context, &credentials,
                                       user_principal, password,
                                       0, 0, 0, sprinc, &gic_options);

    switch (err) {
    case 0:
	/* Success. */
	have_credentials = 1;
	break;
    case KRB5KDC_ERR_PREAUTH_FAILED:
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	/* Bad username or password, unknown user etc */
	success = 0;
	goto cleanup;
    default:
	/* Some other sort of failure. */
	FAIL(err, "from krb5_get_init_creds_password");
	break;
    }

    err = krb5_cc_store_cred(context, ccache, &credentials);
    FAIL(err, "from krb5_cc_store_cred");

    err = krb5_sname_to_principal(context, host, service,
				  KRB5_NT_SRV_HST, &service_principal);
    FAIL(err, "from krb5_sname_to_principal");
    have_service_principal = 1;

    if (kt_pathname && *kt_pathname) {
	err = krb5_kt_resolve(context, kt_pathname, &keytab);
	FAIL(err, "from krb5_kt_resolve");
	have_keytab = 1;
    }

    krb5_verify_init_creds_opt_init(&vic_options);
    krb5_verify_init_creds_opt_set_ap_req_nofail(&vic_options, 1);
    err = krb5_verify_init_creds(context, &credentials, service_principal,
                                 keytab, 0, &vic_options);
    FAIL(err, "from krb5_verify_init_creds");

    success = 1;

cleanup:

    if (have_ccache)
        krb5_cc_destroy(context, ccache);

    if (apreq_pkt.data)
	krb5_free_data_contents(context, &apreq_pkt);

    if (have_keytab)
	if ( (err = krb5_kt_close(context, keytab)) )
	    com_err("kpass", err, "from krb5_kt_close");

    if (have_user_principal)
	krb5_free_principal(context, user_principal);

    if (have_service_principal)
	krb5_free_principal(context, service_principal);

    if (have_credentials)
	krb5_free_cred_contents(context, &credentials);

    if (auth_context) {
     	krb5_auth_con_free(context, auth_context);
	auth_context = NULL;
    }

    if (context)
	krb5_free_context(context);

    return success;
}


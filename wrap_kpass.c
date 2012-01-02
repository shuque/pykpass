#include <Python.h>
#include <stdlib.h>
#include "kpass.h"

static char rcsid[] = "$Id: wrap_kpass.c,v 1.2 2007/04/10 03:02:00 shuque Exp $";

static PyObject *KpassError;
 
static PyObject *
wrap_kpass(PyObject *self, PyObject *args) {

    char *username, *password, *service, *host, *kt_pathname;
    int  rc;

    if ( !PyArg_ParseTuple(args, "ssszz", 
			   &username, &password, &service, &host, 
			   &kt_pathname) )
	return NULL;

    rc = kpass(username, password, service, host, kt_pathname);

    if (rc == -1) {
	PyErr_SetString(KpassError, obtain_errormsg());
	return NULL;
    }

    return Py_BuildValue("i", rc);

}
 
static struct PyMethodDef kpass_methods[] = {
    {"kpass", wrap_kpass, METH_VARARGS,  "Kerberos 5 password verification"},
    {NULL, NULL, 0, NULL}
};
 
 
/*
 * Initialization: called by Python on first import
 */

PyMODINIT_FUNC
init_kpass() {

    PyObject *m;

    m = Py_InitModule("_kpass", kpass_methods);
    KpassError = PyErr_NewException("kpass.KpassError", 
				    PyExc_Exception, NULL);
    Py_INCREF(KpassError);
    PyModule_AddObject(m, "KpassError", KpassError);

}

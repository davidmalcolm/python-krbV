#ifndef KRB5ERR_H
#define KRB5ERR_H 1

#include <krb5.h>
#include <com_err.h>

extern PyObject *pk_exception;

PyObject *pk_error(krb5_error_code rc); /* Just returns NULL */
void pk_error_init(PyObject *module);

#endif

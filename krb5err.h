#ifndef KRB5ERR_H
#define KRB5ERR_H 1

#include <krb5.h>
#ifndef __COM_ERR_H__
#include <com_err.h>
#endif

extern PyObject *pk_exception;

PyObject *pk_error(krb5_error_code rc); /* Just returns NULL */
void pk_error_init(PyObject *module);

#endif

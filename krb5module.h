#ifndef KRB5MODULE_H
#define KRB5MODULE_H 1

#include <Python.h>
#include <krb5.h>
#include <com_err.h>

#include <netinet/in.h>

typedef struct {
  PyObject_HEAD

  krb5_auth_context auth_context;
} PK_AuthenticationContext;

typedef struct {
  PyObject_HEAD

  krb5_principal principal;
} PK_Principal;

#endif

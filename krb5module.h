#ifndef KRB5MODULE_H
#define KRB5MODULE_H 1
#endif

#include <Python.h>
#include <krb5.h>
#ifndef __COM_ERR_H__
#include <com_err.h>
#endif

#include <netinet/in.h>

#if __GNUC__ >= 3
#define __UNUSED __attribute__ ((unused))
#else
#define __UNUSED /* no unused */
#endif

/*
 * krb5module - Module to access basic Kerberos functions from Python.
 * Hopefully obsoletes the krb5module-0.1 from 1998 written by *@cnri.reston.va.us, which is much more technically restrictive,
 * has ugly code, and is totally unmaintained.
 *
 * Copyright (C) 2001 Red Hat, Inc.
 * Licensed under the LGPL.
 *
 * Written by Elliot Lee <sopwith@redhat.com>
 * Not completely tested (yet).
 */
#include "krb5module.h"
#include "krb5err.h"
#include "krb5util.h"

#include <alloca.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <assert.h>

#ifndef _KRB5_INT_H
krb5_error_code krb5_get_krbhst KRB5_PROTOTYPE((krb5_context, const krb5_data *, char ***));
krb5_error_code krb5_free_krbhst KRB5_PROTOTYPE((krb5_context, char * const *));
#endif

static PyObject *pk_default_context(PyObject *self, PyObject *unused_args);
static void destroy_ac(void *cobj, void *desc);
static void destroy_principal(void *cobj, void *desc);

static PyObject *krb5_module, *context_class, *auth_context_class, *principal_class, *ccache_class, *rcache_class, *keytab_class;

static PyObject*
Context_init(PyObject *notself, PyObject *args)
{
  PyObject *self;
  PyObject *cobj;
  krb5_context ctx = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "O:__init__", &self))
    return NULL;

  rc = krb5_init_context(&ctx);
  if(rc)
    pk_error(rc);
  else
    {
      cobj = PyCObject_FromVoidPtr(ctx, (void (*)(void*))krb5_free_context);
      assert(cobj);
      PyObject_SetAttrString(self, "_ctx", cobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
Context_getattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *retval = NULL, *self;
  krb5_context kctx;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  if(strcmp(name, "_ctx"))
    {
      PyObject *ctx;
      ctx = PyObject_GetAttrString(self, "_ctx");
      kctx = PyCObject_AsVoidPtr(ctx);
    }

  if(!strcmp(name, "default_realm"))
    {
      char *realm = NULL;

      rc = krb5_get_default_realm(kctx, &realm);
      if(rc)
	return pk_error(rc);
      retval = PyString_FromString(realm);
      krb5_free_default_realm(kctx, realm);
    }
  else
    {
      PyErr_Format(PyExc_AttributeError, "%.50s instance has no attribute '%.400s'",
		   PyString_AS_STRING(((PyInstanceObject *)self)->in_class->cl_name), name);
      retval = NULL;
    }

  return retval;
}

static PyObject*
Context_setattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *self, *value, *nameo;
  PyInstanceObject *inst;
  krb5_context kctx = NULL;

  if(!PyArg_ParseTuple(args, "OO!O:__setattr__", &self, &PyString_Type, &nameo, &value))
    return NULL;
  inst = (PyInstanceObject *)self;

  name = PyString_AsString(nameo);

  if(strcmp(name, "_ctx"))
    {
      PyObject *ctx;
      ctx = PyObject_GetAttrString(self, "_ctx");
      kctx = PyCObject_AsVoidPtr(ctx);
    }
  if(!strcmp(name, "default_realm"))
    {
      if(!PyString_Check(value))
	{
	  PyErr_Format(PyExc_TypeError, "argument 2 must be a string");
	  return NULL;
	}
      krb5_set_default_realm(kctx, PyString_AsString(value));
    }
  else if((!strcmp(name, "_ctx") && kctx))
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
Context_cc_default(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self;

  if(!PyArg_ParseTuple(args, "O:default_ccache", &self))
    return NULL;

  retval = PyObject_GetAttrString(self, "_default_cc");
  if(retval)
    return retval;
  PyErr_Clear();

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  {
    PyObject *subargs, *mykw = NULL;

    subargs = Py_BuildValue("()");
    if(!kw)
      mykw = kw = PyDict_New();
    PyDict_SetItemString(kw, "context", self); /* Just pass existing keywords straight along */
    retval = PyEval_CallObjectWithKeywords(ccache_class, subargs, kw);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
    if(retval)
      PyObject_SetAttrString(self, "_default_cc", retval);
  }

  return retval;
}

static PyObject*
Context_rc_default(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self;

  if(!PyArg_ParseTuple(args, "O:default_rcache", &self))
    return NULL;

  retval = PyObject_GetAttrString(self, "_default_rc");
  if(retval)
    return retval;

  PyErr_Clear();

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  {
    PyObject *subargs, *mykw = NULL;

    subargs = Py_BuildValue("()");
    if(!kw)
      {
	mykw = kw = PyDict_New();
      }
    PyDict_SetItemString(kw, "context", self); /* Just pass existing keywords straight along */
    retval = PyEval_CallObjectWithKeywords(rcache_class, subargs, kw);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
    if(retval)
      PyObject_SetAttrString(self, "_default_rc", retval);
  }

  return retval;
}

static PyObject*
Context_kt_default(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self;

  if(!PyArg_ParseTuple(args, "O:default_keytab", &self))
    return NULL;

  retval = PyObject_GetAttrString(self, "_default_kt");
  if(retval)
    return retval;

  PyErr_Clear();

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  {
    PyObject *args, *mykw = NULL;

    args = Py_BuildValue("()");
    if(!kw)
      {
	mykw = kw = PyDict_New();
      }
    PyDict_SetItemString(kw, "context", self); /* Just pass existing keywords straight along, mostly */
    retval = PyEval_CallObjectWithKeywords(keytab_class, args, kw);
    Py_DECREF(args);
    Py_XDECREF(mykw);
    if(retval)
      PyObject_SetAttrString(self, "_default_kt", retval);
  }

  return retval;
}

static PyObject*
Context_mk_req(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *in_data = NULL, *options = NULL, *server = NULL, *client = NULL, *ccacheo = NULL, *tmp,
    *auth_context = NULL, *credso = NULL;
  krb5_auth_context ac_out = NULL;
  krb5_data outbuf, inbuf;
  krb5_creds creds, *credsp = NULL, *credsptr;
  krb5_ccache ccache;
  krb5_principal pclient, pserver;
  krb5_flags ap_req_options = 0;
  int free_pclient = 0;
  krb5_error_code rc = 0;
  int free_ccacheo = 0;
  static const char *kwlist[] = {
    "self", "server", "data", "options", "client", "ccache", "auth_context", "creds"
  };

  if(!PyArg_ParseTupleAndKeywords(args, kw, "O|O!SiO!O!O!O:mk_req", (char **)kwlist, &self,
				  principal_class, &server,
				  &in_data, &ap_req_options,
				  principal_class, &client,
				  ccache_class, &ccacheo,
				  auth_context_class, &auth_context,
				  &creds))
    return NULL;

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  if(options)
    ap_req_options = PyInt_AsLong(options);
  if(in_data)
    {
      inbuf.data = PyString_AsString(in_data);
      inbuf.length = PyString_Size(in_data);
    }
  else
    {
      inbuf.data = "BLANK";
      inbuf.length = 5;
    }

  if(credso)
    {
      credsptr = &creds;

      if(!PyArg_ParseTuple(credso, "O!O!(iz#)(iiii)OOOz#z#O",
			   principal_class, &client, principal_class, &server,
			   &creds.keyblock.enctype, &creds.keyblock.contents, &creds.keyblock.length,
			   &creds.times.authtime, &creds.times.starttime, &creds.times.endtime,
			   &creds.times.renew_till, &tmp, &tmp, &tmp, &tmp,
			   &creds.ticket.data,
			   &creds.ticket.length,
			   &creds.second_ticket.data,
			   &creds.second_ticket.length,
			   &tmp))
	return NULL;
    }
  else
    {
      if(!ccacheo)
	{
	  PyObject *subargs;
	  subargs = Py_BuildValue("(O)", self);
	  ccacheo = Context_cc_default(unself, subargs, NULL);
	  Py_DECREF(subargs);
	  free_ccacheo = 1;
	}
      tmp = PyObject_GetAttrString(ccacheo, "_ccache");
      ccache = PyCObject_AsVoidPtr(tmp);
      if(free_ccacheo)
	{
	  Py_DECREF(ccacheo);
	}
    }

  if(client)
    {
      tmp = PyObject_GetAttrString(client, "_princ");
      pclient = PyCObject_AsVoidPtr(tmp);
    }
  else
    {
      rc = krb5_cc_get_principal(kctx, ccache, &pclient);
      if(rc)
	return pk_error(rc);
      free_pclient = 1;
    }

  if(server)
    {
      tmp = PyObject_GetAttrString(server, "_princ");
      pserver = PyCObject_AsVoidPtr(tmp);
    }
  else
    {
      PyErr_Format(PyExc_TypeError, "A server principal is required");
      return NULL;
    }

  creds.server = pserver;
  creds.client = pclient;
  if(!credso)
    {
      rc = krb5_get_credentials(kctx, 0, ccache, &creds, &credsp);
      if(rc)
	{
	  if(free_pclient)
	    krb5_free_principal(kctx, pclient);
	  return pk_error(rc);
	}
      credsptr = credsp;
    }

  if(auth_context)
    {
      tmp = PyObject_GetAttrString(auth_context, "_ac");
      ac_out = PyCObject_AsVoidPtr(tmp);
    }

  rc = krb5_mk_req_extended(kctx, &ac_out, ap_req_options, &inbuf, credsptr, &outbuf);
  if(credsp)
    krb5_free_creds(kctx, credsp);
  if(free_pclient)
    krb5_free_principal(kctx, pclient);
  if(rc)
    return pk_error(rc);

  retval = PyTuple_New(2);
  if(auth_context)
    {
      Py_INCREF(auth_context);
    }
  else
    {
      PyObject *subargs, *mykw = NULL, *otmp;

      subargs = Py_BuildValue("()");
      mykw = PyDict_New();
      PyDict_SetItemString(mykw, "context", self);
      otmp = PyCObject_FromVoidPtrAndDesc(ac_out, kctx, destroy_ac);
      PyDict_SetItemString(mykw, "ac", otmp);
      auth_context = PyEval_CallObjectWithKeywords(auth_context_class, subargs, mykw);
      Py_DECREF(otmp);
      Py_DECREF(subargs);
      Py_XDECREF(mykw);
    }
  PyTuple_SetItem(retval, 0, auth_context);
  tmp = PyString_FromStringAndSize(outbuf.data, outbuf.length);
  PyTuple_SetItem(retval, 1, tmp);
  krb5_free_data_contents(kctx, &outbuf);

  return retval;
}

static PyObject*
Context_rd_req(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *in_data, *server = NULL, *keytab = NULL, *tmp, *options = NULL;
  krb5_auth_context ac_out = NULL;
  krb5_data inbuf;
  krb5_keytab kt;
  krb5_principal pserver = NULL;
  krb5_flags ap_req_options = 0;
  krb5_error_code rc = 0;
  krb5_ticket *ticket = NULL;
  int free_keytab = 0;

  if(!PyArg_ParseTuple(args, "OO:rd_req", &self, &in_data))
    return NULL;

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  if(kw)
    {
      options = PyDict_GetItemString(kw, "options");
      server = PyDict_GetItemString(kw, "server");
      keytab = PyDict_GetItemString(kw, "keytab");
    }
  if(in_data)
    {
      if(!PyString_Check(in_data))
	{
	  PyErr_Format(PyExc_TypeError, "First argument must be a string type");
	  return NULL;
	}

      inbuf.data = PyString_AsString(in_data);
      inbuf.length = PyString_Size(in_data);
    }

  if(keytab == Py_None)
    {
      PyObject *subargs;
      subargs = Py_BuildValue("(O)", self);
      keytab = Context_kt_default(unself, subargs, NULL);
      Py_DECREF(subargs);
      free_keytab = 1;
    }
  tmp = PyObject_GetAttrString(keytab, "_keytab");
  kt = PyCObject_AsVoidPtr(tmp);
  if(free_keytab)
    {
      Py_DECREF(keytab);
    }

  if(server)
    {
      tmp = PyObject_GetAttrString(server, "_princ");
      pserver = PyCObject_AsVoidPtr(tmp);
    }
  if(options)
    ap_req_options = PyInt_AsLong(options);

  rc = krb5_rd_req(kctx, &ac_out, &inbuf, pserver, kt, &ap_req_options, &ticket);
  if(rc)
    return pk_error(rc);

  retval = PyTuple_New(3);
  {
    PyObject *subargs, *mykw = NULL, *otmp;

    subargs = Py_BuildValue("()");
    mykw = PyDict_New();
    PyDict_SetItemString(mykw, "context", self);
    otmp = PyCObject_FromVoidPtrAndDesc(ac_out, kctx, destroy_ac);
    PyDict_SetItemString(mykw, "ac", otmp);
    tmp = PyEval_CallObjectWithKeywords(auth_context_class, subargs, mykw);
    Py_DECREF(otmp);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
    PyTuple_SetItem(retval, 0, tmp);
  }
  tmp = PyInt_FromLong(ap_req_options);
  PyTuple_SetItem(retval, 1, tmp);
  {
    PyObject *subargs, *otmp, *mykw = NULL;
    krb5_principal princ;

    krb5_copy_principal(kctx, ticket->server, &princ);
    otmp = PyCObject_FromVoidPtrAndDesc(princ, kctx, destroy_principal);
    subargs = Py_BuildValue("(O)", otmp);
    mykw = PyDict_New();
    PyDict_SetItemString(kw, "context", self); /* Just pass existing keywords straight along */
    tmp = PyEval_CallObjectWithKeywords(principal_class, subargs, mykw);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
    Py_DECREF(otmp);

    PyTuple_SetItem(retval, 2, tmp);
  }
  krb5_free_ticket(kctx, ticket);

  return retval;
}

static int
obj_to_fd(PyObject *fd_obj)
{
  if(PyInt_Check(fd_obj))
    return PyInt_AsLong(fd_obj);
  else if(PyLong_Check(fd_obj))
    return PyLong_AsLongLong(fd_obj);

  fd_obj = PyEval_CallMethod(fd_obj, "fileno", "()");
  if(!fd_obj)
    return -1;
  return PyInt_AsLong(fd_obj);
}

static PyObject*
Context_sendauth(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *fd_obj = NULL, *options = NULL, *server = NULL, *client = NULL, *ccacheo = NULL, *tmp, *in_data = NULL;
  krb5_auth_context ac_out = NULL;
  krb5_ccache ccache;
  krb5_principal pclient, pserver;
  krb5_flags ap_req_options = 0;
  krb5_data inbuf;
  int free_pclient = 0;
  krb5_error_code rc = 0;
  int free_ccacheo = 0;
  char *appl_version;
  int fd;
  krb5_pointer fd_ptr = &fd;

  if(!PyArg_ParseTuple(args, "OOs:sendauth", &self, &fd_obj, &appl_version))
    return NULL;

  fd = obj_to_fd(fd_obj);
  if(fd < 0)
    return NULL;
  
  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  if(kw)
    {
      options = PyDict_GetItemString(kw, "options");
      server = PyDict_GetItemString(kw, "server");
      client = PyDict_GetItemString(kw, "client");
      ccacheo = PyDict_GetItemString(kw, "ccache");
      in_data = PyDict_GetItemString(kw, "data");
    }

  if(!ccacheo)
    {
      PyObject *subargs;
      subargs = Py_BuildValue("(O)", self);
      ccacheo = Context_cc_default(unself, subargs, NULL);
      Py_DECREF(subargs);
      free_ccacheo = 1;
    }
  tmp = PyObject_GetAttrString(ccacheo, "_ccache");
  ccache = PyCObject_AsVoidPtr(tmp);
  if(free_ccacheo)
    {
      Py_DECREF(ccacheo);
    }
  if(client)
    {
      tmp = PyObject_GetAttrString(client, "_princ");
      pclient = PyCObject_AsVoidPtr(tmp);
    }
  else
    {
      rc = krb5_cc_get_principal(kctx, ccache, &pclient);
      if(rc)
	return pk_error(rc);
      free_pclient = 1;
    }

  if(server)
    {
      tmp = PyObject_GetAttrString(server, "_princ");
      pserver = PyCObject_AsVoidPtr(tmp);
    }
  else
    {
      PyErr_Format(PyExc_TypeError, "A server keyword argument is required");
      return NULL;
    }
  if(options)
    ap_req_options = PyInt_AsLong(options);
  if(in_data)
    {
      if(!PyString_Check(in_data))
	{
	  PyErr_Format(PyExc_TypeError, "data must be a string type");
	  return NULL;
	}
	  
      inbuf.data = PyString_AsString(in_data);
      inbuf.length = PyString_Size(in_data);
    }
  else
    {
      inbuf.data = "BLANK";
      inbuf.length = 5;
    }

  Py_BEGIN_ALLOW_THREADS
  rc = krb5_sendauth(kctx, &ac_out, fd_ptr, appl_version, pclient, pserver, ap_req_options, &inbuf,
		     NULL, ccache, NULL, NULL, NULL);
  Py_END_ALLOW_THREADS
  if(free_pclient)
    krb5_free_principal(kctx, pclient);
  if(rc)
    return pk_error(rc);

  {
    PyObject *subargs, *mykw = NULL, *otmp;

    subargs = Py_BuildValue("()");
    mykw = PyDict_New();
    PyDict_SetItemString(mykw, "context", self);
    otmp = PyCObject_FromVoidPtrAndDesc(ac_out, kctx, destroy_ac);
    PyDict_SetItemString(mykw, "ac", otmp);
    retval = PyEval_CallObjectWithKeywords(auth_context_class, subargs, mykw);
    Py_DECREF(otmp);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
  }

  return retval;
}

static PyObject*
Context_recvauth(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *fd_obj, *server = NULL, *keytab = NULL, *tmp, *options = NULL;
  krb5_auth_context ac_out = NULL;
  krb5_keytab kt;
  krb5_principal pserver;
  krb5_flags ap_req_options = 0;
  krb5_error_code rc = 0;
  int free_keytab = 0;
  int fd;
  char *appl_version;
  krb5_pointer fd_ptr = &fd;

  if(!PyArg_ParseTuple(args, "OOs:recvauth", &self, &fd_obj, &appl_version))
    return NULL;

  fd = obj_to_fd(fd_obj);
  if(fd < 0)
    return NULL;

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  if(kw)
    {
      options = PyDict_GetItemString(kw, "options");
      server = PyDict_GetItemString(kw, "server");
      keytab = PyDict_GetItemString(kw, "keytab");
    }

  if(!keytab)
    {
      PyObject *subargs;
      subargs = Py_BuildValue("(O)", self);
      keytab = Context_kt_default(unself, subargs, NULL);
      Py_DECREF(subargs);
      free_keytab = 1;
    }
  tmp = PyObject_GetAttrString(keytab, "_keytab");
  kt = PyCObject_AsVoidPtr(tmp);
  if(free_keytab)
    {
      Py_DECREF(keytab);
    }

  if(server)
    {
      tmp = PyObject_GetAttrString(server, "_princ");
      pserver = PyCObject_AsVoidPtr(tmp);
    }
  else
    {
      PyErr_Format(PyExc_TypeError, "A server keyword argument is required");
      return NULL;
    }
  if(options)
    ap_req_options = PyInt_AsLong(options);

  Py_BEGIN_ALLOW_THREADS
  rc = krb5_recvauth(kctx, &ac_out, fd_ptr, appl_version, pserver, ap_req_options, kt, NULL);
  Py_END_ALLOW_THREADS
  if(rc)
    return pk_error(rc);

  {
    PyObject *subargs, *mykw = NULL, *otmp;

    subargs = Py_BuildValue("()");
    mykw = PyDict_New();
    PyDict_SetItemString(mykw, "context", self);
    otmp = PyCObject_FromVoidPtrAndDesc(ac_out, kctx, destroy_ac);
    PyDict_SetItemString(mykw, "ac", otmp);
    retval = PyEval_CallObjectWithKeywords(auth_context_class, subargs, mykw);
    Py_DECREF(otmp);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
  }

  return retval;
}

static PyObject*
Context_mk_rep(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *auth_context = NULL, *tmp;
  krb5_auth_context ac;
  krb5_data outbuf;
  krb5_error_code rc = 0;

  if(!PyArg_ParseTuple(args, "O:mk_rep", &self))
    return NULL;

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  if(kw && PyDict_Check(kw))
    auth_context = PyDict_GetItemString(kw, "auth_context");
  if(!auth_context || !PyObject_IsInstance(auth_context, auth_context_class))
    {
      PyErr_Format(PyExc_TypeError, "auth_context keyword argument required");
      return NULL;
    }
  tmp = PyObject_GetAttrString(auth_context, "_ac");
  ac = PyCObject_AsVoidPtr(tmp);

  rc = krb5_mk_rep(kctx, ac, &outbuf);
  if(rc)
    return pk_error(rc);

  retval = PyString_FromStringAndSize(outbuf.data, outbuf.length);
  krb5_free_data_contents(kctx, &outbuf);

  return retval;
}

static PyObject*
Context_rd_rep(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *self, *auth_context = NULL, *in_data, *tmp;
  krb5_auth_context ac;
  krb5_data inbuf;
  krb5_error_code rc = 0;
  krb5_ap_rep_enc_part *repl = NULL;

  if(!PyArg_ParseTuple(args, "OO!:rd_rep", &self, &PyString_Type, &in_data))
    return NULL;

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  if(kw && PyDict_Check(kw))
    auth_context = PyDict_GetItemString(kw, "auth_context");
  if(!auth_context || !PyObject_IsInstance(auth_context, auth_context_class))
    {
      PyErr_Format(PyExc_TypeError, "auth_context keyword argument required");
      return NULL;
    }
  tmp = PyObject_GetAttrString(auth_context, "_ac");
  ac = PyCObject_AsVoidPtr(tmp);

  inbuf.data = PyString_AsString(in_data);
  inbuf.length = PyString_Size(in_data);
  rc = krb5_rd_rep(kctx, ac, &inbuf, &repl);
  if(rc)
    return pk_error(rc);

  krb5_free_ap_rep_enc_part(kctx, repl);

  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef context_methods[] = {
  {"__init__", Context_init, METH_VARARGS|METH_KEYWORDS},
  {"default_ccache", (PyCFunction)Context_cc_default, METH_VARARGS|METH_KEYWORDS},
  {"default_rcache", (PyCFunction)Context_rc_default, METH_VARARGS|METH_KEYWORDS},
  {"default_keytab", (PyCFunction)Context_kt_default, METH_VARARGS|METH_KEYWORDS},
  {"mk_req", (PyCFunction)Context_mk_req, METH_VARARGS|METH_KEYWORDS},
  {"rd_req", (PyCFunction)Context_rd_req, METH_VARARGS|METH_KEYWORDS},
  {"sendauth", (PyCFunction)Context_sendauth, METH_VARARGS|METH_KEYWORDS},
  {"recvauth", (PyCFunction)Context_recvauth, METH_VARARGS|METH_KEYWORDS},
  {"mk_rep", (PyCFunction)Context_mk_rep, METH_VARARGS|METH_KEYWORDS},
  {"rd_rep", (PyCFunction)Context_rd_rep, METH_VARARGS|METH_KEYWORDS},
  {NULL, NULL}
};

static PyObject *
pk_context_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef getattr = {"__getattr__", Context_getattr, METH_VARARGS},
    setattr = {"__setattr__", Context_setattr, METH_VARARGS};
  PyObject *dict, *name, *retval;
  PyClassObject *klass;
  dict = PyDict_New();
  name = PyString_FromString("Context");

  retval = PyClass_New(NULL, dict, name);
  klass = (PyClassObject *)retval;

  PyObject_SetAttrString(retval, "__module__", module);
  for(def = context_methods; def->ml_name; def++)
    {
      PyObject *func = PyCFunction_New(def, NULL);
      PyObject *method = PyMethod_New(func, NULL, retval);
      PyDict_SetItemString(dict, def->ml_name, method);
      Py_DECREF(func);
      Py_DECREF(method);
    }
  klass->cl_getattr = PyMethod_New(PyCFunction_New(&getattr, NULL), NULL, retval);
  klass->cl_setattr = PyMethod_New(PyCFunction_New(&setattr, NULL), NULL, retval);

  return retval;
}

/*********************** AuthContext **********************/
static PyObject*
AuthContext_getattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *retval = NULL, *self, *tmp;
  krb5_context ctx = NULL;
  krb5_auth_context ac = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  if(strcmp(name, "context") && strcmp(name, "_ac"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_ac");
      if(tmp)
	ac = PyCObject_AsVoidPtr(tmp);
    }

  PyErr_Clear();
  
  if(!strcmp(name, "flags"))
    {
      krb5_int32 flags;
      rc = krb5_auth_con_getflags(ctx, ac, &flags);
      if(rc)
	return pk_error(rc);
      retval = PyInt_FromLong(flags);
    }
  else if(!strcmp(name, "addrs"))
    {
      PyObject *ra1, *ra2;
      krb5_address *a1=NULL, *a2=NULL;
      rc = krb5_auth_con_getaddrs(ctx, ac, &a1, &a2);
      if(rc)
	return pk_error(rc);
      if(a1)
	{
	  ra1 = PyTuple_New(2);
	  PyTuple_SetItem(ra1, 0, PyInt_FromLong(a1->addrtype));
	  PyTuple_SetItem(ra1, 1, PyString_FromStringAndSize(a1->contents, a1->length));
	  krb5_free_address(ctx, a1);
	}
      else
	{
	  ra1 = Py_None;
	  Py_INCREF(ra1);
	}
      if(a2)
	{
	  ra2 = PyTuple_New(2);
	  PyTuple_SetItem(ra2, 0, PyInt_FromLong(a2->addrtype));
	  PyTuple_SetItem(ra2, 1, PyString_FromStringAndSize(a2->contents, a2->length));
	  krb5_free_address(ctx, a2);
	}
      else
	{
	  ra2 = Py_None;
	  Py_INCREF(ra2);
	}
      retval = PyTuple_New(2);
      PyTuple_SetItem(retval, 0, ra1);
      PyTuple_SetItem(retval, 1, ra2);
    }
  else
    {
      PyErr_Format(PyExc_AttributeError, "%.50s instance has no attribute '%.400s'",
		   PyString_AS_STRING(((PyInstanceObject *)self)->in_class->cl_name), name);
      retval = NULL;
    }

  return retval;
}

static PyObject*
AuthContext_setattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *self, *value, *nameo, *tmp;
  PyInstanceObject *inst;
  krb5_context ctx = NULL;
  krb5_auth_context ac = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "OO!O:__setattr__", &self, &PyString_Type, &nameo, &value))
    return NULL;
  inst = (PyInstanceObject *)self;

  name = PyString_AsString(nameo);

  if(strcmp(name, "context") && strcmp(name, "_ac"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_ac");
      if(tmp)
	ac = PyCObject_AsVoidPtr(tmp);
    }

  PyErr_Clear();
  
  if(!strcmp(name, "flags"))
    {
      krb5_int32 flags;
      if(PyInt_Check(value))
	flags = PyInt_AsLong(value);
      else if(PyLong_Check(value))
	flags = PyLong_AsLongLong(value);
      else
	{
	  PyErr_Format(PyExc_TypeError, "flags must be an integer");
	  return NULL;
	}
      rc = krb5_auth_con_setflags(ctx, ac, flags);
      if(rc)
	return pk_error(rc);
    }
  else if(!strcmp(name, "rcache"))
    {
      krb5_rcache rcache;

      tmp = PyObject_GetAttrString(value, "_rcache");
      assert(tmp);
      rcache = PyCObject_AsVoidPtr(tmp);
      rc = krb5_auth_con_setrcache(ctx, ac, rcache);
      if(rc)
	return pk_error(rc);
    }
  else if(!strcmp(name, "useruserkey"))
    {
      krb5_keyblock kb;

      memset(&kb, 0, sizeof(kb));
      if(!PyArg_ParseTuple(value, "iz#", &kb.enctype, &kb.contents, &kb.length))
	return NULL;
      rc = krb5_auth_con_setuseruserkey(ctx, ac, &kb);
      if(rc)
	return pk_error(rc);
    }
  else if(!strcmp(name, "addrs")
	  || (!strcmp(name, "context") && ctx)
	  || (!strcmp(name, "_ac") && ac)
	  )
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
}

static void
destroy_ac(void *cobj, void *desc)
{
  krb5_auth_con_free(desc, cobj);
}

static PyObject*
AuthContext_init(PyObject *notself, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *acobj = NULL;
  krb5_context ctx;
  krb5_auth_context ac;
  krb5_error_code rc = 0;
  static const char *kwlist[] = { "self", "context", "ac"};

  if(!PyArg_ParseTupleAndKeywords(args, kw, "O|O!O!:__init__", (char **)kwlist, &self,
				  context_class, &conobj, &PyCObject_Type, &acobj))
    return NULL;

  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  if(!acobj)
    rc = krb5_auth_con_init(ctx, &ac);
  if(rc)
    return pk_error(rc);
  else
    {
      if(acobj)
	{
	  cobj = acobj;
	  Py_INCREF(acobj);
	}
      else
	cobj = PyCObject_FromVoidPtrAndDesc(ac, ctx, destroy_ac);
      PyObject_SetAttrString(self, "_ac", cobj);
      PyObject_SetAttrString(self, "context", conobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
AuthContext_genaddrs(PyObject *notself, PyObject *args, PyObject *kw)
{
  PyObject *self, *fh, *tmp;
  int fd;
  krb5_context ctx;
  krb5_auth_context ac;
  krb5_flags flags = 0;
  krb5_error_code rc;
  static const char *kwlist[] = {"self", "fh", "flags"};

  if(!PyArg_ParseTupleAndKeywords(args, kw, "OO|i:genaddrs", (char **)kwlist, &self, &fh, &flags))
    return NULL;

  tmp = PyObject_GetAttrString(self, "context");
  tmp = PyObject_GetAttrString(tmp, "_ctx");
  ctx = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(self, "_ac");
  ac = PyCObject_AsVoidPtr(tmp);
  
  fd = obj_to_fd(fh);
  if(fd < 0)
    return NULL;

  rc = krb5_auth_con_genaddrs(ctx, ac, fd, flags);
  if(rc)
    return pk_error(rc);
  
  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef auth_context_methods[] = {
  {"__init__", (PyCFunction)AuthContext_init, METH_VARARGS|METH_KEYWORDS},
  {"genaddrs", (PyCFunction)AuthContext_genaddrs, METH_VARARGS|METH_KEYWORDS},
  {NULL, NULL}
};

static PyObject *
pk_auth_context_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef getattr = {"__getattr__", AuthContext_getattr, METH_VARARGS},
    setattr = {"__setattr__", AuthContext_setattr, METH_VARARGS};
  PyObject *dict, *name, *retval;
  PyClassObject *klass;

  dict = PyDict_New();
  name = PyString_FromString("AuthContext");

  retval = PyClass_New(NULL, dict, name);
  klass = (PyClassObject *)retval;

  PyObject_SetAttrString(retval, "__module__", module);
  for(def = auth_context_methods; def->ml_name; def++)
    {
      PyObject *func = PyCFunction_New(def, NULL);
      PyObject *method = PyMethod_New(func, NULL, retval);
      PyDict_SetItemString(dict, def->ml_name, method);
      Py_DECREF(func);
      Py_DECREF(method);
    }

  klass->cl_getattr = PyMethod_New(PyCFunction_New(&getattr, NULL), NULL, retval);
  klass->cl_setattr = PyMethod_New(PyCFunction_New(&setattr, NULL), NULL, retval);

  return retval;
}

/************************* Principal **********************************/
static PyObject*
Principal_getattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *retval = NULL, *self, *tmp;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  if(strcmp(name, "context") && strcmp(name, "_princ"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_princ");
      if(tmp)
	princ = PyCObject_AsVoidPtr(tmp);
    }

  PyErr_Clear();

  if(!strcmp(name, "realm"))
    {
      krb5_data *realm;

      realm = krb5_princ_realm(ctx, princ);
      retval = PyString_FromStringAndSize(realm->data, realm->length);
    }
  else if(!strcmp(name, "name"))
    {
      char *outname = NULL;

      rc = krb5_unparse_name(ctx, princ, &outname);
      if(rc)
	return pk_error(rc);

      retval = PyString_FromString(outname);
      free(outname);
    }
  else
    {
      PyErr_Format(PyExc_AttributeError, "%.50s instance has no attribute '%.400s'",
		   PyString_AS_STRING(((PyInstanceObject *)self)->in_class->cl_name), name);
      retval = NULL;
    }

  return retval;
}

static PyObject*
Principal_setattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *self, *value, *nameo, *tmp;
  PyInstanceObject *inst;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL;

  if(!PyArg_ParseTuple(args, "OO!O:__setattr__", &self, &PyString_Type, &nameo, &value))
    return NULL;
  inst = (PyInstanceObject *)self;

  name = PyString_AsString(nameo);

  if(strcmp(name, "context") && strcmp(name, "_princ"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_princ");
      if(tmp)
	princ = PyCObject_AsVoidPtr(tmp);
    }

  PyErr_Clear();
  
  if((!strcmp(name, "context") && ctx)
     || (!strcmp(name, "_princ") && princ)
     || !strcmp(name, "realm")
     || !strcmp(name, "name")
     )
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
}

static void
destroy_principal(void *cobj, void *desc)
{
  krb5_free_principal(desc, cobj);
}

static PyObject*
Principal_init(PyObject *notself, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj, *princobj;
  krb5_context ctx;
  krb5_principal princ;
  krb5_error_code rc = 0;
  char *name;

  if(!PyArg_ParseTuple(args, "OO:__init__", &self, &princobj))
    return NULL;

  if(kw && PyDict_Check(kw))
    conobj = PyDict_GetItemString(kw, "context");
  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  cobj = NULL;
  if(PyString_Check(princobj))
    {
      name = PyString_AsString(princobj);
      rc = krb5_parse_name(ctx, name, &princ);
    }
  else if(PyObject_IsInstance(princobj, (PyObject *)&PyCObject_Type))
    {
      cobj = princobj;
    }
  else
    {
      PyErr_Format(PyExc_TypeError, "Invalid type for argument 1");
      return NULL;
    }

  if(rc)
    {
      pk_error(rc);
      return NULL;
    }
  else
    {
      if(cobj)
	Py_INCREF(cobj);
      else
	cobj = PyCObject_FromVoidPtrAndDesc(princ, ctx, destroy_principal);
      PyObject_SetAttrString(self, "_princ", cobj);
      PyObject_SetAttrString(self, "context", conobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
Principal_getitem(PyObject *unself, PyObject *args)
{
  PyObject *self, *tmp, *retval;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL;
  int index;
  krb5_data *d;

  if(!PyArg_ParseTuple(args, "Oi:__getitem__", &self, &index))
    return NULL;

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_princ");
  if(tmp)
    princ = PyCObject_AsVoidPtr(tmp);

  if(index >= krb5_princ_size(ctx, princ))
    {
      PyErr_Format(PyExc_IndexError, "index out of range");
      return NULL;
    }

  d = krb5_princ_component(ctx, princ, index);
  retval = PyString_FromStringAndSize(d->data, d->length);

  return retval;
}

static PyObject*
Principal_itemlen(PyObject *unself, PyObject *args)
{
  PyObject *self, *tmp;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL;

  if(!PyArg_ParseTuple(args, "O:__len__", &self))
    return NULL;

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_princ");
  if(tmp)
    princ = PyCObject_AsVoidPtr(tmp);

  return PyInt_FromLong(krb5_princ_size(ctx, princ));
}


static PyObject*
Principal_eq(PyObject *unself, PyObject *args)
{
  PyObject *self, *tmp, *other;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL, otherprinc = NULL;

  if(!PyArg_ParseTuple(args, "OO:__eq__", &self, &other))
    return NULL;
  if(!PyObject_IsInstance(other, principal_class))
    {
      PyErr_Format(PyExc_TypeError, "Second argument must be a Principal");
      return NULL;
    }

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_princ");
  princ = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(other, "_princ");
  otherprinc = PyCObject_AsVoidPtr(tmp);

  if(krb5_principal_compare(ctx, princ, otherprinc))
    return PyInt_FromLong(1);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
Principal_repr(PyObject *unself, PyObject *args)
{
  PyObject *self, *tmp, *retval;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL;
  char *outname, *outbuf;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "O:__len__", &self))
    return NULL;

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_princ");
  if(tmp)
    princ = PyCObject_AsVoidPtr(tmp);

  rc = krb5_unparse_name(ctx, princ, &outname);
  if(rc)
    return pk_error(rc);
  outbuf = alloca(strlen(outname) + strlen("<krb5.Principal instance at 0x1234567890123456: >") + 1);
  sprintf(outbuf, "<krb5.Principal instance at %p: %s>", self, outname);

  retval = PyString_FromString(outbuf);
  free(outname);
  return retval;
}

static PyMethodDef principal_methods[] = {
  {"__init__", (PyCFunction)Principal_init, METH_VARARGS|METH_KEYWORDS},
  {"__getitem__", (PyCFunction)Principal_getitem, METH_VARARGS},
  {"__len__", (PyCFunction)Principal_itemlen, METH_VARARGS},
  {"__eq__", (PyCFunction)Principal_eq, METH_VARARGS},
  {"__repr__", (PyCFunction)Principal_repr, METH_VARARGS},
  {NULL, NULL}
};

static PyObject *
pk_principal_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef getattr = {"__getattr__", Principal_getattr, METH_VARARGS},
    setattr = {"__setattr__", Principal_setattr, METH_VARARGS};
  PyObject *dict, *name, *retval;
  PyClassObject *klass;

  dict = PyDict_New();
  name = PyString_FromString("Principal");

  retval = PyClass_New(NULL, dict, name);
  klass = (PyClassObject *)retval;

  PyObject_SetAttrString(retval, "__module__", module);
  for(def = principal_methods; def->ml_name; def++)
    {
      PyObject *func = PyCFunction_New(def, NULL);
      PyObject *method = PyMethod_New(func, NULL, retval);
      PyDict_SetItemString(dict, def->ml_name, method);
      Py_DECREF(func);
      Py_DECREF(method);
    }
  klass->cl_getattr = PyMethod_New(PyCFunction_New(&getattr, NULL), NULL, retval);
  klass->cl_setattr = PyMethod_New(PyCFunction_New(&setattr, NULL), NULL, retval);

  return retval;
}

/************************* Creds cache **********************************/
static PyObject*
CCache_getattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *retval = NULL, *self, *tmp;
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  if(strcmp(name, "context") && strcmp(name, "_ccache"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_ccache");
      if(tmp)
	ccache = PyCObject_AsVoidPtr(tmp);
    }

  if(!strcmp(name, "name"))
    {
      char *nom;

      nom = krb5_cc_get_name(ctx, ccache);
      retval = PyString_FromString(nom);
      //      free(nom);
    }
  else if(!strcmp(name, "type"))
    {
      char *type;

      type = krb5_cc_get_type(ctx, ccache);
      if(type)
	retval = PyString_FromString(type);
      else
	{
	  retval = Py_None;
	  Py_INCREF(Py_None);
	}
    }
  else
    {
      PyErr_Format(PyExc_AttributeError, "%.50s instance has no attribute '%.400s'",
		   PyString_AS_STRING(((PyInstanceObject *)self)->in_class->cl_name), name);
      retval = NULL;
    }

  return retval;
}

static PyObject*
CCache_setattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *self, *value, *nameo, *tmp;
  PyInstanceObject *inst;
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;

  if(!PyArg_ParseTuple(args, "OO!O:__setattr__", &self, &PyString_Type, &nameo, &value))
    return NULL;
  inst = (PyInstanceObject *)self;

  name = PyString_AsString(nameo);

  if(strcmp(name, "context") && strcmp(name, "_ccache"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_ccache");
      if(tmp)
	ccache = PyCObject_AsVoidPtr(tmp);
    }

  if((!strcmp(name, "context") && ctx)
     || (!strcmp(name, "_ccache") && ccache)
     || !strcmp(name, "name")
     || !strcmp(name, "type")
     )
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
}

static void
destroy_ccache(void *cobj, void *desc)
{
  krb5_cc_close((krb5_context)desc, (krb5_ccache)cobj);
}

static PyObject*
CCache_init(PyObject *notself, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *new_cc = NULL, *new_cc_name = NULL, *primary_principal = NULL;
  krb5_context ctx;
  krb5_ccache cc;
  krb5_error_code rc;
  int is_dfl = 0;

  if(!PyArg_ParseTuple(args, "O:__init__", &self))
    return NULL;

  if(kw && PyDict_Check(kw))
    {
      conobj = PyDict_GetItemString(kw, "context");
      new_cc_name = PyDict_GetItemString(kw, "name");
      new_cc = PyDict_GetItemString(kw, "ccache");
      primary_principal = PyDict_GetItemString(kw, "primary_principal");
    }
  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);
  if(primary_principal && !PyObject_IsInstance(primary_principal, principal_class))
    {
      PyErr_Format(PyExc_TypeError, "primary_principal argument must be a Principal");
      return NULL;
    }

  if(new_cc)
    {
      rc = 0;
      cc = PyCObject_AsVoidPtr(new_cc);
    }
  else if(new_cc_name)
    {
      char *ccname = PyString_AsString(new_cc_name);
      assert(ccname);
      rc = krb5_cc_resolve(ctx, ccname, &cc);
    }
  else
    {
      rc = krb5_cc_default(ctx, &cc);
      is_dfl = 1;
    }

  if(rc)
    {
      pk_error(rc);
      return NULL;
    }
  else
    {
      cobj = PyCObject_FromVoidPtrAndDesc(cc, ctx, is_dfl?NULL:destroy_ccache);
      PyObject_SetAttrString(self, "_ccache", cobj);
      PyObject_SetAttrString(self, "context", conobj);
      if(primary_principal)
	{
	  krb5_principal princ;
	  PyObject *ppo;
	  ppo = PyObject_GetAttrString(primary_principal, "_princ");
	  assert(ppo);
	  princ = PyCObject_AsVoidPtr(ppo);
	  krb5_cc_initialize(ctx, cc, princ);
	}
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
CCache_eq(PyObject *unself, PyObject *args)
{
  PyObject *self, *tmp, *other;
  krb5_context ctx = NULL;
  krb5_ccache princ = NULL, otherprinc = NULL;

  if(!PyArg_ParseTuple(args, "OO:__eq__", &self, &other))
    return NULL;
  if(!PyObject_IsInstance(other, (PyObject *)((PyInstanceObject *)self)->in_class))
    {
      PyErr_Format(PyExc_TypeError, "Second argument must be a CCache");
      return NULL;
    }

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_ccache");
  princ = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(other, "_ccache");
  otherprinc = PyCObject_AsVoidPtr(tmp);

  if(princ == otherprinc)
    return PyInt_FromLong(1);

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
CCache_principal(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;
  PyObject *retval, *self, *tmp, *conobj;
  krb5_principal princ = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "O:principal", &self))
    return NULL;

  retval = PyObject_GetAttrString(self, "_principal");
  if(retval)
    return retval;

  conobj = tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_ccache");
  if(tmp)
    ccache = PyCObject_AsVoidPtr(tmp);

  {
    PyObject *subargs, *otmp, *mykw = NULL;

    rc = krb5_cc_get_principal(ctx, ccache, &princ);
    if(rc)
      return pk_error(rc);

    otmp = PyCObject_FromVoidPtrAndDesc(princ, ctx, destroy_principal);
    subargs = Py_BuildValue("(O)", otmp);
    if(!kw)
      mykw = kw = PyDict_New();
    PyDict_SetItemString(kw, "context", conobj); /* Just pass existing keywords straight along */
    retval = PyEval_CallObjectWithKeywords(principal_class, subargs, kw);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
    Py_DECREF(otmp);
    if(retval)
      PyObject_SetAttrString(self, "_principal", retval);
  }

  return retval;
}

static PyObject*
CCache_get_credentials(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;
  PyObject *retval, *self, *tmp, *conobj, *client, *server, *adlist, *addrlist;
  krb5_flags options;
  krb5_error_code rc;
  krb5_creds in_creds, *out_creds = NULL;

  static const char *kwlist[]={"self", "in_creds", "options" };

  memset(&in_creds, 0, sizeof(in_creds));
  if(!PyArg_ParseTupleAndKeywords(args, kw, "O(O!O!(iz#)(iiii)OOOz#z#O)|i:get_credentials", (char **)kwlist, &self,
				  principal_class, &client, principal_class, &server,
				  &in_creds.keyblock.enctype, &in_creds.keyblock.contents, &in_creds.keyblock.length,
				  &in_creds.times.authtime, &in_creds.times.starttime, &in_creds.times.endtime,
				  &in_creds.times.renew_till, &tmp, &tmp, &tmp, &tmp,
				  &in_creds.ticket.data,
				  &in_creds.ticket.length,
				  &in_creds.second_ticket.data,
				  &in_creds.second_ticket.length,
				  &tmp,
				  &options))
    return NULL;

  tmp = PyObject_GetAttrString(client, "_princ");
  in_creds.client = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(server, "_princ");
  in_creds.server = PyCObject_AsVoidPtr(tmp);

  conobj = tmp = PyObject_GetAttrString(self, "context");
  tmp = PyObject_GetAttrString(tmp, "_ctx");
  ctx = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(self, "_ccache");
  ccache = PyCObject_AsVoidPtr(tmp);

  rc = krb5_get_credentials(ctx, options, ccache, &in_creds, &out_creds);
  if(rc)
    return pk_error(rc);

  if(out_creds->server != in_creds.server)
    {
      PyObject *subargs, *mykw = NULL;
      krb5_principal princ = NULL;

      krb5_copy_principal(ctx, out_creds->server, &princ);
      subargs = Py_BuildValue("(O)", PyCObject_FromVoidPtrAndDesc(princ, ctx, destroy_principal));
      server = PyEval_CallObjectWithKeywords(principal_class, subargs, mykw);
      Py_XDECREF(mykw);
      Py_XDECREF(subargs);
    }
  else
    Py_XINCREF(server);
  if(out_creds->client != in_creds.client)
    {
      PyObject *subargs, *mykw = NULL;
      krb5_principal princ = NULL;

      krb5_copy_principal(ctx, out_creds->client, &princ);
      subargs = Py_BuildValue("(O)", PyCObject_FromVoidPtrAndDesc(princ, ctx, destroy_principal));
      server = PyEval_CallObjectWithKeywords(principal_class, subargs, mykw);
      Py_XDECREF(mykw);
      Py_XDECREF(subargs);
    }
  else
    Py_XINCREF(client);

  {
    int i, n;
    for(n = 0; out_creds->addresses[n]; n++) /* */;
    addrlist = PyTuple_New(n);
    for(i = 0; i < n; i++)
      PyTuple_SetItem(addrlist, i,
		      Py_BuildValue("(iz#)", out_creds->addresses[i]->addrtype, out_creds->addresses[i]->contents,
				    out_creds->addresses[i]->length));
  }

  {
    int i, n;
    for(n = 0; out_creds->authdata[n]; n++) /* */;
    adlist = PyTuple_New(n);
    for(i = 0; i < n; i++)
      PyTuple_SetItem(addrlist, i,
		      Py_BuildValue("(iz#)", out_creds->authdata[i]->ad_type, out_creds->authdata[i]->contents,
				    out_creds->authdata[i]->length));
  }

  retval = Py_BuildValue("(NN(iz#)(iiii)iiNz#z#N)", client, server, out_creds->keyblock.enctype,
			 out_creds->keyblock.contents, out_creds->keyblock.length,
			 out_creds->times.authtime, out_creds->times.starttime,
			 out_creds->times.endtime, out_creds->times.renew_till,
			 out_creds->is_skey, out_creds->ticket_flags, addrlist,
			 out_creds->ticket.data, out_creds->ticket.length,
			 out_creds->second_ticket.data, out_creds->second_ticket.data,
			 adlist);
  krb5_free_creds(ctx, out_creds);

  return retval;
}

static PyMethodDef ccache_methods[] = {
  {"__init__", (PyCFunction)CCache_init, METH_VARARGS|METH_KEYWORDS},
  {"__eq__", (PyCFunction)CCache_eq, METH_VARARGS},
  {"principal", (PyCFunction)CCache_principal, METH_VARARGS},
  {"get_credentials", (PyCFunction)CCache_get_credentials, METH_VARARGS|METH_KEYWORDS},
  {NULL, NULL}
};

static PyObject *
pk_ccache_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef getattr = {"__getattr__", CCache_getattr, METH_VARARGS},
    setattr = {"__setattr__", CCache_setattr, METH_VARARGS};
  PyObject *dict, *name, *retval;
  PyClassObject *klass;

  dict = PyDict_New();
  name = PyString_FromString("CCache");

  retval = PyClass_New(NULL, dict, name);
  klass = (PyClassObject *)retval;

  PyObject_SetAttrString(retval, "__module__", module);
  for(def = ccache_methods; def->ml_name; def++)
    {
      PyObject *func = PyCFunction_New(def, NULL);
      PyObject *method = PyMethod_New(func, NULL, retval);
      PyDict_SetItemString(dict, def->ml_name, method);
      Py_DECREF(func);
      Py_DECREF(method);
    }
  klass->cl_getattr = PyMethod_New(PyCFunction_New(&getattr, NULL), NULL, retval);
  klass->cl_setattr = PyMethod_New(PyCFunction_New(&setattr, NULL), NULL, retval);

  return retval;
}

/************************* replay cache **********************************/
static PyObject*
RCache_getattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *retval = NULL, *self, *tmp;
  krb5_context ctx = NULL;
  krb5_rcache rcache = NULL;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  if(strcmp(name, "context") && strcmp(name, "_rcache"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_rcache");
      if(tmp)
	rcache = PyCObject_AsVoidPtr(tmp);
    }

  if(!strcmp(name, "name"))
    {
      char *nom;

      nom = krb5_rc_get_name(ctx, rcache);
      retval = PyString_FromString(nom);
    }
  else if(!strcmp(name, "type"))
    {
      char *nom;

      nom = krb5_rc_get_type(ctx, rcache);
      retval = PyString_FromString(nom);
    }
  else
    {
      PyErr_Format(PyExc_AttributeError, "%.50s instance has no attribute '%.400s'",
		   PyString_AS_STRING(((PyInstanceObject *)self)->in_class->cl_name), name);
      retval = NULL;
    }

  return retval;
}

static PyObject*
RCache_setattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *self, *value, *nameo, *tmp;
  PyInstanceObject *inst;
  krb5_context ctx = NULL;
  krb5_rcache rcache = NULL;

  if(!PyArg_ParseTuple(args, "OO!O:__setattr__", &self, &PyString_Type, &nameo, &value))
    return NULL;
  inst = (PyInstanceObject *)self;

  name = PyString_AsString(nameo);

  if(strcmp(name, "context") && strcmp(name, "_rcache"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_rcache");
      if(tmp)
	rcache = PyCObject_AsVoidPtr(tmp);
    }

  if((!strcmp(name, "context") && ctx)
     || (!strcmp(name, "_rcache") && rcache)
     || !strcmp(name, "name")
     || !strcmp(name, "type")
     )
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
}

static void
destroy_rcache(void *cobj, void *desc)
{
  krb5_rc_close((krb5_context)desc, (krb5_rcache)cobj);
}

static PyObject*
RCache_init(PyObject *notself, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *new_rc = NULL, *new_rc_name = NULL, *do_recover = NULL;
  krb5_context ctx;
  krb5_rcache rcache;
  krb5_error_code rc;
  int is_dfl = 0;

  if(!PyArg_ParseTuple(args, "O:__init__", &self))
    return NULL;

  if(kw && PyDict_Check(kw))
    {
      conobj = PyDict_GetItemString(kw, "context");
      new_rc_name = PyDict_GetItemString(kw, "name");
      new_rc = PyDict_GetItemString(kw, "rcache");
      do_recover = PyDict_GetItemString(kw, "recover");
    }
  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  if(new_rc)
    {
      rc = 0;
      rcache = PyCObject_AsVoidPtr(new_rc);
    }
  else if(new_rc_name)
    {
      char *ccname = PyString_AsString(new_rc_name);
      assert(ccname);
      rc = krb5_rc_resolve_full(ctx, &rcache, ccname);
    }
  else
    {
      rc = krb5_rc_default(ctx, &rcache);
      is_dfl = 1;
    }

  if(rc)
    {
      pk_error(rc);
      return NULL;
    }
  else
    {
      cobj = PyCObject_FromVoidPtrAndDesc(rcache, ctx, destroy_rcache);
      PyObject_SetAttrString(self, "_rcache", cobj);
      PyObject_SetAttrString(self, "context", conobj);
      if(do_recover)
	rc = krb5_rc_recover(ctx, rcache);
      if(rc || !do_recover)
	krb5_rc_initialize(ctx, rcache, 24000);
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
RCache_eq(PyObject *unself, PyObject *args)
{
  PyObject *self, *tmp, *other;
  krb5_context ctx = NULL;
  krb5_rcache princ = NULL, otherprinc = NULL;

  if(!PyArg_ParseTuple(args, "OO:__eq__", &self, &other))
    return NULL;
  if(!PyObject_IsInstance(other, (PyObject *)((PyInstanceObject *)self)->in_class))
    {
      PyErr_Format(PyExc_TypeError, "Second argument must be a RCache");
      return NULL;
    }

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_rcache");
  princ = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(other, "_rcache");
  otherprinc = PyCObject_AsVoidPtr(tmp);

  if(princ == otherprinc)
    return PyInt_FromLong(1);

  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef rcache_methods[] = {
  {"__init__", (PyCFunction)RCache_init, METH_VARARGS|METH_KEYWORDS},
  {"__eq__", (PyCFunction)RCache_eq, METH_VARARGS},
  {NULL, NULL}
};

static PyObject *
pk_rcache_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef getattr = {"__getattr__", RCache_getattr, METH_VARARGS},
    setattr = {"__setattr__", RCache_setattr, METH_VARARGS};
  PyObject *dict, *name, *retval;
  PyClassObject *klass;

  dict = PyDict_New();
  name = PyString_FromString("RCache");

  retval = PyClass_New(NULL, dict, name);
  klass = (PyClassObject *)retval;

  PyObject_SetAttrString(retval, "__module__", module);
  for(def = rcache_methods; def->ml_name; def++)
    {
      PyObject *func = PyCFunction_New(def, NULL);
      PyObject *method = PyMethod_New(func, NULL, retval);
      PyDict_SetItemString(dict, def->ml_name, method);
      Py_DECREF(func);
      Py_DECREF(method);
    }
  klass->cl_getattr = PyMethod_New(PyCFunction_New(&getattr, NULL), NULL, retval);
  klass->cl_setattr = PyMethod_New(PyCFunction_New(&setattr, NULL), NULL, retval);

  return retval;
}

/************************* keytab **********************************/
static PyObject*
Keytab_getattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *retval = NULL, *self, *tmp;
  krb5_context ctx = NULL;
  krb5_keytab keytab = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  if(strcmp(name, "context") && strcmp(name, "_keytab"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_keytab");
      if(tmp)
	keytab = PyCObject_AsVoidPtr(tmp);
    }

  if(!strcmp(name, "name"))
    {
      char nombuf[64];

      rc = krb5_kt_get_name(ctx, keytab, nombuf, sizeof(nombuf));
      if(rc)
	return pk_error(rc);
      retval = PyString_FromString(nombuf);
    }
  else
    {
      PyErr_Format(PyExc_AttributeError, "%.50s instance has no attribute '%.400s'",
		   PyString_AS_STRING(((PyInstanceObject *)self)->in_class->cl_name), name);
      retval = NULL;
    }

  return retval;
}

static PyObject*
Keytab_setattr(PyObject *unself, PyObject *args)
{
  char *name;
  PyObject *self, *value, *nameo, *tmp;
  PyInstanceObject *inst;
  krb5_context ctx = NULL;
  krb5_keytab keytab = NULL;

  if(!PyArg_ParseTuple(args, "OO!O:__setattr__", &self, &PyString_Type, &nameo, &value))
    return NULL;
  inst = (PyInstanceObject *)self;

  name = PyString_AsString(nameo);

  if(strcmp(name, "context") && strcmp(name, "_keytab"))
    {
      tmp = PyObject_GetAttrString(self, "context");
      if(tmp)
	{
	  tmp = PyObject_GetAttrString(tmp, "_ctx");
	  if(tmp)
	    ctx = PyCObject_AsVoidPtr(tmp);
	}
      tmp = PyObject_GetAttrString(self, "_keytab");
      if(tmp)
	keytab = PyCObject_AsVoidPtr(tmp);
    }

  if((!strcmp(name, "context") && ctx)
     || (!strcmp(name, "_keytab") && keytab)
     || !strcmp(name, "name")
     )
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
}

static void
destroy_keytab(void *cobj, void *desc)
{
  krb5_kt_close((krb5_context)desc, (krb5_keytab)cobj);
}

static PyObject*
Keytab_init(PyObject *notself, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *new_rc = NULL, *new_rc_name = NULL;
  krb5_context ctx;
  krb5_keytab keytab;
  krb5_error_code rc;
  int is_dfl = 0;

  if(!PyArg_ParseTuple(args, "O:__init__", &self))
    return NULL;

  if(kw && PyDict_Check(kw))
    {
      conobj = PyDict_GetItemString(kw, "context");
      new_rc_name = PyDict_GetItemString(kw, "name");
      new_rc = PyDict_GetItemString(kw, "keytab");
    }
  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  if(new_rc)
    {
      rc = 0;
      keytab = PyCObject_AsVoidPtr(new_rc);
    }
  else if(new_rc_name)
    {
      char *ccname = PyString_AsString(new_rc_name);
      assert(ccname);
      rc = krb5_kt_resolve(ctx, ccname, &keytab);
    }
  else
    {
      rc = krb5_kt_default(ctx, &keytab);
      is_dfl = 1;
    }

  if(rc)
    {
      pk_error(rc);
      return NULL;
    }
  else
    {
      cobj = PyCObject_FromVoidPtrAndDesc(keytab, ctx, destroy_keytab);
      PyObject_SetAttrString(self, "_keytab", cobj);
      PyObject_SetAttrString(self, "context", conobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
Keytab_eq(PyObject *unself, PyObject *args)
{
  PyObject *self, *tmp, *other;
  krb5_context ctx = NULL;
  krb5_keytab princ = NULL, otherprinc = NULL;

  if(!PyArg_ParseTuple(args, "OO:__eq__", &self, &other))
    return NULL;
  if(!PyObject_IsInstance(other, (PyObject *)((PyInstanceObject *)self)->in_class))
    {
      PyErr_Format(PyExc_TypeError, "Second argument must be a Keytab");
      return NULL;
    }

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
    }
  tmp = PyObject_GetAttrString(self, "_keytab");
  princ = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(other, "_keytab");
  otherprinc = PyCObject_AsVoidPtr(tmp);

  if(princ == otherprinc)
    return PyInt_FromLong(1);

  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef keytab_methods[] = {
  {"__init__", (PyCFunction)Keytab_init, METH_VARARGS|METH_KEYWORDS},
  {"__eq__", (PyCFunction)Keytab_eq, METH_VARARGS},
  {NULL, NULL}
};

static PyObject *
pk_keytab_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef getattr = {"__getattr__", Keytab_getattr, METH_VARARGS},
    setattr = {"__setattr__", Keytab_setattr, METH_VARARGS};
  PyObject *dict, *name, *retval;
  PyClassObject *klass;

  dict = PyDict_New();
  name = PyString_FromString("Keytab");

  retval = PyClass_New(NULL, dict, name);
  klass = (PyClassObject *)retval;

  PyObject_SetAttrString(retval, "__module__", module);
  for(def = keytab_methods; def->ml_name; def++)
    {
      PyObject *func = PyCFunction_New(def, NULL);
      PyObject *method = PyMethod_New(func, NULL, retval);
      PyDict_SetItemString(dict, def->ml_name, method);
      Py_DECREF(func);
      Py_DECREF(method);
    }
  klass->cl_getattr = PyMethod_New(PyCFunction_New(&getattr, NULL), NULL, retval);
  klass->cl_setattr = PyMethod_New(PyCFunction_New(&setattr, NULL), NULL, retval);

  return retval;
}

/****** main module ********/
static PyObject *
pk_default_context(PyObject *self, PyObject *unused_args)
{
  PyObject *retval = NULL;

  retval = PyObject_GetAttrString(krb5_module, "_default_context");
  if(!retval)
    {
      PyObject *klass, *subargs;

      PyErr_Clear();
      klass = PyObject_GetAttrString(krb5_module, "Context");
      subargs = Py_BuildValue("()");
      retval = PyEval_CallObject(klass, subargs);
      assert(retval);
      Py_DECREF(subargs);
      if(retval)
	PyObject_SetAttrString(krb5_module, "_default_context", retval);
    }

  Py_INCREF(retval);

  return retval;
}

static PyMethodDef krb5_functions[] = {
  {"default_context", pk_default_context, METH_VARARGS},
  {NULL, NULL}
};

void
initkrb5(void)
{
  PyObject *module = Py_InitModule("krb5", krb5_functions);
  PyObject *dict, *revdict;
  PyObject *modname;

  if(!module)
    return; /* Already initialized */

  krb5_module = module;

  dict = PyModule_GetDict(module);
  pk_error_init(module);

  PyDict_SetItemString(dict, "__doc__",
		       PyString_FromString(
					   "This module implements python bindings to the Kerberos5 API."
					   ));

  revdict = PyDict_New();
  PyDict_SetItemString(dict, "errors", revdict);
  modname = PyString_FromString(PyModule_GetName(module));

  context_class = pk_context_make_class(modname);
  PyDict_SetItemString(dict, "Context", context_class);
  Py_DECREF(context_class);

  auth_context_class = pk_auth_context_make_class(modname);
  PyDict_SetItemString(dict, "AuthContext", auth_context_class);
  Py_DECREF(auth_context_class);

  principal_class = pk_principal_make_class(modname);
  PyDict_SetItemString(dict, "Principal", principal_class);
  Py_DECREF(principal_class);

  ccache_class = pk_ccache_make_class(modname);
  PyDict_SetItemString(dict, "CCache", ccache_class);
  Py_DECREF(ccache_class);

  rcache_class = pk_rcache_make_class(modname);
  PyDict_SetItemString(dict, "RCache", rcache_class);
  Py_DECREF(rcache_class);

  keytab_class = pk_keytab_make_class(modname);
  PyDict_SetItemString(dict, "Keytab", keytab_class);
  Py_DECREF(keytab_class);

  Py_DECREF(modname);

#include "krb5defines.h"
}

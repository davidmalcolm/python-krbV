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
#define KRB5_PRIVATE 1
#include "krb5module.h"
#include "krb5err.h"
#include "krb5util.h"

#include <alloca.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <stdio.h>
#include <arpa/inet.h>

#if !defined(_KRB5_INT_H) && defined(KRB5_PROTOTYPE)
krb5_error_code krb5_get_krbhst KRB5_PROTOTYPE((krb5_context, const krb5_data *, char ***));
krb5_error_code krb5_free_krbhst KRB5_PROTOTYPE((krb5_context, char * const *));
#endif

static PyObject *pk_default_context(PyObject *self, PyObject *unused_args);
static void destroy_ac(void *cobj, void *desc);
static void destroy_principal(void *cobj, void *desc);

static PyObject *krb5_module, *context_class, *auth_context_class, *principal_class, *ccache_class, *rcache_class, *keytab_class;

PyDoc_STRVAR(Context_init__doc__,
"__init__() -> KrbV.Context                                                  \n\
                                                                             \n\
:Summary : Create a Krb Context object.                                      \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Purpose :                                                                   \n\
The KrbV.Context structure is designed to hold all per-thread state.         \n\
All global variables that are thread-specific are stored in this structure,  \n\
including default encryption-types, credentials-cache (ticket file), and     \n\
default realms.  The internals of the structure should never be accessed     \n\
directly, functions exist for extracting information.                        \n\
:Return value :                                                              \n\
    __init__() returns a Context object.                                     \n\
");

static PyObject*
Context_init(PyObject *unself __UNUSED, PyObject *args)
{
  PyObject *self;
  PyObject *cobj;
  krb5_context ctx = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "O:__init__", &self))
    return NULL;

  rc = krb5_init_context(&ctx);
  if(rc)
    return pk_error(rc);
  else
    {
      cobj = PyCObject_FromVoidPtr(ctx, (void (*)(void*))krb5_free_context);
      assert(cobj);
      PyObject_SetAttrString(self, "_ctx", cobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
} /* KrbV.Context.__init__() */

PyDoc_STRVAR(Context_getattr__doc__,
"__getattr__(string) -> PyObject                                             \n\
                                                                             \n\
:Summary : Retrieve a KrbV.Context member object by name.                    \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Purpose :                                                                   \n\
__getattr__() supports only the following Object-members:                    \n\
    * _ctx :           Sort of a copy() method?                              \n\
    * default_realm  : The default realm is extracted from the krb.conf file \n\
                                                                             \n\
:Return value :                                                              \n\
    This method's retval-type corresponds to the member-name parameter.      \n\
");
static PyObject*
Context_getattr(PyObject *unself __UNUSED, PyObject *args)
{
  char *name;
  PyObject *retval = NULL, *self;
  krb5_context kctx = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  if(strcmp(name, "_ctx"))
    {
      PyObject *ctx;
      ctx = PyObject_GetAttrString(self, "_ctx");
      if(!ctx)
	return NULL;
      kctx = PyCObject_AsVoidPtr(ctx);
      if(!kctx)
	return NULL;
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
} /* KrbV.Context.__getattr__() */

PyDoc_STRVAR(Context_setattr__doc__,
"__setattr__(string, value-object) -> 'None'                                    \n\
                                                                                \n\
:Summary : Set a KrbV.Context member object's value, by name.                   \n\
           Internal function, do not use.                                       \n\
                                                                                \n\
:Purpose :                                                                      \n\
__setattr__() supports only the following Context-members:                       \n\
    * default_realm  : Set the default realm.                                   \n\
                                                                                \n\
:Return value :                                                                 \n\
    'None', or NULL.                                                            \n\
");
static PyObject*
Context_setattr(PyObject *unself __UNUSED, PyObject *args)
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
      if(!ctx)
	return NULL;
      kctx = PyCObject_AsVoidPtr(ctx);
      if(!kctx)
	return NULL;
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
} /* KrbV.Context.__setattr__() */

PyDoc_STRVAR(Context_cc_default__doc__,
"default_ccache(context) -> CCache object                                    \n\
                                                                             \n\
:Summary : Retrieve the default credentials-cache object from the current    \n\
           Kerberos context, or from the ticket-file, if necessary.          \n\
                                                                             \n\
:Parameters :                                                                \n\
    context : KrbV.Context                                                   \n\
        The current Kerberos context holds the host's kerberos config-data,  \n\
        including default encryption-types, credentials-cache (ticket file), \n\
        and default realms.                                                  \n\
                                                                             \n\
:Purpose :                                                                   \n\
    default_ccache() loads the default ticket-file's contents into a CCache  \n\
    object.  The default ticket-file's pathname is part of the krb context.  \n\
    BTW, only kerberos clients have ticket files;  this is where a client's  \n\
    short-lived tickets and session keys stay, while a user is logged-in.    \n\
                                                                             \n\
:Action and side-effects :                                                   \n\
    krb_context.default_ccache() calls CCache.__init__(context=krb_context), \n\
    which in turn calls the krblib C routine krb5_cc_default().              \n\
    krb5_cc_default() looks in the krb context for the default filename of   \n\
    the ticket file, and then reads the ticket-file's contents into a        \n\
    credentials-cache (a C data-structure),  Finally, default_ccache()       \n\
    converts the C-struct credentials-cache to a CCache object.              \n\
                                                                             \n\
:Return value :                                                              \n\
    A CCache object, containing the user's tickets and session-keys.         \n\
");

static PyObject*
Context_cc_default(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
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
} /* KrbV.Context.default_ccache() */

PyDoc_STRVAR(Context_rc_default__doc__,
"default_rcache(context) -> KrbV.Context.RCache object                       \n\
                                                                             \n\
:Summary :  Retrieve the default replay-cache object from                    \n\
            the current Kerberos context.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    context : KrbV.Context                                                   \n\
        The current Kerberos context holds the host's kerberos config-data,  \n\
        including default encryption-types, credentials-cache (ticket file), \n\
        and default realms.                                                  \n\
                                                                             \n\
:Purpose :                                                                   \n\
    default_rcache() loads the default replay-cache into an RCache object.   \n\
    Only kerberized application-servers have replay caches.                  \n\
                                                                             \n\
:Action and side-effects :                                                   \n\
    krb_context.default_rcache() calls RCache.__init__(context=krb_context), \n\
    which in turn calls the krblib C routine krb5_rc_default().              \n\
    krb5_rc_default() looks in the krb context for the default replay cache, \n\
    and default_rcache() converts the C-struct replay-cache to an RCache     \n\
    object.                                                                  \n\
                                                                             \n\
:Return value :                                                              \n\
    An RCache object, containing the user's tickets and session-keys.        \n\
");
static PyObject*
Context_rc_default(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
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
} /* KrbV.Context.default_rcache() */

PyDoc_STRVAR(Context_kt_default__doc__,
"default_keytab(context) -> KrbV.Context.RCache object                       \n\
                                                                             \n\
:Summary : Retrieve the default key-table object from the current,           \n\
           Kerberos context or from the default keytab-file, if necessary.   \n\
                                                                             \n\
:Parameters :                                                                \n\
    context : KrbV.Context                                                   \n\
        The current Kerberos context holds the host's kerberos config-data,  \n\
        including default encryption-types, credentials-cache (ticket file), \n\
        and default realms.                                                  \n\
                                                                             \n\
:Purpose :                                                                   \n\
    default_keytab() loads the default keytab-file's contents into a Keytab  \n\
    object.  The default keytab-file's pathname is part of the krb context.  \n\
    Only kerberos servers have keytab files;  this is where a server's       \n\
    long-lived secret keys stay.  The keytab in not encrypted, so that the   \n\
    server can cold-start without a human operator's help.                   \n\
                                                                             \n\
:Action and side-effects :                                                   \n\
    KrbV.Context.default_keytab() calls RCache.__init__(context=krb_context),\n\
    which in turn calls the krblib C routine krb5_rc_default().              \n\
    krb5_rc_default() looks in the krb context for the default replay cache, \n\
    and default_keytab() converts the C-struct replay-cache to an RCache     \n\
    object.                                                                  \n\
                                                                             \n\
:Return value :                                                              \n\
    An RCache object, containing the user's tickets and session-keys.        \n\
");
static PyObject*
Context_kt_default(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
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
} /* KrbV.Context.default_keytab() */

PyDoc_STRVAR(Creds_tuple__doc__,
"Creds_tuple object                                                          \n\
                                                                             \n\
:Purpose :  A Creds_tuple holds a single entry from a CCache.                \n\
            The main items are the client's & server's names, the            \n\
            user's tickets, the session key, and the ticket lifetime.        \n\
            TBD:  This object isn't yet set up as a Python class.            \n\
                                                                             \n\
:Contents :                                                                  \n\
    <client>          Principal : Client's name, eg, 'JohnDoe/EXAMPLE.COM'   \n\
    <server>          Principal : Server's name, eg, 'NFS/FILER_1.EXAMPLE.COM'\n\
    <keyblock>        tuple                                                  \n\
       <enctype>      integer        :                                       \n\
       <contents>     string         :                                       \n\
    <times>           tuple                                                  \n\
       <authtime>     integer        :                                       \n\
       <starttime>    integer        :                                       \n\
       <endtime>      integer        :                                       \n\
       <renew_till>   integer        :                                       \n\
    <is_skey>                                                                \n\
    <ticket_flags>    integer                                                \n\
    <addrlist>        tuple ((type, string)...)                              \n\
    <ticket.data>     string                                                 \n\
    <2nd_ticket.data> string                                                 \n\
    <authdata_list>   tuple ((type, string)...)                              \n\
");

PyDoc_STRVAR(Context_mk_req__doc__,
"mk_req(in_data, options, server, keytab, auth_context) ->                   \n\
       (auth_context, int, tkt-cipher [,tkt-plain])                          \n\
                                                                             \n\
:Parameters:                                                                 \n\
    server krbV.Principal :                                                  \n\
         The server name. The server principal in the AP_REQ must            \n\
         be the same as the principal specified by this parameter.           \n\
    data : str (optional)                                                    \n\
         A small buffer containing a message to send in the authenticator.   \n\
         If data is 'None', then mk_req() will use the string 'BLANK' as the \n\
         message to be protected.                                            \n\
         BUG:  This should be a msg-checksum, not the message itself.        \n\
    options : int (optional)                                                 \n\
         KRB_AP_REQ flags.  Valid flag values are:                           \n\
            * AP_OPTS_MUTUAL_REQUIRED :                                      \n\
                The client requires mutual authentication, ie, kerberized    \n\
                proof of the server's identity.                              \n\
                Normally, you should always use this flag, but only for      \n\
                the first send_auth() call on a connection.                  \n\
            * AP_OPTS_USE_SESSION_KEY :                                      \n\
                Specific for user-to-user (ie, peer-to-peer) connections.    \n\
                Not used for most client-server applications.                \n\
            * AP_OPTS_USE_SUBKEY :                                           \n\
                The application client or server can choose a sub-session    \n\
                key, but this usually isn't necessary.                       \n\
         These KRB_AP_REQ flags can be OR'ed together, as needed.            \n\
         For details about the use of user-to-user and subkeys, see RFC 4120.\n\
         If the options are not needed, specify 'None' for this parameter.   \n\
    client : krbV.Principal (optional)                                       \n\
         The client name.                                                    \n\
    ccache : KrbV.CCache (optional)                                          \n\
    auth_context : KrbV.AuthContext                                          \n\
         Info about the kerberos-session, especially:                        \n\
            * the client's principal-name, and                               \n\
            * any session-key the server shares with the client.             \n\
    creds tuple :                                                            \n\
         BUG: this parameter should be a Creds object, not a tuple.          \n\
         For details of the creds tuple's structure, see the doc-string for  \n\
         'Creds_tuple', elsewhere in this document.                          \n\
                                                                             \n\
:Summary: Prepare a Krb 'application request' message.                       \n\
                                                                             \n\
:Purpose :                                                                   \n\
An application-client calls mk_req() to prepare a client's authenticated     \n\
request for service (AP_REQ).  The client must then explicitly send the      \n\
AP_REQ message to the application-server; mk_req() doesn't send the message. \n\
The client's AP_REQ message contains the client's encrypted service-ticket   \n\
and an encrypted timestamp (aka 'authenticator').                            \n\
The client calls mk_req() as the first step in an authenticated handshake.   \n\
                                                                             \n\
:Action & side-effects :                                                     \n\
mk_req() doesn't actually send the AP_REQ message across the network;        \n\
mk_req() only encodes and encrypts the AP_REQ message.                       \n\
However, mk_req() can ask the TGS for application tickets, if necessary.     \n\
If you call mk_req() with a client-principal object (so that creds=='None'), \n\
mk_req() will use the client & service principals to get and use a service-  \n\
ticket, with which to construct the AP_REQ message.  In case mk_req() does   \n\
request a new ticket, you should refresh your ccache parameter before calling\n\
mk_req() again, so that your next mk_req() call can use the new ticket.      \n\
                                                                             \n\
The caller must supply either a client parameter or a creds parameter.       \n\
If you call mk_req() with both a client-principal and credentials, mk_req()  \n\
will use the credentials' client-principal as the client's name.             \n\
                                                                             \n\
:Return value:                                                               \n\
    mk_req() returns a tuple of 2 elements:                                  \n\
                                                                             \n\
    0. An AuthContext.  The input authentication context, or a new           \n\
       AuthContext if the input AuthContext value was 'None'.                \n\
       In either case, the retval's AuthContext contains any new             \n\
       application that mk_req() may have requested from the TGS.            \n\
    1. An output string, containing the new AP_REQ message.  The caller's    \n\
       code must transmit this AP_REQ message to the application-server.     \n\
                                                                             \n\
:See also:                                                                   \n\
KrbV.Context     methods : rd_req(),  mk_rep(), rd_rep();                    \n\
KrbV.AuthContext methods : mk_priv(), rd_priv()                              \n\
");

static PyObject*
Context_mk_req(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *in_data = NULL, *server = NULL, *client = NULL, *ccacheo = NULL, *tmp,
    *auth_context = NULL, *credso = NULL;
  krb5_auth_context ac_out = NULL;
  krb5_data outbuf, inbuf;
  krb5_creds creds, *credsp = NULL, *credsptr = NULL;
  krb5_ccache ccache;
  krb5_principal pclient, pserver;
  krb5_flags ap_req_options = 0;
  int free_pclient = 0;
  krb5_error_code rc = 0;
  int free_ccacheo = 0;
  static const char *kwlist[] = {
    "self", "server", "data", "options", "client", "ccache", "auth_context", "creds", NULL
  };

  if(!PyArg_ParseTupleAndKeywords(args, kw, "O|OSiOOOO:mk_req", (char **)kwlist, &self,
				  &server,
				  &in_data, &ap_req_options,
				  &client,
				  &ccacheo,
				  &auth_context,
				  &credso))
    return NULL;

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

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

  memset(&creds, 0, sizeof(creds));

  if(credso)
    {
      credsptr = &creds;

      if(!PyArg_ParseTuple(credso, "OO(iz#)(iiii)OOOz#z#O",
			   &client, &server,
			   &creds.keyblock.enctype, &creds.keyblock.contents, &creds.keyblock.length,
			   &creds.times.authtime, &creds.times.starttime, &creds.times.endtime,
			   &creds.times.renew_till, &tmp, &tmp, &tmp,
			   &creds.ticket.data,
			   &creds.ticket.length,
			   &creds.second_ticket.data,
			   &creds.second_ticket.length,
			   &tmp))
	return NULL;
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

  if(client && client != Py_None)
    {
      tmp = PyObject_GetAttrString(client, "_princ");
      pclient = PyCObject_AsVoidPtr(tmp);
    }
  else
    {
      if(!ccache)
	{
	  PyErr_Format(PyExc_TypeError, "A ccache is required");
	  return NULL;
	}

      rc = krb5_cc_get_principal(kctx, ccache, &pclient);
      if(rc)
	return pk_error(rc);
      free_pclient = 1;
    }

  if(server && server != Py_None)
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

      /* Construct and evaluate an AuthContext.__init__() call,
       * which makes a copy of the AuthContext input parameter,
       * as we've modified it:
       */
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
  /* mk_req()'s retval is a 2-elt tuple:  (AuthContext, string) */
  PyTuple_SetItem(retval, 0, auth_context);
  PyTuple_SetItem(retval, 1, PyString_FromStringAndSize(outbuf.data, outbuf.length));
  krb5_free_data_contents(kctx, &outbuf);

  return retval;
} /* KrbV.Context.mk_req() */

#ifdef Py_DEBUG
static int
check_obj(PyObject *op)
{
  return (!op->_ob_prev || !op->_ob_next ||
	  op->_ob_prev->_ob_next != op || op->_ob_next->_ob_prev != op || op->ob_refcnt <= 0);
}
#else
static int
check_obj(PyObject *op __UNUSED)
{
  return 0;
}
#endif

static PyObject *
make_principal(PyObject *ctx_obj, krb5_context ctx, krb5_principal orig_princ)
{
  PyObject *subargs, *otmp, *mykw, *retval;
  krb5_principal princ;

  if(!orig_princ)
    {
      Py_INCREF(Py_None);
      return NULL;
    }
  
  krb5_copy_principal(ctx, orig_princ, &princ);
  otmp = PyCObject_FromVoidPtrAndDesc(princ, ctx, destroy_principal);
  subargs = Py_BuildValue("(O)", otmp);
  mykw = PyDict_New();
  PyDict_SetItemString(mykw, "context", ctx_obj);
  retval = PyEval_CallObjectWithKeywords(principal_class, subargs, mykw);
  Py_DECREF(subargs);
  Py_XDECREF(mykw);
  Py_DECREF(otmp);

  return retval;
}

static PyObject *
make_ticket_times(krb5_ticket_times *times)
{
  if(!times)
    {
      Py_INCREF(Py_None);
      return Py_None;
    }

  return Py_BuildValue("(iiii)",
		       times->authtime,
		       times->starttime,
		       times->endtime,
		       times->renew_till);
}

static PyObject *
make_transited(krb5_transited *transited)
{
  if(!transited)
    {
      Py_INCREF(Py_None);
      return Py_None;
    }

  return Py_BuildValue("(iz#)",
		       transited->tr_type,
		       transited->tr_contents.data,
		       transited->tr_contents.length);
}

static PyObject *
make_keyblock(krb5_keyblock *keyblock)
{
  if(!keyblock)
    {
      Py_INCREF(Py_None);
      return Py_None;
    }

  return Py_BuildValue("(iz#)",
		       keyblock->enctype,
		       keyblock->contents,
		       keyblock->length);
}

static PyObject *
make_authdata_list(krb5_authdata **authdata)
{
  int i, n;
  PyObject *adlist;

  if(!authdata)
    {
      Py_INCREF(Py_None);
      return Py_None;
    }
  for(n = 0; authdata[n]; n++) /* */;
  adlist = PyTuple_New(n);
  for(i = 0; i < n; i++)
    PyTuple_SetItem(adlist, i,
		    Py_BuildValue("(iz#)", authdata[i]->ad_type, authdata[i]->contents,
				  authdata[i]->length));
  return adlist;
}

static PyObject *
make_address_list(krb5_address **caddrs)
{
  PyObject *retval;
  int i, n;

  if(!caddrs)
    {
      Py_INCREF(Py_None);
      return Py_None;
    }

  for(n = 0; caddrs[n]; n++) /* */;
  retval = PyTuple_New(n);
  for(i = 0; i < n; i++)
    PyTuple_SetItem(retval, i,
		    Py_BuildValue("(iz#)", caddrs[i]->addrtype, caddrs[i]->contents, caddrs[i]->length));

  return retval;
}

/* ============================ Class Methods =============================== */

PyDoc_STRVAR(Context_rd_req__doc__,
"rd_req(in_data, options, server, keytab, auth_context) ->                   \n\
       (auth_context, int, tkt-cipher [,tkt-plain])                          \n\
                                                                             \n\
:Parameters:                                                                 \n\
    in_data : buffer                                                         \n\
         The buffer containing the AP_REQ message.                           \n\
    options : int                                                            \n\
         The options from the AP_REQ message, as prepared by mk_req().       \n\
         If the options are not needed, specify 'None' for this parameter.   \n\
         BUG:  This should be an Output parameter, and the rd_req() method   \n\
         ignores the input options.  rd_req() does return the output options \n\
         correctly, in the retval tuple.                                     \n\
    server : krbV.Principal                                                  \n\
         The server name. The server principal in the AP_REQ must            \n\
         be the same as the principal specified by this parameter.           \n\
         Specify 'None' if any server principal is acceptable.               \n\
    keytab : KrbV.keytab                                                     \n\
         The key table that contains the server key. The default key table   \n\
         is used if 'None' is specified for this parameter.                  \n\
    auth_context : KrbV.auth_context                                         \n\
         info about the kerberos-session, especially:                        \n\
            * the server's principal-name,                                   \n\
            * any session-key the server shares with the client,             \n\
            * the session's replay-cache.                                    \n\
                                                                             \n\
:Summary: Parse a Krb 'application request' message.                         \n\
                                                                           \n\
:Purpose :                                                                 \n\
An application server calls rd_req() in order to authenticate a client's   \n\
request for service (AP_REQ).  The client's AP_REQ message includes the    \n\
client's encrypted service-ticket and an encrypted timestamp (aka          \n\
'authenticator'). rd_req() decrypts both of these.                         \n\
The server calls rd_req() as the 2nd step in an authenticated handshake.   \n\
                                                                           \n\
:Action & side-effects :                                                   \n\
rd_req() doesn't actually read the AP_REQ message from the network;        \n\
rd_req() only decrypts, decodes, and interprets the AP_REQ message.        \n\
rd_req() decrypts the AP_REQ message, checks the message for freshness,    \n\
and checks to make sure that the encrypted client-name matches the client  \n\
who requested service.                                                     \n\
rd_req() populates an AuthContext for this session, with the following:    \n\
    * The client's name (from the decrypted ticket);                       \n\
    * The client's session-key (from the decrypted ticket);                \n\
    * The AP_REQ message's timestamp (from the decrypted authenticator);   \n\
    * A handle for a replay cache (which holds this first authenticator).  \n\
                                                                           \n\
:Return value:                                                             \n\
    rd_req() returns a tuple of 3 or 4 elements (usually 4):               \n\
                                                                           \n\
    0. An auth context, including the AP_REQ's decrypted authenticator.    \n\
       This is the input authentication context, or a new AuthContext      \n\
       object if the input AuthContext value was 'None'.                   \n\
    1. The client request's stipulated security options.                   \n\
       For example, the client sends the flag krbV.AP_OPTS_MUTUAL_REQUIRED \n\
       in order to tell the server to authenticate itself in return.       \n\
    2. The server's Principal object,                                      \n\
    3. A tuple, containing the plaintext of the ticket that mk_req() sent: \n\
        a. ticket flags,                                                   \n\
        b. session-key, including the enctype,                             \n\
        c. the authenticated name of the client who  sent  the  AP_REQ,    \n\
	d. list of transited realms (if this was an inter-realm AP_REQ),   \n\
        e. ticket-validity times:  auth, start, end, renew_till,           \n\
        f. array of pointers to addresses,                                 \n\
        g. authorization data.                                             \n\
Whew!                                                                      \n\
                                                                           \n\
:See also:                                                                 \n\
KrbV.Context     methods : mk_req(),  mk_rep(), rd_rep();                  \n\
KrbV.AuthContext methods : mk_priv(), rd_priv()                            \n\
The krb5_rd_req() man page fully explains rd_req()'s actions & results.    \n\
");

static PyObject*
Context_rd_req(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *server = NULL, *keytab = NULL, *tmp, *auth_context = NULL;
  krb5_auth_context ac_out = NULL;
  krb5_data inbuf;
  krb5_keytab kt = NULL;
  krb5_principal pserver = NULL;
  krb5_flags ap_req_options = 0;
  krb5_error_code rc = 0;
  krb5_ticket *ticket = NULL;
  int free_keytab = 0;
  static const char *kwlist[] = {"self", "in_data", "options", "server", "keytab", "auth_context", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kw, "Oz#|iOOO:rd_req", (char **)kwlist,
				  &self, &inbuf.data, &inbuf.length, &ap_req_options, &server, &keytab, &auth_context))
    return NULL;

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  assert(!check_obj(args));
  
  if(auth_context)
    {
      tmp = PyObject_GetAttrString(auth_context, "_ac");
      ac_out = PyCObject_AsVoidPtr(tmp);
    }

  if(keytab == Py_None)
    {
      PyObject *subargs;
      subargs = Py_BuildValue("(O)", self);
      keytab = Context_kt_default(unself, subargs, NULL);
      Py_DECREF(subargs);
      free_keytab = 1;
    }
  if(keytab)
    {
      tmp = PyObject_GetAttrString(keytab, "_keytab");
      kt = PyCObject_AsVoidPtr(tmp);
      if(free_keytab)
	{
	  Py_DECREF(keytab);
	}
    }

  if(server)
    {
      tmp = PyObject_GetAttrString(server, "_princ");
      pserver = PyCObject_AsVoidPtr(tmp);
    }

  assert(!check_obj(args));

  rc = krb5_rd_req(kctx, &ac_out, &inbuf, pserver, kt, &ap_req_options, &ticket);
  if(rc)
    return pk_error(rc);

  retval = PyTuple_New(ticket->enc_part2?4:3);
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
  assert(!check_obj(args));

  PyTuple_SetItem(retval, 0, auth_context);
  PyTuple_SetItem(retval, 1, PyInt_FromLong(ap_req_options));
  if(!(tmp = make_principal(self, kctx, ticket->server)))
    {
      Py_DECREF(retval);
      krb5_free_ticket(kctx, ticket);
      return NULL;
    }
  
  PyTuple_SetItem(retval, 2, tmp);

  if(ticket->enc_part2)
    {
      PyObject *princtmp;

      if(!(princtmp = make_principal(self, kctx, ticket->enc_part2->client)))
	{
	  Py_DECREF(retval);
	  krb5_free_ticket(kctx, ticket);
	  return NULL;
	}

      tmp = Py_BuildValue("(iOOOOOO)",
			  ticket->enc_part2->flags,
			  make_keyblock(ticket->enc_part2->session),
			  princtmp,
			  make_transited(&ticket->enc_part2->transited),
			  make_ticket_times(&ticket->enc_part2->times),
			  make_address_list(ticket->enc_part2->caddrs),
			  make_authdata_list(ticket->enc_part2->authorization_data));
      PyTuple_SetItem(retval, 3, tmp);
    }
  krb5_free_ticket(kctx, ticket);

  assert(!check_obj(args));

  return retval;
} /* KrbV.Context.rd_req() */

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

PyDoc_STRVAR(Context_sendauth__doc__,
"Context_sendauth(fd, version, options, server, client, ccache, data) ->     \n\
auth_context                                                                 \n\
                                                                             \n\
:Summary : Offer and complete an authenticated message-handshake and back.   \n\
                                                                             \n\
:Parameters :                                                                \n\
    fd : file descriptor                                                     \n\
        a network socket (TCP only, not UDP)                                 \n\
    version : str                                                            \n\
        the client's version of the application protocol.                    \n\
    options : int (optional)                                                 \n\
        KRB_AP_REQ flags.  Valid flag values are:                            \n\
            * AP_OPTS_MUTUAL_REQUIRED :                                      \n\
                The client requires mutual authentication, ie, kerberized    \n\
                proof of the server's identity.                              \n\
                Normally, you need to use this flag, but only for            \n\
                the first send_auth() call on a connection.                  \n\
            * AP_OPTS_USE_SESSION_KEY :                                      \n\
                Specific for user-to-user (ie, peer-to-peer) connections.    \n\
                Not useful for most client-server applications.              \n\
            * AP_OPTS_USE_SUBKEY :                                           \n\
                The application client or server can choose a sub-session    \n\
                key, but this usually isn't necessary.                       \n\
        These KRB_AP_REQ flags can be OR'ed together, as needed.             \n\
        For details about the use of user-to-user and subkeys, see RFC 4120. \n\
    server : KrbV.Principal                                                  \n\
        The application server's principal/instance name.                    \n\
    client : KrbV.Principal (optional)                                       \n\
        The application client's principal/instance name.                    \n\
    ccache : KrbV.CCache (optional)                                          \n\
        The client's credentials cache.                                      \n\
    data : str                                                               \n\
        A plaintext message to be sent in authenticated form.                \n\
    The first two arguments are positional, and the rest are all             \n\
    keyword-parameters.                                                      \n\
                                                                             \n\
:Purpose :                                                                  \n\
    sendauth() is a high-level routine that both sends a client's AP_REQ    \n\
    service-request _and_ receives the server's corresponding AP_REP reply. \n\
    Further, sendauth() will automatically get service-tickets if necessary.\n\
    No application-specific data get exchanged, except for version numbers. \n\
    Note that only application-clients can call sendauth;  the              \n\
    corresponding server-side method is recvauth().                         \n\
    The handshake's outcome is that the client & server both get complete   \n\
    AuthContext objects, which they then can use to exchange encrypted      \n\
    application-traffic via the AuthContext methods mk_priv() & rd_priv().  \n\
                                                                            \n\
:Action & side-effects :                                                    \n\
    A sendauth()/recvauth() handshake seeks agreement on :                  \n\
      * Application-version number;                                         \n\
      * Client authentication;                                              \n\
      * Server authentication (optionally).                                 \n\
    sendauth() may ask the TGS for fresh application-credentials, and will  \n\
    then add this new ticket and session-key to the credentials cache.      \n\
                                                                            \n\
:Return value:                                                              \n\
    sendauth() returns only a new auth_context object, but this is a BUG:   \n\
    The corresponding C call, krb5_sendauth(), also returns :               \n\
      * the decrypted reply-message from the server (for interpretation),   \n\
      * the application service-ticket (for reuse);                         \n\
      * a KRB_ERROR structure (in case the client fails to authentocate).   \n\
    Context.sendauth() should return a tuple.                               \n\
                                                                            \n\
:See also:                                                                  \n\
KrbV.Context     method  : recvauth()                                       \n\
KrbV.AuthContext methods : mk_priv(), rd_priv()                             \n\
");

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

    /* build & run a python call: AuthContext( context=self, ac=ac_out).             */
    /* this makes a copy of sendauth's updated version of the client's auth_context. */
    /* Context.sendauth() returns this updated auth_context.                         */
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
} /* KrbV.Context.sendauth() */

PyDoc_STRVAR(Context_recvauth__doc__,
"Context_recvauth(fd, version, options, client, server, ccache, data) ->       \n\
auth_context                                                                   \n\
                                                                               \n\
:Summary : Accept and complete an authenticated message-handshake.             \n\
                                                                               \n\
:Parameters :                                                                  \n\
    fd : file descriptor                                                       \n\
        a network socket (TCP only, not UDP)                                   \n\
    version : str                                                              \n\
        the client's version of the application protocol.                      \n\
    server : KrbV.Principal (optional)                                         \n\
        The application server's principal/instance name.                      \n\
    keytab : KrbV.Keytab (optional)                                            \n\
        The key table which contains the serer's secret key.                   \n\
    options : int (optional)                                                   \n\
        No server-side flags are defined yet for recvauth() in the krb5 C API. \n\
    The first two arguments are positional, and the rest are all               \n\
    keyword-parameters.                                                        \n\
    BUG: recvauth() should have an auth_context parameter, which holds the     \n\
    server's replay cache object.                                              \n\
                                                                               \n\
:Purpose :                                                                     \n\
    recvauth() is a high-level routine that both receives a client's AP_REQ    \n\
    service-request _and_ sends the server's corresponding AP_REP reply.       \n\
    No application-specific data get exchanged, except for version numbers.    \n\
    Note that only application-servers can call recvauth;  the                 \n\
    corresponding client-side call is sendauth().                              \n\
    The handshake's outcome is that the client & server both get complete      \n\
    AuthContext objects, which they then can use to exchange encrypted         \n\
    application-traffic via the AuthContext methods mk_priv() & rd_priv().     \n\
                                                                               \n\
    sendauth()/recvauth() is supposed to be easier to use than the similar-    \n\
    but-lower-level KrbV.Context methods mk_req(),rd_req(),mk_rep(),rd_rep().  \n\
                                                                               \n\
:Action & side-effects :                                                       \n\
    A sendauth()/recvauth() handshake seeks agreement on :                     \n\
      * Application-version number;                                            \n\
      * Client authentication;                                                 \n\
      * Server authentication (optionally).                                    \n\
    BUG: recvauth() needs an auth_context parameter, so that recvauth()        \n\
    can add the AP_REQ's authenticator to the auth_context's replay cache.     \n\
                                                                               \n\
:Return value:                                                                 \n\
    recvauth() returns only a new auth_context object, but this is a BUG:      \n\
    The corresponding C call, krb5_recvauth(), also returns :                  \n\
      * the application service-ticket (for reuse);                            \n\
      * a KRB_ERROR structure (in case the version numbers don't match, or     \n\
        the client fails to authenticate).                                     \n\
    Context.sendauth() should return a tuple.                                  \n\
                                                                               \n\
:See also:                                                                     \n\
KrbV.Context     method  : sendauth()                                          \n\
KrbV.AuthContext methods : mk_priv(), rd_priv()                                \n\
");

static PyObject*
Context_recvauth(PyObject *unself, PyObject *args, PyObject *kw)
{
  krb5_context kctx = NULL;
  PyObject *ctx, *retval, *self, *fd_obj, *server = NULL, *keytab = NULL, *tmp, *options = NULL;
  krb5_auth_context ac_out = NULL;
  krb5_keytab kt;
  krb5_principal pserver;
  krb5_ticket *cticket;
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

  if(!keytab || keytab == Py_None)
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
  rc = krb5_recvauth(kctx, &ac_out, fd_ptr, appl_version, pserver, ap_req_options, kt, &cticket);
  Py_END_ALLOW_THREADS
  if(rc)
    return pk_error(rc);

  retval = PyTuple_New(2);

  if (cticket->enc_part2)
    {
      PyObject *cprinc;

      if (!(cprinc = make_principal(self, kctx, cticket->enc_part2->client)))
	{
	  Py_DECREF(retval);
	  krb5_free_ticket(kctx, cticket);
	  return NULL;
	}
      PyTuple_SetItem(retval, 1, cprinc);
    }
  else
    {
      PyTuple_SetItem(retval, 1, Py_None);
      Py_INCREF(Py_None);
    }
  krb5_free_ticket(kctx, cticket);


  {
    PyObject *subargs, *mykw = NULL, *otmp, *auth_context;

    subargs = Py_BuildValue("()");
    mykw = PyDict_New();
    PyDict_SetItemString(mykw, "context", self);
    otmp = PyCObject_FromVoidPtrAndDesc(ac_out, kctx, destroy_ac);
    PyDict_SetItemString(mykw, "ac", otmp);
    auth_context = PyEval_CallObjectWithKeywords(auth_context_class, subargs, mykw);
    PyTuple_SetItem(retval, 0, auth_context);
    Py_DECREF(otmp);
    Py_DECREF(subargs);
    Py_XDECREF(mykw);
  }

  return retval;
} /* KrbV.Context.recvauth() */

PyDoc_STRVAR(Context_mk_rep__doc__,
"mk_rep(auth_context) -> str                                                 \n\
                                                                             \n\
:Summary : Create Kerberos AP_REP Message (Authentication Handshake Reply)   \n\
                                                                             \n\
:Parameters :                                                                \n\
    auth_context : KrbV.AuthContext                                          \n\
        info about the kerberos-session, especially:                         \n\
           * the client's & server's principal-names,                        \n\
           * any session-key the server shares with the client,              \n\
           * the session's replay-cache.                                     \n\
                                                                             \n\
:Purpose :                                                                   \n\
An application server calls mk_rep() to prepare an AP_REP reply, after       \n\
having authenticated a client's request for service (AP_REQ).                \n\
                                                                             \n\
:Action & side-effects:                                                      \n\
mk_rep() prepares, but doesn't send, an AP_REP handshake-reply message.      \n\
The most important part of this AP_REP message is the server's echo of       \n\
the client's encrypted timestamp, re-encrypted for the client's eyes.        \n\
The client will interpret the  server's echo of the timestamp as proof       \n\
that it really is the correct app-server who is on the other end of the      \n\
connection (since the server had to be able to decrypt the client's ticket,  \n\
in order to encrypt the AP_REQ authenticator).                               \n\
The server calls mk_rep() as the 3rd step in an authenticated handshake.     \n\
                                                                             \n\
:Return value:                                                               \n\
    mk_rep() returns a Python string containing the AP_REP message.          \n\
                                                                             \n\
:See also:                                                                   \n\
KrbV.Context     methods : mk_req(),  rd_req(), rd_rep();                    \n\
KrbV.AuthContext methods : mk_priv(), rd_priv()                              \n\
");
static PyObject*
Context_mk_rep(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
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
} /* KrbV.Context.mk_rep() */

PyDoc_STRVAR(Context_rd_rep__doc__,
"rd_rep(in_data, auth_context) -> 'None'                                    \n\
                                                                            \n\
:Parameters :                                                               \n\
    in_data : buffer                                                        \n\
         The buffer containing the AP_REP message.                          \n\
    auth_context : KrbV.auth_context                                        \n\
         info about the kerberos-session, especially:                       \n\
            * the client's & server's principal-names,                      \n\
            * any session-key the server shares with the client,            \n\
            * the session's replay-cache.                                   \n\
                                                                            \n\
:Summary: Parse a Krb 'application reply' message.                          \n\
                                                                            \n\
:Purpose :                                                                  \n\
An application-client calls rd_rep() in order to authenticate the           \n\
app-server's AP_REP message.  The app-server's AP_REP message's main        \n\
content is the server's echoed-&-reencrypted version of the client's        \n\
encrypted timestamp (a.k.a. 'authenticator').                               \n\
The client calls rd_rep() as the 4rd step in an authenticated handshake.    \n\
This step completes the client's authentication with the app-server.        \n\
                                                                            \n\
:Action & side-effects :                                                    \n\
rd_rep() doesn't actually read the AP_REP message from the network;         \n\
rd_rep() only decrypts, decodes, and interprets the AP_REP message.         \n\
rd_rep() checks whether the AP_REP message's encrypted timestamp matches    \n\
exactly the encrypted timestamp that the client originally sent in the      \n\
handshake's initial AP_REQ message.                                         \n\
                                                                            \n\
:Return value:                                                              \n\
None.  BUG: rd_rep() should return at least a string containing the AP_REP  \n\
message's contents, so that the client can confirm the server's echoed      \n\
timestamp.  If these four routines {rd,mk}_re{p,q} are to support subkeys,  \n\
then rd_rep() should also return the modified AuthContext parameter.        \n\
");
static PyObject*
Context_rd_rep(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
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
} /* KrbV.Context.rd_rep() */

static PyMethodDef context_methods[] = {
  {"__init__", Context_init, METH_VARARGS|METH_KEYWORDS, Context_init__doc__},
  {"default_ccache", (PyCFunction)Context_cc_default, METH_VARARGS|METH_KEYWORDS, Context_cc_default__doc__},
  {"default_rcache", (PyCFunction)Context_rc_default, METH_VARARGS|METH_KEYWORDS, Context_rc_default__doc__},
  {"default_keytab", (PyCFunction)Context_kt_default, METH_VARARGS|METH_KEYWORDS, Context_kt_default__doc__},
  {"mk_req",         (PyCFunction)Context_mk_req,     METH_VARARGS|METH_KEYWORDS, Context_mk_req__doc__},
  {"rd_req",         (PyCFunction)Context_rd_req,     METH_VARARGS|METH_KEYWORDS, Context_rd_req__doc__},
  {"sendauth",       (PyCFunction)Context_sendauth,   METH_VARARGS|METH_KEYWORDS, Context_sendauth__doc__},
  {"recvauth",       (PyCFunction)Context_recvauth,   METH_VARARGS|METH_KEYWORDS, Context_recvauth__doc__},
  {"mk_rep",         (PyCFunction)Context_mk_rep,     METH_VARARGS|METH_KEYWORDS, Context_mk_rep__doc__},
  {"rd_rep",         (PyCFunction)Context_rd_rep,     METH_VARARGS|METH_KEYWORDS, Context_rd_rep__doc__},
  {NULL, NULL, 0, NULL}
};

static PyObject *
pk_context_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef
    getattr = {"__getattr__", Context_getattr, METH_VARARGS, Context_getattr__doc__},
    setattr = {"__setattr__", Context_setattr, METH_VARARGS, Context_setattr__doc__};
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

/* Convert a krb5_address to a string representation. */
static PyObject *
addr_to_str(krb5_address *kaddr)
{
  const char* ret = NULL;
  char *addr = NULL;

  if (kaddr->addrtype == ADDRTYPE_INET)
    {
      addr = alloca(INET_ADDRSTRLEN);
      ret = inet_ntop(AF_INET, kaddr->contents,
		       addr, INET_ADDRSTRLEN);
    }
  else if (kaddr->addrtype == ADDRTYPE_INET6)
    {
      addr = alloca(INET6_ADDRSTRLEN);
      ret = inet_ntop(AF_INET6, kaddr->contents,
		       addr, INET6_ADDRSTRLEN);
    }

  if (addr == NULL || ret == NULL)
    {
      return NULL;
    }
  else
    {
      return PyString_FromString(addr);
    }
}

typedef struct addr_storage
{
  struct in_addr ip4;
  struct in6_addr ip6;
} addr_storage;

/* Convert a string representation of an address to a krb5_address */
static int
str_to_addr(const char* address, krb5_address *krb5addr, addr_storage *as)
{
  struct in_addr ipv4addr;
  struct in6_addr ipv6addr;

  /* First try ipv4, and if that fails, try ipv6 */
  if (inet_pton(AF_INET, address, &ipv4addr)) {
    krb5addr->addrtype = ADDRTYPE_INET;
    as->ip4 = ipv4addr;
    krb5addr->length = sizeof(as->ip4.s_addr);
    krb5addr->contents = (krb5_octet *) &(as->ip4.s_addr);
    return 1;
  } else if (inet_pton(AF_INET6, address, &ipv6addr)) {
    krb5addr->addrtype = ADDRTYPE_INET6;
    as->ip6 = ipv6addr;
    krb5addr->length = sizeof(as->ip6.s6_addr);
    krb5addr->contents = (krb5_octet *) &(as->ip6.s6_addr);
    return 1;
  }

  return 0;
}

/* Convert an unsigned short port to a krb5_address */
static int
port_to_addr(unsigned short port, krb5_address *krb5addr)
{
  /* If port == 0, don't set anything and return 0 */
  if (port > 0) {
    krb5addr->addrtype = ADDRTYPE_IPPORT;
    krb5addr->length = sizeof(port);
    krb5addr->contents = (krb5_octet *) &port;
    return 1;
  }

  return 0;
}

/*********************** AuthContext **********************/

PyDoc_STRVAR(AuthContext_getattr__doc__,
"__getattr__(string) -> value-object.                                           \n\
                                                                                \n\
:Summary : Set a member-field in the AuthContext object.                        \n\
           Internal function, do not use.                                       \n\
                                                                                \n\
:Parameters :                                                                   \n\
    __getattr__() can get only the following AuthContext-members:               \n\
    * addrs  : tuple ( local_addr, local_port, remote_addr, remote_port)        \n\
    * flags  : integer;  valid flag values are:                                 \n\
	       KRB5_AUTH_CONTEXT_DO_TIME	Use timestamps                            \n\
	       KRB5_AUTH_CONTEXT_RET_TIME	Save timestamps to output structure       \n\
	       KRB5_AUTH_CONTEXT_DO_SEQUENCE	Use sequence numbers                      \n\
	       KRB5_AUTH_CONTEXT_RET_SEQUENCE	Copy sequence numbers to output structure \n\
                                                                                \n\
:Return value :                                                                 \n\
    NULL   means 'invalid attribute,'                                           \n\
    non-zero integer is a kerberos error-code.                                  \n\
");
static PyObject*
AuthContext_getattr(PyObject *unself __UNUSED, PyObject *args)
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
      PyObject *ra1, *ra2, *laddr, *raddr;
      krb5_address *a1=NULL, *a2=NULL;
      rc = krb5_auth_con_getaddrs(ctx, ac, &a1, &a2);
      if(rc)
	return pk_error(rc);
      if(a1)
	{
	  laddr = addr_to_str(a1);
	  if (laddr == NULL)
	    {
	      laddr = Py_None;
	      Py_INCREF(Py_None);
	    }
	  
	  ra1 = PyTuple_New(2);
	  PyTuple_SetItem(ra1, 0, PyInt_FromLong(a1->addrtype));
	  PyTuple_SetItem(ra1, 1, laddr);
	  krb5_free_address(ctx, a1);
	}
      else
	{
	  ra1 = Py_None;
	  Py_INCREF(ra1);
	}
      if(a2)
	{
	  raddr = addr_to_str(a2);
	  if (raddr == NULL)
	    {
	      raddr = Py_None;
	      Py_INCREF(Py_None);
	    }

	  ra2 = PyTuple_New(2);
	  PyTuple_SetItem(ra2, 0, PyInt_FromLong(a2->addrtype));
	  PyTuple_SetItem(ra2, 1, raddr);
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

PyDoc_STRVAR(AuthContext_setattr__doc__,
"__setattr__(string, value-object) -> 'None' , NULL, or a kerberos error code.  \n\
                                                                                \n\
:Summary : Set a member-field in the AuthContext object.                        \n\
           Internal function, do not use.                                       \n\
                                                                                \n\
:Parameters :                                                                   \n\
    __setattr__() supports only the following AuthContext-members:              \n\
    * addrs  : tuple ( local_addr, local_port, remote_addr, remote_port)        \n\
    * flags  : integer;  valid flag values are:                                 \n\
	       KRB5_AUTH_CONTEXT_DO_TIME	Use timestamps                            \n\
	       KRB5_AUTH_CONTEXT_RET_TIME	Save timestamps to output structure       \n\
	       KRB5_AUTH_CONTEXT_DO_SEQUENCE	Use sequence numbers                      \n\
	       KRB5_AUTH_CONTEXT_RET_SEQUENCE	Copy sequence numbers to output structure \n\
    * rcache      : rcache object               (Replay cache)                  \n\
    * useruserkey : tuple ( enctype, string)    (encryption key)                \n\
                                                                                \n\
:Purpose :                                                                      \n\
    __setattr__ changes the AuthContext contents, so as to control the behavior \n\
    of the many krb-lib calls that use the AuthContext as a parameter.          \n\
                                                                                \n\
:Return value :                                                                 \n\
    'None' means 'success,'                                                     \n\
    NULL   means 'invalid value,'                                               \n\
    non-zero integer is a kerberos error-code.                                  \n\
");
static PyObject*
AuthContext_setattr(PyObject *unself __UNUSED, PyObject *args)
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
  else if(!strcmp(name, "addrs"))
    {
      krb5_address localaddr, remoteaddr, localport, remoteport;
      krb5_address *la = NULL, *ra = NULL, *lp = NULL, *rp = NULL;
      unsigned int lport, rport;
      char *laddr, *raddr;
      addr_storage local_as, remote_as;
    
      if(!PyArg_ParseTuple(value, "zIzI", &laddr, &lport, &raddr, &rport))
        return NULL;
      
      if(laddr) {
        if (str_to_addr(laddr, &localaddr, &local_as)) {
          la = &localaddr;
        } else { 
          PyErr_Format(PyExc_AttributeError, "invalid address: %.400s", laddr);
          return NULL;         
        }
      }

      if(raddr) {
        if (str_to_addr(raddr, &remoteaddr, &remote_as)) {
          ra = &remoteaddr;
        } else {
          PyErr_Format(PyExc_AttributeError, "invalid address: %.400s", raddr);
          return NULL;          
        }
      }

      if(lport > 65535 || rport > 65535) {
        PyErr_Format(PyExc_AttributeError, "port numbers cannot be greater than 65535");
        return NULL;
      }

      if (port_to_addr((unsigned short) lport, &localport))
        lp = &localport;
        
      if (port_to_addr((unsigned short) rport, &remoteport))
        rp = &remoteport;
      
      rc = krb5_auth_con_setaddrs(ctx, ac, la, ra);
      if(rc)
        return pk_error(rc);

      rc = krb5_auth_con_setports(ctx, ac, lp, rp);
      if(rc)
        return pk_error(rc);
    }
  else if((!strcmp(name, "context") && ctx) || 
          (!strcmp(name, "_ac") && ac))
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
} /* LrbV.AuthContext.__setattr__() */

PyDoc_STRVAR(AuthContext_rd_priv__doc__,
"rd_priv() -> string, NULL or a kerberos error code                         \n\
                                                                            \n\
:Summary : rd_priv() decrypts and integrity-checks a buffer of ciphertext.  \n\
                                                                            \n\
:Parameters :                                                               \n\
    in_data : string                                                        \n\
        This buffer contains application-specific ciphertext, and is called \n\
        a KRB_PRIV message.                                                 \n\
                                                                            \n\
:Purpose :                                                                  \n\
    Applications call rd_priv() in order to receive an incoming application \n\
    message that the sender protected from eavesdropping and from on-the-   \n\
    fly alteration.  Either side of an application, client or server, can   \n\
    use rd_priv() upon receiving protected, sensitive application traffic.  \n\
    The incoming ciphertext is called a KRB_PRIV message, and was prepared  \n\
    by the sender via a mk_priv() call.                                     \n\
                                                                            \n\
:Return Value :                                                             \n\
    A string containing the decrypted plaintext, or an error code, if       \n\
    rd_priv() detected tampering.                                           \n\
                                                                            \n\
:Action & side-effects :                                                    \n\
    rd_priv() can be computationally expensive, if the application is       \n\
    sending lots of encrypted traffic back-and-forth.  Developers should    \n\
    use rd_priv() only when privacy is really necessary;  often, it's       \n\
    enough to use rd_safe() instead, so as to protect the message only      \n\
    from on-the-fly alteration, without the expense of encryption.          \n\
");
static PyObject *
AuthContext_rd_priv(PyObject *unself __UNUSED, PyObject *args)
{
  PyObject *self, *tmp, *retval;
  krb5_data inbuf, outbuf;
  krb5_auth_context ac = NULL;
  krb5_error_code rc;
  krb5_context ctx = NULL;
  krb5_replay_data rdata = {0, 0, 0};

  if(!PyArg_ParseTuple(args, "Os#", &self, &inbuf.data, &inbuf.length))
    return NULL;

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
      if(!ctx)
	return NULL;
    }
  else
    return NULL;
  tmp = PyObject_GetAttrString(self, "_ac");
  if(tmp)
    ac = PyCObject_AsVoidPtr(tmp);
  if(!ac)
    return NULL;

  memset(&outbuf, 0, sizeof(outbuf));
  rc = krb5_rd_priv(ctx, ac, &inbuf, &outbuf, &rdata);
  if(rc)
    return pk_error(rc);

  retval = PyString_FromStringAndSize(outbuf.data, outbuf.length);
  free(outbuf.data);
  return retval;
} /* KrbV.AuthContext.rd_priv() */

PyDoc_STRVAR(AuthContext_mk_priv__doc__,
"mk_priv() -> string, NULL or a kerberos error code                         \n\
                                                                            \n\
:Summary : mk_priv() encrypts and integrity-protects a buffer of plaintext. \n\
                                                                            \n\
:Parameters :                                                               \n\
    in_data : string                                                        \n\
        This buffer contains application-specific plaintext.                \n\
                                                                            \n\
:Purpose :                                                                  \n\
    Applications call mk_priv() in order to protect an outgoing application \n\
    message from eavesdropping and from on-the-fly alteration.  Either side \n\
    of an application, client or server, can use mk_priv() before sending   \n\
    sensitive application traffic.  The resulting ciphertext is called a    \n\
    KRB_PRIV message.  After the other side receives this KRB_PRIV message, \n\
    the recipient will use rd_priv() to decrypt and validate the message's  \n\
    contents.                                                               \n\
                                                                            \n\
:Return Value :                                                             \n\
    A KRB_PRIV message, which is a string containing the ciphertext.        \n\
                                                                            \n\
:Action & side-effects :                                                    \n\
    mk_priv() can be computationally expensive, if the application is       \n\
    sending lots of encrypted traffic back-and-forth.  Developers should    \n\
    use mk_priv() only when privacy is really necessary;  often, it's       \n\
    enough to use mk_safe() instead, so as to protect the message only      \n\
    from on-the-fly alteration, without the expense of encryption.          \n\
");
static PyObject *
AuthContext_mk_priv(PyObject *unself __UNUSED, PyObject *args)
{
  PyObject *self, *tmp, *retval;
  krb5_data inbuf, outbuf;
  krb5_auth_context ac = NULL;
  krb5_error_code rc;
  krb5_context ctx = NULL;
  krb5_replay_data rdata = {0, 0, 0};

  if(!PyArg_ParseTuple(args, "Os#", &self, &inbuf.data, &inbuf.length))
    return NULL;

  tmp = PyObject_GetAttrString(self, "context");
  if(tmp)
    {
      tmp = PyObject_GetAttrString(tmp, "_ctx");
      if(tmp)
	ctx = PyCObject_AsVoidPtr(tmp);
      if(!ctx)
	return NULL;
    }
  else
    return NULL;
  tmp = PyObject_GetAttrString(self, "_ac");
  if(tmp)
    ac = PyCObject_AsVoidPtr(tmp);
  if(!ac)
    return NULL;

  memset(&outbuf, 0, sizeof(outbuf));
  rc = krb5_mk_priv(ctx, ac, &inbuf, &outbuf, &rdata);
  if(rc)
    return pk_error(rc);

  retval = PyString_FromStringAndSize(outbuf.data, outbuf.length);
  free(outbuf.data);
  return retval;
} /* KrbV.AuthContext.mk_priv() */

static void
destroy_ac(void *cobj, void *desc)
{
  krb5_auth_con_free(desc, cobj);
}

PyDoc_STRVAR(AuthContext_init__doc__,
"__init__() -> KrbV.AuthContext                                              \n\
                                                                             \n\
:Summary : Create a KrbV AuthContext object.                                 \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Purpose :                                                                   \n\
The KrbV.AuthContext class holds an authenticated connection's               \n\
state, just as krb5.Context holds a thread or process's state.               \n\
KrbV.AuthContext is used by the KrbV functions that directly                 \n\
support authentication between an app-server & its client.                   \n\
This class contains the addresses and port numbers for the                   \n\
client and the server, keyblocks and sub-keys, sequence numbers,             \n\
replay cache, and checksum-type, various flags, and more.                    \n\
                                                                             \n\
:Return Value :                                                              \n\
     __init__() returns an AuthContext object.                               \n\
                                                                             \n\
:Other Methods :                                                             \n\
genaddrs()                                                                   \n\
mk_priv()                                                                   .\n\
rd_priv()                                                                    \n\
");

static PyObject*
AuthContext_init(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *acobj = NULL;
  krb5_context ctx;
  krb5_auth_context ac;
  krb5_error_code rc = 0;
  static const char *kwlist[] = { "self", "context", "ac", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kw, "O|OO!:__init__", (char **)kwlist, &self,
				  &conobj, &PyCObject_Type, &acobj))
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
      Py_DECREF(cobj);
      PyObject_SetAttrString(self, "context", conobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
} /* KrbV.AuthContext.__init__() */

PyDoc_STRVAR(AuthContext_genaddrs__doc__,
"genaddrs(file_desc, flags) -> NULL, None, or a kerberos error code          \n\
                                                                             \n\
:Summary : Copy some or all of the socket's addresses and ports to the       \n\
           AuthContext object.                                               \n\
                                                                             \n\
:Parameters :                                                                \n\
    file_handle    : A socket's file-handle object;                          \n\
    flags          : integer                                                 \n\
        0x00000001 : generate the local  network address.                    \n\
        0x00000002 : generate the remote network address.                    \n\
        0x00000004 : generate the local  network address and the local port. \n\
        0x00000008 : generate the remote network address and the local port. \n\
        These flags can be OR'ed toegether, so as to extract some or all of  \n\
        the socket's addresses and ports, selectively.                       \n\
                                                                             \n\
:Purpose :                                                                   \n\
    genaddrs() populates the AuthContext with optional addresses & ports.    \n\
    Some applications need these addresses in order to authenticate          \n\
    principals by IP-address, or for getting forwardable or proxiable        \n\
    tickets.                                                                 \n\
                                                                             \n\
:Return value :                                                              \n\
    If the retval is:                                                        \n\
    * None, then the genaddrs() call was successful.                         \n\
    * NULL, then the socket's file-handle couldn't be converted to a         \n\
      file-descriptor.                                                       \n\
    * Non-zero, then the kerberos library call returned an error.            \n\
");
static PyObject*
AuthContext_genaddrs(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  PyObject *self, *fh, *tmp;
  int fd;
  krb5_context ctx;
  krb5_auth_context ac;
  krb5_flags flags = 0;
  krb5_error_code rc;
  static const char *kwlist[] = {"self", "fh", "flags", NULL};

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
} /* KrbV.AuthContext.genaddrs() */

static PyMethodDef auth_context_methods[] = {
  {"__init__", (PyCFunction)AuthContext_init,     METH_VARARGS|METH_KEYWORDS, AuthContext_init__doc__},
  {"genaddrs", (PyCFunction)AuthContext_genaddrs, METH_VARARGS|METH_KEYWORDS, AuthContext_genaddrs__doc__},
  {"mk_priv",  (PyCFunction)AuthContext_mk_priv,  METH_VARARGS|METH_KEYWORDS, AuthContext_mk_priv__doc__},
  {"rd_priv",  (PyCFunction)AuthContext_rd_priv,  METH_VARARGS|METH_KEYWORDS, AuthContext_rd_priv__doc__},
  {NULL, NULL, 0, NULL}
};

static PyObject *
pk_auth_context_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef
    getattr = {"__getattr__", AuthContext_getattr, METH_VARARGS, AuthContext_getattr__doc__},
    setattr = {"__setattr__", AuthContext_setattr, METH_VARARGS, AuthContext_setattr__doc__};
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
PyDoc_STRVAR(Principal_getattr__doc__,
"__getattr__(string) -> string                                                  \n\
                                                                                \n\
:Summary : Get the value of a member-field in the Principal object.             \n\
           Internal function, do not use.                                       \n\
                                                                                \n\
:Parameters :                                                                   \n\
    This method supports only the following members:                            \n\
    * realm : string     eg, EXAMPLE.COM                                        \n\
    * name  : string     eg, johndoe                                            \n\
                                                                                \n\
:Return Value :                                                                 \n\
    __getattr__() always returns a string, unless the krb library call fails.   \n\
");
static PyObject*
Principal_getattr(PyObject *unself __UNUSED, PyObject *args)
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
      else
	return NULL;
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
} /* KrbV.Principal.__getattr__() */

PyDoc_STRVAR(Principal_setattr__doc__,
"__setattr__(string, object) -> NULL, or None.                                  \n\
                                                                                \n\
:Summary : Set the value of a member-field in the Principal object.             \n\
           Internal function, do not use.                                       \n\
                                                                                \n\
:Parameters :                                                                   \n\
    This method _doesn't_ support setting the following members:                \n\
    * realm : string     eg, EXAMPLE.COM                                        \n\
    * name  : string     eg, johndoe                                            \n\
                                                                                \n\
:Return Value :                                                                 \n\
    NULL means you tried to set a disallowed member's value.                    \n\
    None means you successfully set some other member's value.                  \n\
");
static PyObject*
Principal_setattr(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.Principal.__setattr__() */

static void
destroy_principal(void *cobj, void *desc)
{
  krb5_free_principal(desc, cobj);
}

PyDoc_STRVAR(Principal_init__doc__,
"__init__(string, KrbV.Context) -> KrbV.Principal                            \n\
                                                                             \n\
:Summary : Create a Principal object.                                        \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    name : string     eg, johhndoe@EXAMPLE.COM                               \n\
                                                                             \n\
:Purpose :                                                                   \n\
    A kerberos principal is the basic account-indentifier for all users and  \n\
    application-services that Kerberos authenticates.  The Principal object  \n\
    contains mostly names:                                                   \n\
      * The 'principal name': the user's name or the service's name,         \n\
      * The Kerberos 'realm name', which identifies which kerberos           \n\
        key-database knows about this user or service.                       \n\
      * A service-principal also contains an FQDN for a server               \n\
        that offers the service.                                             \n\
    For example:                                                             \n\
      * 'johndoe/EXAMPLE.COM' is a user's principal, containing both         \n\
        his Principal name johndoe and his realm name EXAMPLE.COM            \n\
      * 'NFS/filer-1.EXAMPLE.COM' is a server's principal, containing        \n\
        the principal name NFS, the server's FQDN, including the realm name. \n\
                                                                             \n\
:Return Value :                                                              \n\
    A Principal object, containing the name components.                      \n\
                                                                             \n\
:Other methods :                                                             \n\
    __getitem__()                                                            \n\
    __len__()                                                                \n\
    __eq__()                                                                 \n\
    __repr__()                                                               \n\
");
static PyObject*
Principal_init(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *princobj;
  krb5_context ctx;
  krb5_principal princ;
  krb5_error_code rc = 0;
  char *name;
  static const char *kwlist[] = {"self", "name", "context", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kw, "OO|O:__init__", (char **)kwlist, &self, &princobj, &conobj))
    return NULL;

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
  else if(PyCObject_Check(princobj))
    cobj = princobj;
  else
    {
      PyErr_Format(PyExc_TypeError, "Invalid type %s for argument 1", princobj->ob_type->tp_name);
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
      Py_DECREF(cobj);
      PyObject_SetAttrString(self, "context", conobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
} /* KrbV.Principal.__init(__) */

PyDoc_STRVAR(Principal_getitem__doc__,
"__getitem__(integer) -> string                                              \n\
                                                                             \n\
:Summary : Get the i^th name component from a principal.                     \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    index : integer                                                          \n\
                                                                             \n\
:Return value :                                                              \n\
    A string containing the indexed name-component in the principal.         \n\
    __getitem__() returns NULL if anything goes wrong.                       \n\
                                                                             \n\
:Purpose :                                                                   \n\
    A Principal holds names in a parsed array of name-components, where      \n\
    a 'component' is a string that appears between dots or slashes.          \n\
    __getitem__() is a krb-internal routine, mostly used for comparing       \n\
    principals, and for reassembling the name-components.                    \n\
");
static PyObject*
Principal_getitem(PyObject *unself __UNUSED, PyObject *args)
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
      else
	return NULL;
    }
  else
    return NULL;
  tmp = PyObject_GetAttrString(self, "_princ");
  if(tmp)
    princ = PyCObject_AsVoidPtr(tmp);
  else
    return NULL;

  if(index >= krb5_princ_size(ctx, princ))
    {
      PyErr_Format(PyExc_IndexError, "index out of range");
      return NULL;
    }

  d = krb5_princ_component(ctx, princ, index);
  retval = PyString_FromStringAndSize(d->data, d->length);

  return retval;
} /* KrbV.Principal.__getitem__() */

PyDoc_STRVAR(Principal_itemlen__doc__,
"__len__() -> integer                                                        \n\
                                                                             \n\
:Summary : Get the number of name-components that a principal has.           \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Return value :                                                              \n\
    A string containing how many name-component are in the principal.        \n\
    __getitem__() returns NULL if anything goes wrong.                       \n\
                                                                             \n\
:Purpose :                                                                   \n\
    A Principal holds names in a parsed array of name-components, where      \n\
    a 'component' is a string that appears between dots or slashes.          \n\
    __len__() is a krb-internal routine, mostly used for comparing           \n\
    principals, and when reassembling the name-components.                   \n\
");
static PyObject*
Principal_itemlen(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.Principal.__len__() */

PyDoc_STRVAR(Principal_eq__doc__,
"__eq__( Principal, Principal) -> integer or None                            \n\
                                                                             \n\
:Summary : Compare two principals' names.                                    \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    Two Principals.                                                          \n\
                                                                             \n\
:Return value :                                                              \n\
    1, if the principals are equal;                                          \n\
    None, if the principals are different.                                   \n\
");
static PyObject*
Principal_eq(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.Principal.__eq__() */

PyDoc_STRVAR(Principal_repr__doc__,
"__repr__() -> string                                                         \n\
                                                                              \n\
:Summary : Make a printable string from the Principal.                        \n\
           Internal function, do not use.                                     \n\
                                                                              \n\
:Purpose :                                                                    \n\
     Reassemble a principal's name-components, to make a printable            \n\
     representation of the principal.                                         \n\
");
static PyObject*
Principal_repr(PyObject *unself __UNUSED, PyObject *args)
{
  PyObject *self, *tmp, *retval;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL;
  char *outname, *outbuf;
  krb5_error_code rc;

  if(!PyArg_ParseTuple(args, "O:__repr__", &self))
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
} /* KrbV.Principal.__repr__() */

static PyMethodDef principal_methods[] = {
  {"__init__",    (PyCFunction)Principal_init,    METH_VARARGS|METH_KEYWORDS, Principal_init__doc__},
  {"__getitem__", (PyCFunction)Principal_getitem, METH_VARARGS, Principal_getitem__doc__},
  {"__len__",     (PyCFunction)Principal_itemlen, METH_VARARGS, Principal_itemlen__doc__},
  {"__eq__",      (PyCFunction)Principal_eq,      METH_VARARGS, Principal_eq__doc__},
  {"__repr__",    (PyCFunction)Principal_repr,    METH_VARARGS, Principal_repr__doc__},
  {NULL, NULL, 0, NULL}
};

static PyObject *
pk_principal_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef
    getattr = {"__getattr__", Principal_getattr, METH_VARARGS, Principal_getattr__doc__},
    setattr = {"__setattr__", Principal_setattr, METH_VARARGS, Principal_setattr__doc__};
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
PyDoc_STRVAR(CCache_getattr__doc__,
"__getattr__(string) -> string                                               \n\
                                                                             \n\
:Summary : Get the value of a member-field in the CCache object.             \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    __getattr__() method can access only the following members:              \n\
    * name : string  name for the ticket cache, with no type prefix.         \n\
    * type : string  CCache type-prefix.                                     \n\
                                                                             \n\
:Return Value :                                                              \n\
    NULL means you tried to access a member that has no value.               \n\
    None means a krb llibrary call threw an error.                           \n\
");
static PyObject*
CCache_getattr(PyObject *unself __UNUSED, PyObject *args)
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
      const char *nom;

      nom = krb5_cc_get_name(ctx, ccache);
      retval = PyString_FromString(nom);
    }
  else if(!strcmp(name, "type"))
    {
      const char *type;

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
} /* KrbV.CCache.__getattr__() */

PyDoc_STRVAR(CCache_setattr__doc__,
"__setattr__() -> NULL or None                                               \n\
                                                                             \n\
:Summary : Set the value of a member-field in the CCache object.             \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    __setattr__() method _doesn't_ support setting the following members:    \n\
    * name                                                                   \n\
    * type                                                                   \n\
                                                                             \n\
:Return Value :                                                              \n\
    NULL means you tried to set a disallowed member's value.                 \n\
    None means you successfully set some other member's value.               \n\
");
static PyObject*
CCache_setattr(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.CCache.__setattr__() */

static void
destroy_ccache(void *cobj, void *desc)
{
  krb5_cc_close((krb5_context)desc, (krb5_ccache)cobj);
}

PyDoc_STRVAR(CCache__init__doc__,
" __init__() -> CCache                                                       \n\
                                                                             \n\
:Summary : Create a new Credentials Cache.                                   \n\
                                                                             \n\
:Parameters :                                                                \n\
    name               : string        (optional) pathname for ticket file   \n\
    ccache             : CCache        (optional) empty CCache object        \n\
    primary_principal  : Principal     (optional)                            \n\
    context            : Context       (optional)                            \n\
                                                                             \n\
:Return Value :                                                              \n\
    CCache object                                                            \n\
                                                                             \n\
:Other Methods :                                                             \n\
  initialize()                                                               \n\
  __eq__()                                                                   \n\
  get_credentials()                                                          \n\
  init_creds_keytab()                                                        \n\
  principal()                                                                \n\
");
static PyObject*
CCache__init__(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *new_cc = NULL, *new_cc_name = NULL, *primary_principal = NULL;
  krb5_context ctx;
  krb5_ccache cc;
  krb5_error_code rc;
  int is_dfl = 0;
  static const char *kwlist[] = {"self",  "name", "ccache", "primary_principal", "context", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kw, "O|SOOO:__init__", (char **)kwlist, &self, &new_cc_name, &new_cc, &primary_principal, &conobj))
    return NULL;

  if(conobj == Py_None)
    conobj = NULL;
  if(new_cc == Py_None)
    new_cc = NULL;
  if(new_cc_name == Py_None)
    new_cc_name = NULL;
  if(primary_principal == Py_None)
    primary_principal = NULL;

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
} /* KrbV.CCache.__init__() */

PyDoc_STRVAR(CCache_eq__doc__,
"__eq__(CCache, CCache) -> 1 or None                                         \n\
                                                                             \n\
:Summary : Compare two credentials-cache objects, by Principal-name          \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    Two Credentials Cache (CCache) objects.                                  \n\
                                                                             \n\
:Return Value :                                                              \n\
    1 if the two CCache objects have the same principal name,                \n\
    None if the two CCache objects' principal names are different.           \n\
");
static PyObject*
CCache_eq(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.CCache.__eq__() */
PyDoc_STRVAR(CCache_principal__doc__,
"principal() -> Principal                                                    \n\
                                                                             \n\
:Summary : Get the value of the CCache's principal member.                   \n\
                                                                             \n\
:Return Value :                                                              \n\
    KrbV.Principal                                                           \n\
                                                                             \n\
:Purpose :                                                                   \n\
    Get the Principal object for the user or service that owns the CCache.   \n\
");
static PyObject*
CCache_principal(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
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
    {
      Py_INCREF(retval);
      return retval;
    }
  PyErr_Clear();

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
    else
      return NULL;
  }

  return retval;
} /* KrbV.CCache.principal() */

PyDoc_STRVAR(CCache_init_creds_keytab__doc__,
"init_creds_keytab(keytab, principal) -> NULL, None, or krb error code       \n\
                                                                             \n\
:Summary : Get a server's initial credentials, using a keytab.               \n\
                                                                             \n\
:Parameters :                                                                \n\
    keytab                                                                   \n\
    principal                                                                \n\
                                                                             \n\
:Return value :                                                              \n\
    None means everything worked.                                            \n\
    NULL means the principal name was invalid.                               \n\
    nonzero integer means the TGT-request failed somehow.                    \n\
                                                                             \n\
:See also :                                                                  \n\
    get_credentials() - for application-clients that need to request & use  \n\
    tickets.                                                                 \n\
");
static PyObject*
CCache_init_creds_keytab(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  static const char *kwlist[] = {"self", "keytab", "principal", NULL};
  PyObject *self, *keytab = NULL, *principal = NULL, *conobj = NULL, *tmp;
  krb5_ccache ccache = NULL;
  krb5_context ctx = NULL;
  krb5_keytab kt = NULL;
  krb5_principal princ = NULL;
  krb5_error_code rc;
  krb5_creds my_creds;
  krb5_get_init_creds_opt options;

  if(!PyArg_ParseTupleAndKeywords(args, kw, "OO|O:init_creds_keytab", (char **)kwlist,
				  &self, &keytab, &principal))
    return NULL;

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
  tmp = PyObject_GetAttrString(keytab, "_keytab");
  if(tmp)
    kt = PyCObject_AsVoidPtr(tmp);
  if(principal == Py_None)
    principal = NULL;
  if(!principal)
    {
      tmp = Py_BuildValue("(O)", self);
      principal = CCache_principal(NULL, tmp, NULL);
      Py_DECREF(tmp);
    }
  tmp = PyObject_GetAttrString(principal, "_princ");
  if(tmp)
    princ = PyCObject_AsVoidPtr(tmp);
  else
    return NULL;
  memset(&my_creds, 0, sizeof(my_creds));

  krb5_get_init_creds_opt_init(&options);
  rc = krb5_get_init_creds_keytab(ctx, &my_creds, princ, kt, 0, NULL, &options);
  if(rc)
    return pk_error(rc);

  rc = krb5_cc_store_cred(ctx, ccache, &my_creds);
  if(rc)
    return pk_error(rc);

  krb5_free_cred_contents(ctx, &my_creds);

  Py_INCREF(Py_None);
  return Py_None;
} /* KrbV.CCache.init_creds_keytab() */

PyDoc_STRVAR(CCache_initialize__doc__,
"initialize(Principal) ->  None, NULL, or krb error code.                    \n\
                                                                             \n\
:Summary : Initialize a CCache for a principal                               \n\
                                                                             \n\
:Parameters :                                                                \n\
    Principal : the user or service that owns this ccache.                   \n\
                                                                             \n\
:Return value :                                                              \n\
    None means everything worked.                                            \n\
    NULL means the principal name was invalid.                               \n\
    nonzero integer means the krb library threw an error.                    \n\
                                                                             \n\
:See also :                                                                  \n\
    init_creds_keytab() - for services that need to request & use client-    \n\
    side.                                                                    \n\
");
static PyObject*
CCache_initialize(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  static const char *kwlist[] = {"self", "principal", NULL};
  PyObject *self, *principal = NULL, *conobj = NULL, *tmp;
  krb5_ccache ccache = NULL;
  krb5_context ctx = NULL;
  krb5_principal princ = NULL;
  krb5_error_code rc;

  if(!PyArg_ParseTupleAndKeywords(args, kw, "OO:initialize", (char **)kwlist,
				  &self, &principal))
    return NULL;

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
  if(principal == Py_None)
    principal = NULL;
  if(!principal)
    {
      PyErr_SetNone(PyExc_ValueError);
      return NULL;
    }
  tmp = PyObject_GetAttrString(principal, "_princ");
  if(tmp)
    princ = PyCObject_AsVoidPtr(tmp);
  else
    return NULL;

  rc = krb5_cc_initialize(ctx, ccache, princ);
  if(rc)
    return pk_error(rc);

  Py_INCREF(Py_None);
  return Py_None;
}
PyDoc_STRVAR(CCache_get_credentials__doc__,
"get_credentials(Creds_tuple, integer, integer) -> Creds_tuple               \n\
                                                                             \n\
:Summary : Get an application-service ticket.                                \n\
                                                                             \n\
:Parameters :                                                                \n\
    in_creds : Creds_tuple                                                   \n\
    options  : integer                                                       \n\
       0x00000001 KRB5_GC_USER_USER    Get a peer-to-peer ticket             \n\
       0x00000002 KRB5_GC_CACHED       Don't request a new ticket            \n\
    basepid  : integer       (unused?)                                       \n\
                                                                             \n\
:Return Value :                                                              \n\
    Creds_tuple                                                              \n\
                                                                             \n\
:Purpose :                                                                   \n\
    get_credentials() is the normal way for an application client to         \n\
    get tickets on the user's behalf.                                        \n\
                                                                             \n\
:Action & side-effects :                                                     \n\
  * If the CCache contains up-to-date tickets for this service,              \n\
    get_credentials() retrieves those tickets from in_creds or the CCache.   \n\
  * If the CCache doesn't have up-to-date tickets, get_credentials()         \n\
    uses the user's TGT, in the in_creds parameter, to request tickets.      \n\
  * Either way, get credentials() returns an up-to-date application-ticket.  \n\
  * get_credentials() also may use the CCache self-object to find the TGT    \n\
    and to store the new tickets.                                            \n\
                                                                             \n\
:See also :                                                                  \n\
    init_creds_keytab() - for application-servers that need to request & use \n\
    client-side tickets.                                                     \n\
");
static PyObject*
CCache_get_credentials(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  krb5_context ctx = NULL;
  krb5_ccache ccache = NULL;
  PyObject *retval, *self, *tmp, *conobj, *client, *server, *adlist, *addrlist, *subtmp=NULL, *authdata_tmp=NULL;
  krb5_flags options;
  krb5_error_code rc;
  krb5_creds in_creds, *out_creds = NULL;
  int basepid = 0;
  krb5_authdata *adata, **adata_ptrs = NULL;

  static const char *kwlist[]={"self", "in_creds", "options", "basepid", NULL };

  if(!PyArg_ParseTupleAndKeywords(args, kw, "OO!|ii:get_credentials", (char **)kwlist, &self,
				  &PyTuple_Type, &subtmp,
				  &options, &basepid))
    return NULL;

  memset(&in_creds, 0, sizeof(in_creds));
  if(!PyArg_ParseTuple(subtmp, "OO(iz#)(iiii)OOOz#z#O",
		       &client, &server,
		       &in_creds.keyblock.enctype, &in_creds.keyblock.contents, &in_creds.keyblock.length,
		       &in_creds.times.authtime,   &in_creds.times.starttime,   &in_creds.times.endtime,
		       &in_creds.times.renew_till, &tmp, &tmp, &tmp,
		       &in_creds.ticket.data,
		       &in_creds.ticket.length,
		       &in_creds.second_ticket.data,
		       &in_creds.second_ticket.length,
		       &authdata_tmp))
    return NULL;

  if(authdata_tmp && authdata_tmp != Py_None)
    {
      if(PyString_Check(authdata_tmp))
	{
	  adata = alloca(sizeof(krb5_authdata));
	  memset(adata, 0, sizeof(krb5_authdata));
	  adata_ptrs = alloca(sizeof(krb5_authdata *) * 2);
	  adata_ptrs[0] = &adata[0];
	  adata_ptrs[1] = NULL;
	  adata[0].length = PyString_GET_SIZE(authdata_tmp);
	  adata[0].contents = (krb5_octet *) PyString_AS_STRING(authdata_tmp);
	}
      else  if(PySequence_Check(authdata_tmp))
	{
	  int i, n;

	  n = PySequence_Length(authdata_tmp);
	  adata = alloca(sizeof(krb5_authdata) * n);
	  memset(adata, 0, sizeof(krb5_authdata) * n);
	  adata_ptrs = alloca(sizeof(krb5_authdata *) * (n+1));
	  for(i = 0; i < n; i++)
	    {
	      PyObject *otmp = PySequence_GetItem(authdata_tmp, i);
	      if(PyString_Check(otmp))
		{
		  adata[i].length = PyString_GET_SIZE(otmp);
		  adata[i].contents = (krb5_octet *) PyString_AS_STRING(otmp);
		}
	      else if(PySequence_Check(otmp))
		{
		  if(!PyArg_ParseTuple(otmp, "z#i", &adata[i].contents, &adata[i].length, &adata[i].ad_type))
		    return NULL;
		}
	      else
		{
		  PyErr_Format(PyExc_TypeError, "authdata must be a sequence or string");
		  return NULL;
		}

	      adata_ptrs[i] = &adata[i];
	    }
	  adata_ptrs[i] = NULL;
	}
      else
	{
	  PyErr_Format(PyExc_TypeError, "authdata must be a sequence");
	  return NULL;
	}

      in_creds.authdata = adata_ptrs;
    }

  tmp = PyObject_GetAttrString(client, "_princ");
  if(!tmp) return NULL;
  in_creds.client = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(server, "_princ");
  if(!tmp) return NULL;
  in_creds.server = PyCObject_AsVoidPtr(tmp);

  conobj = tmp = PyObject_GetAttrString(self, "context");
  if(!tmp) return NULL;
  tmp = PyObject_GetAttrString(tmp, "_ctx");
  if(!tmp) return NULL;
  ctx = PyCObject_AsVoidPtr(tmp);
  tmp = PyObject_GetAttrString(self, "_ccache");
  if(!tmp) return NULL;
  ccache = PyCObject_AsVoidPtr(tmp);

  rc = krb5_get_credentials(ctx, options, ccache, &in_creds, &out_creds);
  if(rc)
    return pk_error(rc);

  if(out_creds->server != in_creds.server && !krb5_principal_compare(ctx, out_creds->server, in_creds.server))
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
    Py_INCREF(server);

  if(out_creds->client != in_creds.client && !krb5_principal_compare(ctx, out_creds->client, in_creds.client))
    {
      PyObject *subargs, *mykw = NULL;
      krb5_principal princ = NULL;

      krb5_copy_principal(ctx, out_creds->client, &princ);
      subargs = Py_BuildValue("(O)", PyCObject_FromVoidPtrAndDesc(princ, ctx, destroy_principal));
      client = PyEval_CallObjectWithKeywords(principal_class, subargs, mykw);
      Py_XDECREF(mykw);
      Py_XDECREF(subargs);
    }
  else
    Py_INCREF(client);

  addrlist = make_address_list(out_creds->addresses);

  adlist = make_authdata_list(out_creds->authdata);

  retval = Py_BuildValue("(NN(iz#)(iiii)iiNz#z#N)", client, server, out_creds->keyblock.enctype,
			 out_creds->keyblock.contents, out_creds->keyblock.length,
			 out_creds->times.authtime, out_creds->times.starttime,
			 out_creds->times.endtime, out_creds->times.renew_till,
			 out_creds->is_skey, out_creds->ticket_flags, addrlist,
			 out_creds->ticket.data, out_creds->ticket.length,
			 out_creds->second_ticket.data, out_creds->second_ticket.length,
			 adlist);
  krb5_free_creds(ctx, out_creds);

  return retval;
} /* KrbV.CCache.get_credentials() */

static PyMethodDef ccache_methods[] = {
  {"__init__",         (PyCFunction)CCache__init__,          METH_VARARGS|METH_KEYWORDS, CCache__init__doc__},
  {"__eq__",           (PyCFunction)CCache_eq,               METH_VARARGS,               CCache_eq__doc__},
  {"principal",        (PyCFunction)CCache_principal,        METH_VARARGS|METH_KEYWORDS, CCache_principal__doc__},
  {"get_credentials",  (PyCFunction)CCache_get_credentials,  METH_VARARGS|METH_KEYWORDS, CCache_get_credentials__doc__},
  {"init_creds_keytab",(PyCFunction)CCache_init_creds_keytab,METH_VARARGS|METH_KEYWORDS, CCache_init_creds_keytab__doc__},
  {"init",             (PyCFunction)CCache_initialize,       METH_VARARGS|METH_KEYWORDS, CCache_initialize__doc__},
  {NULL, NULL, 0, NULL}
};

static PyObject *
pk_ccache_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef
    getattr = {"__getattr__", CCache_getattr, METH_VARARGS, CCache_getattr__doc__},
    setattr = {"__setattr__", CCache_setattr, METH_VARARGS, CCache_setattr__doc__};
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
PyDoc_STRVAR(RCache_getattr__doc__,
"__getattr__() -> NULL                                                       \n\
:Summary : Vestigial internal function, do not use.                          \n\
:Purpose:                                                                    \n\
     In recent versions of Kerberos, the rcache has become a totally opaque  \n\
     object, and there are no public methods to get information about it.    \n\
");
static PyObject*
RCache_getattr(PyObject *unself __UNUSED, PyObject *args)
{
  /* In recent versions of Kerberos, the rcache has become a totally opaque
     object, and there are no public methods to get information about it. */

  PyObject *self;
  char *name;

  if(!PyArg_ParseTuple(args, "Os:__getattr__", &self, &name))
    return NULL;

  PyErr_Format(PyExc_AttributeError, "%.50s instance has no attribute '%.400s'",
               PyString_AS_STRING(((PyInstanceObject *)self)->in_class->cl_name), name);
  return NULL;
}

PyDoc_STRVAR(RCache_setattr__doc__,
"__setattr__() -> NULL                                                       \n\
:Summary : Vestigial internal function, do not use.                          \n\
:Purpose:                                                                    \n\
     In recent versions of Kerberos, the rcache has become a totally opaque  \n\
     object, and there are no public methods to set RCache attributes.       \n\
");
static PyObject*
RCache_setattr(PyObject *unself __UNUSED, PyObject *args)
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
     || (!strcmp(name, "_rcache") && rcache))
    {
      PyErr_Format(PyExc_AttributeError, "You cannot set attribute '%.400s'", name);
      return NULL;
    }
  else
    PyDict_SetItem(inst->in_dict, nameo, value);

  Py_INCREF(Py_None);
  return Py_None;
}
PyDoc_STRVAR(RCache_init__doc__,
"__init__(context, string) -> NULL or None                                   \n\
                                                                             \n\
:Summary : Initialize a new RCache object (replay cache).                    \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    context : KrbV.Context      (optional) kerberos context object           \n\
    name    : string            (optional) a unique name for the cache       \n\
                                                                             \n\
:Return Value :                                                              \n\
    None means success                                                       \n\
    NULL means the krb library couldn't find a replay-cache.                 \n\
                                                                             \n\
:Purpose :                                                                   \n\
    A replay-cache is a server-side object, which the server's krb-lib uses  \n\
    to detect and reject replays of recently-offered client credentials.     \n\
                                                                             \n\
:Other Methods :                                                             \n\
    __eq__() - Compare two replay caches by principal name.                  \n\
");
static PyObject*
RCache_init(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *new_rc_name = NULL;
  krb5_context ctx;
  krb5_rcache rcache;
  krb5_error_code rc;
  krb5_data rcname;

  if(!PyArg_ParseTuple(args, "O:__init__", &self))
    return NULL;

  if(kw && PyDict_Check(kw))
    {
      conobj = PyDict_GetItemString(kw, "context");
      new_rc_name = PyDict_GetItemString(kw, "name");
    }
  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  if(new_rc_name)
    {
      rcname.data = PyString_AsString(new_rc_name);
      rcname.length = PyString_Size(new_rc_name);
    }
  else
    {
      rcname.data = "default";
      rcname.length = 7;
    }
  
  rc = krb5_get_server_rcache(ctx, &rcname, &rcache);

  if(rc)
    {
      pk_error(rc);
      return NULL;
    }
  else
    {
      cobj = PyCObject_FromVoidPtr(rcache, NULL);
      PyObject_SetAttrString(self, "_rcache", cobj);
      PyObject_SetAttrString(self, "context", conobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
} /* KrbV.RCache.__init__() */

PyDoc_STRVAR(RCache_eq__doc__,
"__eq__() -> 1 or None                                                       \n\
                                                                             \n\
:Summary : Compare two replay caches, by Principal-name.                     \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    Two RCache objects.                                                      \n\
                                                                             \n\
:Return value :                                                              \n\
    1 means the two RCache objects have the  same principal name.            \n\
    None means the  RCache objects have different principal names.           \n\
");
static PyObject*
RCache_eq(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.RCache.__eq__() */

static PyMethodDef rcache_methods[] = {
  {"__init__", (PyCFunction)RCache_init, METH_VARARGS|METH_KEYWORDS, RCache_init__doc__},
  {"__eq__",   (PyCFunction)RCache_eq,   METH_VARARGS,               RCache_eq__doc__},
  {NULL, NULL, 0, NULL}
};

static PyObject *
pk_rcache_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef
    getattr = {"__getattr__", RCache_getattr, METH_VARARGS, RCache_getattr__doc__},
    setattr = {"__setattr__", RCache_setattr, METH_VARARGS, RCache_setattr__doc__};
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

PyDoc_STRVAR(Keytab_getattr__doc__,
"__getattr__(string) -> string                                               \n\
                                                                             \n\
:Summary : Get the value of a member-field in the Keytab object.             \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    __getattr__() method can access only the following members:              \n\
    * name : string  name for the keytab file, in 'type:name' format.        \n\
                                                                             \n\
:Return Value :                                                              \n\
    NULL means you tried to access a member that has no value.               \n\
    None means a krb llibrary call threw an error.                           \n\
");
static PyObject*
Keytab_getattr(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.Keytab.__getattr__() */

PyDoc_STRVAR(Keytab_setattr__doc__,
"__setattr__() -> NULL or None                                               \n\
                                                                             \n\
:Summary : Set the value of a member-field in the Keytab object.             \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    __setattr__() method _doesn't_ support setting the following members:    \n\
    * name                                                                   \n\
                                                                             \n\
:Return Value :                                                              \n\
    NULL means you tried to set a disallowed member's value.                 \n\
    None means you successfully set some other member's value.               \n\
");
static PyObject*
Keytab_setattr(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.Keytab.__setattr__() */

static void
destroy_keytab(void *cobj, void *desc)
{
  krb5_kt_close((krb5_context)desc, (krb5_keytab)cobj);
}

PyDoc_STRVAR(Keytab_init__doc__,
"__init__(context, string) -> NULL or None                                   \n\
                                                                             \n\
:Summary : Initialize a new Keytab object.                                   \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    context : Context object (optional) kerberos context object              \n\
    name    : string         (optional)                                      \n\
                             The key table name in the format 'type:name'.   \n\
                             The type must be a registered keytab type.      \n\
                             The name must be unique for this type.          \n\
    keytab  : Keytab object  (optional)                                      \n\
                                                                             \n\
:Return Value :                                                              \n\
    None means success                                                       \n\
    NULL means the krb library couldn't find a keytab.                       \n\
                                                                             \n\
:Purpose :                                                                   \n\
    A Keytab is a server-side object, which the server's krb-lib uses        \n\
    to access an application-server's secret key.                            \n\
                                                                             \n\
:Action & side-effects:                                                      \n\
  * If __init__() gets called without a Keytab name parameter, then the      \n\
    server's default keytab gets opened.                                     \n\
  * The new Keytab's context attribute is filled with the context parameter. \n\
                                                                             \n\
:Other Methods :                                                             \n\
    __eq__() - Compare two keytab objects by principal name.                 \n\
");
static PyObject*
Keytab_init(PyObject *unself __UNUSED, PyObject *args, PyObject *kw)
{
  PyObject *self;
  PyObject *cobj, *conobj = NULL, *new_kt = NULL;
  char *ktname = NULL;
  krb5_context ctx;
  krb5_keytab keytab;
  krb5_error_code rc;
  int is_dfl = 0;
  static const char *kwlist[] = {"self", "name", "keytab", "context", NULL};

  if(!PyArg_ParseTupleAndKeywords(args, kw, "O|zOO:__init__", (char **)kwlist, &self, &ktname, &new_kt, &conobj))
    return NULL;

  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  if(new_kt)
    {
      rc = 0;
      keytab = PyCObject_AsVoidPtr(new_kt);
    }
  else if(ktname)
    {
      rc = krb5_kt_resolve(ctx, ktname, &keytab);
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
} /* KrbV.Keytab.__init__() */

PyDoc_STRVAR(Keytab_eq__doc__,
"__eq__() -> 1 or None                                                       \n\
                                                                             \n\
:Summary : Compare two Keytab objects, by Principal-name.                    \n\
           Internal function, do not use.                                    \n\
                                                                             \n\
:Parameters :                                                                \n\
    Two Keytab objects.                                                      \n\
                                                                             \n\
:Return value :                                                              \n\
    1 means the two Keytab objects have the  same principal name.            \n\
    None means the  Keytab objects have different principal names.           \n\
");
static PyObject*
Keytab_eq(PyObject *unself __UNUSED, PyObject *args)
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
} /* KrbV.Keytab.__eq__() */

static PyMethodDef keytab_methods[] = {
  {"__init__", (PyCFunction)Keytab_init, METH_VARARGS|METH_KEYWORDS, Keytab_init__doc__},
  {"__eq__",   (PyCFunction)Keytab_eq,   METH_VARARGS,               Keytab_eq__doc__},
  {NULL, NULL, 0, NULL}
};

static PyObject *
pk_keytab_make_class(PyObject *module)
{
  PyMethodDef *def;
  static PyMethodDef
    getattr = {"__getattr__", Keytab_getattr, METH_VARARGS, Keytab_getattr__doc__},
    setattr = {"__setattr__", Keytab_setattr, METH_VARARGS, Keytab_setattr__doc__};
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
} /* pk_keytab_make_class() */

/****** main module ********/
static PyObject *
pk_default_context(PyObject *unself __UNUSED, PyObject *unused_args __UNUSED)
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
  {"default_context", pk_default_context, METH_VARARGS, NULL},
  {NULL, NULL, 0, NULL}
};

void
initkrbV(void)
{
  PyObject *module = Py_InitModule("krbV", krb5_functions);
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

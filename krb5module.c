#include "krb5module.h"
#include "krb5err.h"
#include "krb5util.h"

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

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  {
    PyObject *args, *mykw = NULL;

    args = Py_BuildValue("()");
    if(!kw)
      mykw = kw = PyDict_New();
    PyDict_SetItemString(kw, "context", self); /* Just pass existing keywords straight along */
    retval = PyEval_CallObjectWithKeywords(ccache_class, args, kw);
    Py_DECREF(args);
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

  ctx = PyObject_GetAttrString(self, "_ctx");
  kctx = PyCObject_AsVoidPtr(ctx);

  {
    PyObject *args, *mykw = NULL;

    args = Py_BuildValue("()");
    if(!kw)
      {
	mykw = kw = PyDict_New();
      }
    PyDict_SetItemString(kw, "context", self); /* Just pass existing keywords straight along */
    retval = PyEval_CallObjectWithKeywords(rcache_class, args, kw);
    Py_DECREF(args);
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

static PyMethodDef context_methods[] = {
  {"__init__", Context_init, METH_VARARGS|METH_KEYWORDS},
  {"default_ccache", (PyCFunction)Context_cc_default, METH_VARARGS|METH_KEYWORDS},
  {"default_rcache", (PyCFunction)Context_rc_default, METH_VARARGS|METH_KEYWORDS},
  {"default_keytab", (PyCFunction)Context_kt_default, METH_VARARGS|METH_KEYWORDS},
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

  if(!strcmp(name, "flags"))
    {
      krb5_int32 flags;
      if(PyInt_Check(value))
	flags = PyInt_AsLong(value);
      else if(PyLong_Check(value))
	flags = PyLong_AsLongLong(value);
      else
	{
	  PyErr_Format(PyExc_TypeError, "argument 2 must be a string");
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
  PyObject *cobj, *conobj, *acobj;
  krb5_context ctx;
  krb5_auth_context ac;
  krb5_error_code rc = 0;

  if(!PyArg_ParseTuple(args, "O:__init__", &self))
    return NULL;

  if(PyDict_Check(kw))
    {
      conobj = PyDict_GetItemString(kw, "context");
      acobj = PyDict_GetItemString(kw, "ac");
    }
  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  if(acobj)
    ac = PyCObject_AsVoidPtr(acobj);
  else
    rc = krb5_auth_con_init(ctx, &ac);
  if(rc)
    {
      pk_error(rc);
      return NULL;
    }
  else
    {
      cobj = PyCObject_FromVoidPtrAndDesc(ac, ctx, destroy_ac);
      PyObject_SetAttrString(self, "_ac", cobj);
      PyObject_SetAttrString(self, "context", conobj);
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef auth_context_methods[] = {
  {"__init__", (PyCFunction)AuthContext_init, METH_VARARGS|METH_KEYWORDS},
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
  PyObject *cobj, *conobj;
  krb5_context ctx;
  krb5_principal princ;
  krb5_error_code rc;
  char *name;

  if(!PyArg_ParseTuple(args, "Os:__init__", &self, &name))
    return NULL;

  if(PyDict_Check(kw))
    conobj = PyDict_GetItemString(kw, "context");
  if(!conobj)
    conobj = pk_default_context(NULL, NULL);
  assert(conobj);
  cobj = PyObject_GetAttrString(conobj, "_ctx");
  assert(cobj);
  ctx = PyCObject_AsVoidPtr(cobj);

  rc = krb5_parse_name(ctx, name, &princ);
  if(rc)
    {
      pk_error(rc);
      return NULL;
    }
  else
    {
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

static PyMethodDef principal_methods[] = {
  {"__init__", (PyCFunction)Principal_init, METH_VARARGS|METH_KEYWORDS},
  {"__getitem__", (PyCFunction)Principal_getitem, METH_VARARGS},
  {"__len__", (PyCFunction)Principal_itemlen, METH_VARARGS},
  {"__eq__", (PyCFunction)Principal_eq, METH_VARARGS},
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
      free(nom);
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

  if(PyDict_Check(kw))
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

static PyMethodDef ccache_methods[] = {
  {"__init__", (PyCFunction)CCache_init, METH_VARARGS|METH_KEYWORDS},
  {"__eq__", (PyCFunction)CCache_eq, METH_VARARGS},
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
      free(nom);
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

  if(PyDict_Check(kw))
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

  if(PyDict_Check(kw))
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
      PyObject *klass, *args;

      klass = PyObject_GetAttrString(krb5_module, "Context");
      args = Py_BuildValue("()");
      retval = PyEval_CallObject(klass, args);
      Py_DECREF(args);
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
					   "This module implements python bindings to the Kerberos security API."
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

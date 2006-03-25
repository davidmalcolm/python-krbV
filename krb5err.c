#include "krb5module.h"
#include "krb5err.h"

PyObject *pk_exception = NULL;

PyObject *
pk_error(krb5_error_code rc)
{
  if(rc == ENOMEM)
    {
      PyErr_NoMemory();
    }
  else
    {
      const char *msg = error_message(rc);
      PyObject *py_rc = PyInt_FromLong(rc), *py_msg = PyString_FromString(msg);

      if(py_rc && py_msg) {
	if(PyClass_Check(pk_exception))
	  {
	    PyObject *exc = PyObject_CallFunction(pk_exception, "OO", py_rc, py_msg);
	    if(!exc)
	      return NULL;
	    PyObject_SetAttrString(exc, "err_code", py_rc);
	    PyObject_SetAttrString(exc, "message", py_msg);
	    PyErr_SetObject(pk_exception, exc);
	    Py_DECREF(exc);
	  }
	else
	  PyErr_SetObject(pk_exception, Py_BuildValue("OO", py_rc, py_msg));
      }
      Py_XDECREF(py_rc);
      Py_XDECREF(py_msg);
    }

  return NULL;
}

void
pk_error_init(PyObject *module)
{
  PyObject *dict;

  dict = PyModule_GetDict(module);
  pk_exception = PyErr_NewException("krbV.Krb5Error", NULL, NULL);
  PyDict_SetItemString(dict, "Krb5Error", pk_exception);
}

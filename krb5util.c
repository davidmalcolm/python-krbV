#include "krb5util.h"

void
dict_addint(PyObject *dict, PyObject *revdict, const char *name, long value)
{
  PyObject *key, *val;
  key = PyString_FromString(name);
  val = PyInt_FromLong(value);
  PyDict_SetItem(dict, key, val);
  PyDict_SetItem(revdict, val, key);
}

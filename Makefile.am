INCLUDES=$(PYTHON_INCLUDES) -I$(KRB5_HEADERS)
python_LTLIBRARIES=krb5module.la

krb5module_la_SOURCES=krb5module.c krb5module.h \
	krb5util.c krb5util.h \
	krb5err.c krb5err.h
krb5module_la_LDFLAGS=-module -avoid-version
krb5module_la_LIBADD=$(KRB5_LIBS)
krb5module.c: krb5defines.h

DEFFILES=$(KRB5_HEADERS)/krb5.h
krb5defines.h: $(DEFFILES) gendefines.awk
	awk -f $(srcdir)/gendefines.awk $(DEFFILES) > $@

EXTRA_DIST=gendefines.awk

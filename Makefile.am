INCLUDES=$(PYTHON_INCLUDES) -I/usr/kerberos/include
python_LTLIBRARIES=krb5module.la

krb5module_la_SOURCES=krb5module.c krb5module.h \
	krb5util.c krb5util.h \
	krb5err.c krb5err.h
krb5module_la_LDFLAGS=-module -avoid-version
krb5module_la_LIBADD=-L/usr/kerberos/lib -lkrb5
krb5module.c: krb5defines.h

DEFFILES=/usr/kerberos/include/krb5.h
krb5defines.h: $(DEFFILES) gendefines.awk
	awk -f $(srcdir)/gendefines.awk $(DEFFILES) > $@

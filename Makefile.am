INCLUDES=$(PYTHON_INCLUDES) -I$(KRB5_HEADERDIR)
python_LTLIBRARIES=krbVmodule.la

nodist_krbVmodule_la_SOURCES=krb5defines.h 
krbVmodule_la_SOURCES=krb5module.c krb5module.h \
	krb5util.c krb5util.h \
	krb5err.c krb5err.h
krbVmodule_la_LDFLAGS=-module -avoid-version
krbVmodule_la_LIBADD=$(KRB5_LIBS)
krbVmodule_la_DEPS=krb5defines.h

DEFFILES=$(KRB5_HEADERDIR)/krb5.h
krb5defines.h: $(DEFFILES) gendefines.awk
	awk -f $(srcdir)/gendefines.awk $(DEFFILES) > $@

EXTRA_DIST=gendefines.awk krbVmodule.spec.in
BUILT_SOURCES=krb5defines.h
CLEANFILES=krb5defines.h

dist-hook: krbVmodule.spec
	cp krbVmodule.spec $(distdir)

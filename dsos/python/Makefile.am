CFLAGS := $(filter-out -Werror, ${CFLAGS})
PY_INCLUDES = -I$(top_srcdir)/sos/include \
	      -I$(top_srcdir)/dsos/include \
	      -I$(top_srcdir)/sos/src \
	      -I$(top_srcdir)/ods/include \
	      -I$(NUMPY_INCLUDE_PATH)

pkgpyexec_LTLIBRARIES = Sos.la Array.la

Sos_la_SOURCES = Sos.pyx Sos.pxd
nodist_Sos_la_SOURCES = Sos.c
Sos_la_CFLAGS = $(PY_INCLUDES) $(PYTHON_CPPFLAGS)
Sos_la_LDFLAGS = $(PYTHON_LDFLAGS) -module -shared
Sos_la_LIBADD = $(top_builddir)/dsos/client/libdsos.la \
	$(top_builddir)/sos/src/libsos.la \
	$(top_builddir)/ods/src/libods.la \
	$(top_builddir)/util/json/libjson_util.la  \
	$(top_builddir)/util/mmalloc/libmmalloc.la \
	$(top_builddir)/dsos/util/libpack.la       \
	@LIBZAP_LIBDIR@/libzap.la -lssl

Array_la_SOURCES = Array.pyx
nodist_Array_la_SOURCES = Array.c
Array_la_CFLAGS = $(PY_INCLUDES) $(PYTHON_CPPFLAGS)
Array_la_LDFLAGS = $(PYTHON_LDFLAGS) -module -shared
Array_la_LIBADD = $(top_builddir)/sos/src/libsos.la

pkgpyexecdir = $(pkgpythondir)

pkgpython_PYTHON = __init__.py DataSet.py

dist_bin_SCRIPTS = sos-db sos-part sos-schema sos-import-csv sos-monitor lmq

Sos.c: Sos.pyx Sos.pxd
	echo PYTHON_LDFLAGS are "$(PYTHON_LDFLAGS)"
	cython --gdb --directive language_level=2 $< -o $@

Array.c : Array.pyx
	cython --gdb $< -o $@

clean-local:
	rm -f Sos.c
	rm -f Ldms.c
	rm -f Array.c

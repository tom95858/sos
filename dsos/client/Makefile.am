bin_PROGRAMS =

AM_CFLAGS = -I$(top_srcdir)/dsos/include  \
	    -I$(top_srcdir)/sos/src       \
	    -I$(top_srcdir)/sos/include   \
	    -I$(top_srcdir)/ods/include   \
	    -I$(top_srcdir)/util/json     \
	    -I$(top_srcdir)/util/mmalloc  \
	    -I@LIBZAP_INCDIR@

if ENABLE_DEBUG
AM_CFLAGS += -DDSOS_DEBUG
endif

AM_CPPFLAGS = $(AM_CFLAGS)

libdsos_la_SOURCES = dsos.c dsos_api.c dsos_api_cpp.cc dsos_config.c dsos_conn.c \
	dsos_err.c dsos_obj.c dsos_req.c dsos_rpc.c
lib_LTLIBRARIES = libdsos.la

dsos_ping_SOURCES = dsos_ping.c
dsos_ping_LDADD = libdsos.la                       \
	$(top_builddir)/sos/src/libsos.la          \
	$(top_builddir)/util/json/libjson_util.la  \
	$(top_builddir)/util/mmalloc/libmmalloc.la \
	@LIBZAP_LIBDIR@/libzap.la -lssl
bin_PROGRAMS += dsos_ping

dsos_cmd_SOURCES = dsos_cmd.cc
dsos_cmd_LDADD = libdsos.la                       \
	$(top_builddir)/sos/src/libsos.la          \
	$(top_builddir)/util/json/libjson_util.la  \
	$(top_builddir)/util/mmalloc/libmmalloc.la \
	@LIBZAP_LIBDIR@/libzap.la -lssl
bin_PROGRAMS += dsos_cmd

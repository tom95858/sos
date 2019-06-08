bin_PROGRAMS =

AM_CFLAGS = -I$(top_srcdir)/dsos/include  \
	    -I$(top_srcdir)/dsos/client   \
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

dsos_cmd_SOURCES = dsos_cmd.c
dsos_cmd_LDADD = \
	$(top_builddir)/dsos/client/libdsos.la     \
	$(top_builddir)/sos/src/libsos.la          \
	$(top_builddir)/util/json/libjson_util.la  \
	$(top_builddir)/util/mmalloc/libmmalloc.la \
	@LIBZAP_LIBDIR@/libzap.la -lssl
bin_PROGRAMS += dsos_cmd

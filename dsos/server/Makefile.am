AM_CFLAGS =

if ENABLE_DEBUG
AM_CFLAGS += -DDSOSD_DEBUG
endif

dsosd_SOURCES = dsosd.c dsosd_rpc.c
dsosd_CFLAGS  = $(AM_CFLAGS)         \
	-I$(top_srcdir)/dsos/include \
	-I$(top_srcdir)/sos/src      \
	-I$(top_srcdir)/sos/include  \
	-I$(top_srcdir)/ods/include  \
	-I@LIBZAP_INCDIR@
dsosd_LDADD = $(top_builddir)/sos/src/libsos.la @LIBZAP_LIBDIR@/libzap.la
bin_PROGRAMS = dsosd

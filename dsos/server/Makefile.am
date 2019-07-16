AM_CFLAGS =

if ENABLE_DEBUG
AM_CFLAGS += -DDSOSD_DEBUG
endif

dsosd_SOURCES = dsosd.c dsosd_rpc.c dsosd_rpc_handlers.c
dsosd_CFLAGS  = $(AM_CFLAGS)         \
	-I$(top_srcdir)/dsos/include \
	-I$(top_srcdir)/sos/src      \
	-I$(top_srcdir)/sos/include  \
	-I$(top_srcdir)/ods/include  \
	-I$(top_srcdir)/util/mmalloc \
	-I$(top_srcdir)/dsos/util    \
	-I$(top_srcdir)/util         \
	-I@LIBZAP_INCDIR@
dsosd_LDADD = $(top_builddir)/sos/src/libsos.la    \
	$(top_builddir)/util/mmalloc/libmmalloc.la \
	$(top_builddir)/dsos/util/libpack.la       \
	@LIBZAP_LIBDIR@/libzap.la
bin_PROGRAMS = dsosd

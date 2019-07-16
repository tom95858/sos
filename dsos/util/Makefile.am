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

libpack_la_SOURCES = dsos_pack.c
lib_LTLIBRARIES = libpack.la

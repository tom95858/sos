SUBDIRS =
lib_LTLIBRARIES =

CFLAGS := $(filter-out -Werror, ${CFLAGS})

BUILT_SOURCES = json_parser.h
AM_YFLAGS = -d

EXTRA_DIST = json_lexer.l json_parser.y

json_parser.c: json_parser.h json_util.h

json_parser.h: json_parser.y
	bison --defines=json_parser.h -o json_parser.c $<

json_lexer.c: json_lexer.l json_util.h json_parser.h
	$(LEX) -o $@ $<

nodist_libjson_util_la_SOURCES = json_lexer.c json_parser.c json_parser.h
libjson_util_la_SOURCES = json_util.c json_util.h
libjson_util_la_CFLAGS = -I$(top_srcdir)/ods/include
lib_LTLIBRARIES += libjson_util.la

json_test_SOURCES = json_test.c json_util.h
json_test_CFLAGS = -I$(top_srcdir)/ods/include
json_test_LDADD = $(top_builddir)/util/json/libjson_util.la $(top_builddir)/sos/src/libsos.la
json_test_LDFLAGS = $(AM_LDFLAGS)

sbin_PROGRAMS = json_test

AM_CFLAGS = $(PACKAGE_CFLAGS)

bin_PROGRAMS = lttngtop

noinst_HEADERS = \
	lttngtoptypes.h \
	common.h \
	cputop.h \
	cursesdisplay.h \
	iostreamtop.h

lttngtop_SOURCES = \
	lttngtop.c \
	common.c \
	cursesdisplay.c \
	cputop.c \
	iostreamtop.c

lttngtop_LDADD = -lbabeltrace -lbabeltrace-ctf

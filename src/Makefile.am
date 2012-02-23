AM_CFLAGS = $(PACKAGE_CFLAGS)

bin_PROGRAMS = lttngtop

lttngtop_SOURCES = \
	lttngtop.c \
	common.c \
	cursesdisplay.c \
	cputop.c \
	iostreamtop.c

lttngtop_LDADD = -lbabeltrace -lbabeltrace-ctf

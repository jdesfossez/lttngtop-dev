AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(top_srcdir)/lib -DBABELTRACE_HAVE_LIBUUID

bin_PROGRAMS = lttngtop

noinst_HEADERS = \
	lttngtoptypes.h \
	common.h \
	cputop.h \
	cursesdisplay.h \
	iostreamtop.h \
	mmap-live.h \
	network-live.h

lttngtop_SOURCES = \
	lttngtop.c \
	common.c \
	cursesdisplay.c \
	cputop.c \
	iostreamtop.c \
	mmap-live.c \
	network-live.c

#lttngtop_LDADD = -lbabeltrace -lbabeltrace-ctf -llttngtop-helper -llttng-ctl -lurcu -llttngtopmmappacketseek -llttng-ust-ctl -lcurses -lpanel
lttngtop_LDADD = -lbabeltrace -lbabeltrace-ctf -llttng-ctl -lurcu -llttng-ust-ctl -lcurses -lpanel

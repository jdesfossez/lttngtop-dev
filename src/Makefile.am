AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(top_srcdir)/lib -DBABELTRACE_HAVE_LIBUUID

lib_LTLIBRARIES = libbabeltrace-lttng-live.la

libbabeltrace_lttng_live_la_SOURCES = \
				      network-live.c lttng-live-functions.c

bin_PROGRAMS = lttngtop

noinst_HEADERS = \
	lttngtoptypes.h \
	common.h \
	cputop.h \
	cursesdisplay.h \
	iostreamtop.h \
	mmap-live.h \
	network-live.h \
	lttng-live-functions.h \
	lttngtop.h

lttngtop_SOURCES = \
	lttngtop.c \
	common.c \
	cursesdisplay.c \
	cputop.c \
	iostreamtop.c \
	mmap-live.c

lttngtop_LDFLAGS = -Wl,--no-as-needed

#lttngtop_LDADD = -lbabeltrace -lbabeltrace-ctf -llttngtop-helper -llttng-ctl -lurcu -llttngtopmmappacketseek -llttng-ust-ctl -lcurses -lpanel
lttngtop_LDADD = -lbabeltrace -lbabeltrace-ctf -llttng-ctl -lurcu -llttng-ust-ctl -lcurses -lpanel \
		 $(top_builddir)/src/libbabeltrace-lttng-live.la


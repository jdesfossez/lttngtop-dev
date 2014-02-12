AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(top_srcdir)/lib -DBABELTRACE_HAVE_LIBUUID

lib_LTLIBRARIES = libbabeltrace-lttngtop-live.la

libbabeltrace_lttngtop_live_la_SOURCES = \
				      network-live.c lttng-live-comm.c

bin_PROGRAMS = lttngtop

noinst_HEADERS = \
	lttngtoptypes.h \
	common.h \
	cputop.h \
	cursesdisplay.h \
	iostreamtop.h \
	mmap-live.h \
	network-live.h \
	lttng-live-comm.h \
	lttng-viewer-abi.h \
	lttngtop.h

lttngtop_SOURCES = \
	lttngtop.c \
	common.c \
	cursesdisplay.c \
	cputop.c \
	iostreamtop.c \
	mmap-live.c

lttngtop_LDFLAGS = -Wl,--no-as-needed

lttngtop_LDADD = -lbabeltrace -lbabeltrace-ctf -llttng-ctl \
		 -lurcu -llttng-ust-ctl \
		 $(top_builddir)/src/libbabeltrace-lttngtop-live.la

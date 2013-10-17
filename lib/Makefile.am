SUBDIRS = .

AM_CFLAGS = $(PACKAGE_CFLAGS) -I$(top_srcdir)/lib

lib_LTLIBRARIES = libmmappacketseek.la

libmmappacketseek_la_SOURCES = mmap-packet-seek.c

libmmappacketseek_la_LDFLAGS = \
	-Wl,--no-as-needed \
	-lbabeltrace_types

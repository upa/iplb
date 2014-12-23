## Automake.am for OSPF API client

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib

lib_LTLIBRARIES = libospfapiclient.la
libospfapiclient_la_LDFLAGS = -version-info 0:0:0

sbin_PROGRAMS = ospfclient iplbospfd

libospfapiclient_la_SOURCES = \
	ospf_apiclient.c

ospfapiheaderdir = $(pkgincludedir)/ospfapi

ospfapiheader_HEADERS = \
	ospf_apiclient.h

ospfclient_SOURCES = \
	ospfclient.c

ospfclient_LDADD = libospfapiclient.la \
	../ospfd/libospf.la ../lib/libzebra.la @LIBCAP@

ospfclient_CFLAGS = $(AM_CFLAGS) $(PICFLAGS)
ospfclient_LDFLAGS = $(AM_LDFLAGS) $(PILDFLAGS)

# iplb related definitions
iplbospfd_SOURCES = \
	iplbospfd.c

iplbospfd_LDADD = libospfapiclient.la \
	../ospfd/libospf.la ../lib/libzebra.la @LIBCAP@

iplbospfd_CFLAGS = $(AM_CFLAGS) $(PICFLAGS)
iplbospfd_LDFLAGS = $(AM_LDFLAGS) $(PILDFLAGS)

## Automake.am for OSPF API client

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib

lib_LTLIBRARIES = libospfapiclient.la libnetlink.la libgenl.la
libospfapiclient_la_LDFLAGS = -version-info 0:0:0

sbin_PROGRAMS = ospfclient iplbospfd iplbkspfd

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

# libnetlink and libgenl
libnetlink_la_LDFLAGS = -version-info 0:0:0
libnetlink_la_SOURCES = libnetlink.c
netlinkheaderdir = $(pkgincludedir)/libnetlink
netlinkheader_HEADERS = libnetlink.h

libgenl_la_LDFLAGS = -version-info 0:0:0
libgenl_la_SOURCES = libgenl.c
genlheaderdir = $(pkgincludedir)/libgenl
genlheader_HEADERS = libgenl.h

# iplbospfd
iplbospfd_SOURCES = \
	iplbospfd.c

iplbospfd_LDADD = libospfapiclient.la \
	../ospfd/libospf.la ../lib/libzebra.la libnetlink.la libgenl.la \
	@LIBCAP@

iplbospfd_CFLAGS = $(AM_CFLAGS) $(PICFLAGS)
iplbospfd_LDFLAGS = $(AM_LDFLAGS) $(PILDFLAGS)

# iplbkspfd
iplkspfd_SOURCES = \
	iplbkspfd.c

iplbkspfd_LDADD = libospfapiclient.la \
	../ospfd/libospf.la ../lib/libzebra.la \
	@LIBCAP@

iplbkspfd_CFLAGS = $(AM_CFLAGS) $(PICFLAGS)
iplbkspfd_LDFLAGS = $(AM_LDFLAGS) $(PILDFLAGS)

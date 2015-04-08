/* iplb controller using ospf view python script */

#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <linux/genetlink.h>

#include <zebra.h>
#include "prefix.h"     /* needed by ospf_asbr.h */
#include "privs.h"
#include "table.h"
#include "log.h"
#include "prefix.h"
#include "linklist.h"


#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_api.h"
#include "ospf_apiclient.h"

/* copied from nm_util.h */
#define D(format, ...)                                  \
	fprintf(stderr, "%s [%d] " format "\n",         \
		__FUNCTION__, __LINE__, ##__VA_ARGS__)

#define ASYNCPORT       4000


/* privilages struct.
 */
struct zebra_privs_t ospfd_privs = {
	.user   = NULL,
	.group  = NULL,
	.cap_num_p      = 0,
	.cap_num_i      = 0
};


#include "ospfd/ospf_dump.h"
#include "thread.h"
#include "log.h"

#define DEBUG

struct thread_master * master;
struct ospf_apiclient * oc;
struct ospf_lsdb * lsdb;
static char * kspfc = NULL;
static char * own_router = NULL;
static char * output = NULL;
static int debug_mode = 0;

static struct ospf_lsa *
ospf_lsa_new_from_header (struct lsa_header * lsah)
{
	struct ospf_lsa * new;

	new = ospf_lsa_new ();

	new->data = ospf_lsa_data_new (lsah->length);
	memcpy (new->data, lsah, lsah->length);

	return new;
}

static void
ospf_lsdb_dump (struct ospf_lsdb * db)
{
	int type;
	struct ospf_lsa * lsa;
	struct route_node * rn;
	struct route_table * rt;


	printf ("================ Dump LSDB ================\n");

	for (type = 0; type < OSPF_MAX_LSA; type++) {

		if ((rt = db->type[type].db) == NULL)
			continue;

		for (rn = route_top (rt); rn; rn = route_next (rn)) {
			if ((lsa = rn->info) != NULL) {
				ospf_lsa_header_dump (lsa->data);
			}
		}
	}

	printf ("===========================================\n\n\n");

	return;
}

static void
dump_network_lsa (struct ospf_lsdb * db, struct network_lsa * nlsa, FILE * fp)
{
	int len;
	char ab1[16], ab2[16], buf[64];
	struct in_addr * attached, adv_router;

	adv_router = nlsa->header.adv_router;

	inet_ntop (AF_INET, &adv_router, ab1, sizeof (ab1));

	len = ntohs (nlsa->header.length) - sizeof (struct lsa_header) - 4;

	for (attached = nlsa->routers; len > 0;
	     len -= sizeof (struct in_addr)) {

		if (adv_router.s_addr == attached->s_addr)
			goto next;

		inet_ntop (AF_INET, attached, ab2, sizeof (ab2));
		
		snprintf (buf, sizeof (buf), "NETWORK %s %s\n", ab1, ab2);
		fputs (buf, fp);

	next:
		attached++;
	}
}

static void
dump_network (struct ospf_lsdb * db, FILE * fp)
{
	/* dump links parsed from network lsa */
	struct route_node * rn;
	struct ospf_lsa * lsa;

	for (rn = route_top (db->type[OSPF_NETWORK_LSA].db); rn;
	     rn = route_next (rn)) {
		if ((lsa = rn->info) == NULL)
			continue;
		
		dump_network_lsa (db, (struct network_lsa *) lsa->data, fp);
	}
}

static int
mask2len (struct in_addr netmask)
{
	int len;
	u_int32_t mask = ntohl (netmask.s_addr);
	u_int32_t bit = 0x00000001;

	for (len = 0; len <= 32; len++) {
		if (mask & bit)
			return 32 - len;
		bit <<= 1;
		bit |= 0x00000001;
	}

	return 0;
}

static void
dump_router_lsa (struct ospf_lsdb * db, struct router_lsa * rlsa, FILE * fp)
{
	int len, links, prefixlen;
	char buf[64];
	struct lsa_header * lsa;
	struct router_lsa_link * llsa;

	lsa = &rlsa->header;
	len = ntohs (lsa->length) - sizeof (struct lsa_header) - 4;
	links = ntohs (rlsa->links);

	snprintf (buf, sizeof (buf), "ROUTER %s STUB",
		  inet_ntoa (lsa->adv_router));
	fputs (buf, fp);

	for (llsa = (struct router_lsa_link *) rlsa->link;
	     len > 0 && links > 0;
	     len -= sizeof (struct router_lsa_link), links--) {
		if (llsa->m[0].type != LSA_LINK_TYPE_STUB)
			goto next;

		prefixlen = mask2len (llsa->link_data);
		snprintf (buf, sizeof (buf),
			  " %s/%d", inet_ntoa (llsa->link_id), prefixlen);
		fputs (buf, fp);
	next:
		llsa++;
	}

	fputs ("\n", fp);
	return;
}

static void
dump_router (struct ospf_lsdb * db, FILE * fp)
{
	/* dump router lsa */
	struct route_node * rn;
	struct ospf_lsa * lsa;

	for (rn = route_top (db->type[OSPF_ROUTER_LSA].db); rn;
	     rn = route_next (rn)) {
		if ((lsa = rn->info) == NULL)
			continue;

		dump_router_lsa (db, (struct router_lsa *) lsa->data, fp);
	}
}

static int
iplbkspfd_lsa_read (struct thread * thread)
{
	int fd;
	int ret;
	FILE * fp;
	char cmdbuf[512];
	struct pollfd x[1];

	oc = THREAD_ARG (thread);
	fd = THREAD_FD (thread);

	ret = ospf_apiclient_handle_async (oc); // do callback functions.
	if (ret < 0) {
		D ("ospf_apiclient_handle_async failed");
		exit (1);
	}

	/* check, is the fd read buffer available ? */
	x[0].fd = fd;
	x[0].events = POLLIN;
	if (poll (x, 1, 0) == 0) {
		/* create link info for iplb-kspf.py */

		if (debug_mode) {
			ospf_lsdb_dump (lsdb);
		}

		D ("update LSDB !");
		if (output) {
			fp = fopen (output, "w");
		} else
			fp = stdout;
		if (!fp) {
			D ("failed open output file");
			perror ("fopen");
			return 1;
		}

		dump_router (lsdb, fp);
		dump_network (lsdb, fp);

		fflush (fp);
		if (fp != stdout)
			fclose (fp);

		/* exec kspfc command */
		if (kspfc && output && own_router) {
			snprintf (cmdbuf, sizeof (cmdbuf), "%s %s %s",
				  kspfc, output, own_router);
			D ("exec %s", cmdbuf);
			ret = system (cmdbuf);
		}
	}

	thread_add_read (master, iplbkspfd_lsa_read, oc, fd);

	return 0;
}

static void
lsa_update_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated, struct lsa_header * lsah)
{
	/* update LSDB and re-run iplb-kspf.py */

	struct ospf_lsa * lsa;
	lsa = ospf_lsa_new_from_header (lsah);
	ospf_lsdb_add (lsdb, lsa);

	return;
}

static void
lsa_delete_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated, struct lsa_header * lsah)
{
	/* update LSDB, and re-run iplb-kspf.py */
	struct ospf_lsa * lsa, * old;

	lsa = ospf_lsa_new_from_header (lsah);
	old = ospf_lsdb_lookup (lsdb, lsa);
	if (old)
		ospf_lsdb_delete (lsdb, old);
	else
		D ("old LSA is not found in LSDB!");

	lsa->lock--;
	ospf_lsa_free (lsa);

	return;
}

static void
usage ()
{
	printf ("usage of iplbkspfd\n"
		"\t -s : ospfd api server address\n"
		"\t -k : kspfc script path\n"
		"\t -r : own router id\n"
		"\t -f : output file for kspfc script (default stdout)\n"
		);

	return;
}

int
main (int argc, char ** argv)
{
	int ch;
	char * apisrv = NULL;
	struct thread thread;

	zprivs_init (&ospfd_privs);
	master = thread_master_create ();

	lsdb = ospf_lsdb_new ();

	while ((ch = getopt (argc, argv, "s:k:r:f:d")) != -1) {
		switch (ch) {
		case 's' :
			apisrv = optarg;
			break;
		case 'k' :
			kspfc = optarg;
			break;
		case 'r' :
			own_router = optarg;
			break;
		case 'f' :
			output = optarg;
			break;
		case 'd' :
			debug_mode = 1;
			break;
		default :
			usage ();
			return -1;
		}
	}

	if (!apisrv) {
		D ("-s api server must be specified");
		return 1;
	}

	D ("connect to api server");
	oc = ospf_apiclient_connect (apisrv, ASYNCPORT);
	if (!oc) {
		D ("connecting to OSPF daemon on %s failed!", apisrv);
		return 1;
	}

	D ("register callback");
	ospf_apiclient_register_callback (oc, NULL, NULL, NULL, NULL, NULL,
					  lsa_update_callback,
					  lsa_delete_callback);

	D ("sync lsdb");
	ospf_apiclient_sync_lsdb (oc);

	/* schedule thread that handles asynchronous messages */
	D ("add thread");
	thread_add_read (master, iplbkspfd_lsa_read, oc, oc->fd_async);

	while (1) {
		thread_fetch (master, &thread);
		thread_call (&thread);
	}

	/* not reached */
	return 0;
}

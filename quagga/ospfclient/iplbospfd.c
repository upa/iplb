/* iplb controller using ospf */

#include <poll.h>
#include <unistd.h>

#include <zebra.h>
#include "prefix.h"	/* needed by ospf_asbr.h */
#include "privs.h"
#include "table.h"
#include "log.h"
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

#define ASYNCPORT	4000



/* privilages struct.
 */
struct zebra_privs_t ospfd_privs = {
	.user	= NULL,
	.group	= NULL,
	.cap_num_p	= 0,
	.cap_num_i	= 0
};


#include "ospfd/ospf_dump.h"
#include "thread.h"
#include "log.h"



struct in_addr adv_router;	// The router for own node
struct thread_master * master;
struct ospf_apiclient * oc;
struct ospf_lsdb * lsdb;


/*
 * vertex for calculating spf inclueing ECMP relay points.
 */

struct vertex {

	u_char type;		/* copied from LSA header */
	struct in_addr id;	/* copied from LSA header */
	struct lsa_header * lsa; /* Router or Network LSA */
	uint32_t distance;	/* XXX: hop count */

	struct list * incoming;	/* incoming vertexes */
	struct list * outgoing;	/* outgoing vertexes */
	struct list * stacks;	/* list of stacks of relaying vertexes.
					 * stacks = [ [v,v,v] [v,v,v] [v,v] ].
					 */
};


static struct vertex *
ospf_vertex_new (struct ospf_lsa * lsa)
{
	struct vertex * new;

	new = (struct vertex *) malloc (sizeof (struct vertex));
	memset (new, 0, sizeof (struct vertex));

	new->type = lsa->data->type;
	new->id = lsa->data->id;
	new->lsa = lsa->data;

	new->incoming = list_new ();
	new->outgoing = list_new ();
	new->stacks = list_new ();

	return new;
}

/*
 * Calculate LSDB related
 */

static struct vertex *
ospf_vertex_look_up_id (struct route_table * vs, struct in_addr id)
{
	struct prefix_ls lp;
	struct route_node * rn;
	struct ospf_lsa * find;

	memset (&lp, 0, sizeof (struct prefix_ls));
	lp.family = 0;
	lp.prefixlen = 32;
	lp.id = id;

	rn = route_node_lookup (vs, (struct prefix *) &lp);
	if (rn)
	{
		find = rn->info;
		route_unlock_node (rn);
		return (struct vertex *) find;
	}

	return NULL;
}

static struct vertex *
ospf_vertex_look_up (struct route_table * vs, struct in_addr id,
		     struct in_addr adv_router)
{
	struct prefix_ls lp;
	struct route_node * rn;
	struct ospf_lsa * find;

	memset (&lp, 0, sizeof (struct prefix_ls));
	lp.family = 0;
	lp.prefixlen = 64;
	lp.id = id;
	lp.adv_router = adv_router;

	rn = route_node_lookup (vs, (struct prefix *) &lp);
	if (rn)
	{
		find = rn->info;
		route_unlock_node (rn);
		return (struct vertex *) find;
	}

	return NULL;
}

static struct vertex *
ospf_lsdb_to_vertexes (struct ospf_lsdb * db, struct in_addr adv_router)
{
	/* create complete graph from LSDB */
	char addrbuf1[16], addrbuf2[16];
	struct prefix_ls lp;
	struct ospf_lsa * lsa;
	struct route_node * rn;
	struct vertex * v, * nei;
	struct route_table * nv, * rv;

	/* create vertexes for network LSA */
	nv = route_table_init ();

	LSDB_LOOP (db->type[OSPF_NETWORK_LSA].db, rn, lsa) {
		v = ospf_vertex_new (lsa);
		ls_prefix_set (&lp, lsa);
		rn = route_node_get (nv, (struct prefix *) &lp);

		if (rn->info) {
			inet_ntop (AF_INET, &lsa->data->adv_router, addrbuf1,
				   sizeof (addrbuf1));
			inet_ntop (AF_INET, &lsa->data->id, addrbuf1,
				   sizeof (addrbuf1));
			D ("Duplicated Network LSA adv=%s id=%s",
			   addrbuf1, addrbuf2);
			return NULL; // XXX: free nv and v
		}

		rn->info = v;
	}

	/* create vertexes for router LSA */
	rv = route_table_init ();

	LSDB_LOOP (db->type[OSPF_ROUTER_LSA].db, rn, lsa) {
		v = ospf_vertex_new (lsa);
		ls_prefix_set (&lp, lsa);
		rn = route_node_get (rv, (struct prefix *) &lp);

		if (rn->info) {
			inet_ntop (AF_INET, &lsa->data->adv_router, addrbuf1,
				   sizeof (addrbuf1));
			inet_ntop (AF_INET, &lsa->data->id, addrbuf1,
				   sizeof (addrbuf1));
			D ("Duplicated ROUTER LSA adv=%s id=%s",
			   addrbuf1, addrbuf2);
			return NULL; // XXX: free nv and v
		}

		rn->info = v;
	}


	/* set up link from router vertexes */
	for (rn = route_top (rv); rn; rn = route_next (rn)) {

		int len;
		struct router_lsa * rlsa;
		struct router_lsa_link * llsa;

		v = rn->info;
		rlsa = (struct router_lsa *) v->lsa;

		/* parse router lsa */
		len = v->lsa->length - sizeof (struct lsa_header);
		for (llsa = (struct router_lsa_link *) rlsa->link; len > 0;
		     len -= sizeof (struct router_lsa_link)) {

			switch (llsa->m[0].type) {
			case LSA_LINK_TYPE_POINTOPOINT :
				/* link id and adv router are
				 * router id of neighbor
				 */
				nei = ospf_vertex_look_up (rv, llsa->link_id,
							   llsa->link_id);
				if (!nei) {
					inet_ntop (AF_INET, &v->id, addrbuf1,
						   sizeof (addrbuf1));
					inet_ntop (AF_INET, &llsa->link_id,
						   addrbuf2,
						   sizeof (addrbuf2));
					D ("Neighbor Router "
					   "%s of %s is not found",
					   addrbuf1, addrbuf2);
				}

				/* set link v to nei */
				listnode_add (v->outgoing, nei);
				listnode_add (nei->incoming, v);
				break;

			case LSA_LINK_TYPE_TRANSIT :
				/* link id is interface address of DR */
				nei =ospf_vertex_look_up_id (nv,
							     llsa->link_id);
				if (!nei) {
					inet_ntop (AF_INET, &v->id, addrbuf1,
						   sizeof (addrbuf1));
					inet_ntop (AF_INET, &llsa->link_id,
						   addrbuf2,
						   sizeof (addrbuf2));
					D ("Neighbor Network "
					   "%s of %s is not found",
					   addrbuf1, addrbuf2);
				}

				/* set link v to nei */
				listnode_add (v->outgoing, nei);
				listnode_add (nei->incoming, v);

			default :
				break;
			}

			llsa++;	// next router lsa link
		}
	}

	/* set up link from network vertexes */
	for (rn = route_top (nv); rn; rn = route_next (rn)) {
		int len;
		struct network_lsa * nlsa;
		struct in_addr * attached;

		v = rn->info;
		nlsa = (struct network_lsa *) v->lsa;

		/* parse attached router list */
		len = v->lsa->length - sizeof (struct network_lsa);
		for (attached = nlsa->routers; len > 0;
		     len -= sizeof (struct in_addr)) {

			nei = ospf_vertex_look_up (rv, *attached, * attached);
			if (!nei) {
				inet_ntop (AF_INET, &v->id, addrbuf1,
					   sizeof (addrbuf1));
				inet_ntop (AF_INET, attached, addrbuf2,
					   sizeof (addrbuf2));
				D ("Attached Router"
				   "%s of network %s is not found",
				   addrbuf2, addrbuf1);
			}

			/* set link newtork v to router nei */
			listnode_add (v->outgoing, nei);
			listnode_add (nei->incoming, v);
		}

		attached++;	// next attached router
	}

	/* XXX: Free nv and rv */

	v = ospf_vertex_look_up (rv, adv_router, adv_router);
	if (!v) {
		D ("Router LSA of myself is not found!!");
		return NULL;
	}

	return v;
}

static struct vertex *
iplb_relay_calculate (struct ospf_lsdb * db, struct in_addr adv_router)
{
	struct vertex * v;
	struct list * candidate;

	candidate = list_new ();

	v = ospf_lsdb_to_vertexes (db, adv_router);

	return v;
}

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


static int
iplbospfd_lsa_read (struct thread * thread)
{
	int fd;
	int ret;
	struct pollfd x[1];

	oc = THREAD_ARG (thread);
	fd = THREAD_FD (thread);

	ret = ospf_apiclient_handle_async (oc);	// do callback functions.
	if (ret < 0) {
		D ("%s: ospf_apiclient_handle_async failed\n", __func__);
		exit (1);
	}

	/* check is the fd read buffer available */
	x[0].fd = fd;
	x[0].events = POLLIN;
	if (poll (x, 1, 0) == 0) {
		/* no LSA message in the fd. re-compute LSDB ! */
		D ("re-compute LSDB !!");
		ospf_lsdb_dump (lsdb);
		iplb_relay_calculate (lsdb, adv_router);
	}

	thread_add_read (master, iplbospfd_lsa_read, oc, fd);

	return 0;
}



/*
 * Callback functions for asyncronous events.
 */

static void
lsa_update_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated, struct lsa_header * lsah)
{
	/* update LSDB, and calculate relay points, and re-install it */

	struct ospf_lsa * lsa;

	lsa = ospf_lsa_new_from_header (lsah);
	ospf_lsdb_add (lsdb, lsa);

	return;
}

static void
lsa_delete_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated, struct lsa_header * lsah)
{
	/* update LSDB, and calculate relay points, and re-install it */

	struct ospf_lsa * lsa, * old;

	lsa = ospf_lsa_new_from_header (lsah);

	old = ospf_lsdb_lookup (lsdb, lsa);
	if (old)
		ospf_lsdb_delete (lsdb, old);
	else
		D ("Old LSA is not found in LSDB!!");

	lsa->lock--;
	ospf_lsa_free (lsa);

	return;
}


static void
usage ()
{
	printf ("usage: iplbospfd\n"
		"\t -s : ospfd api server address\n"
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

	while ((ch = getopt (argc, argv, "s:r:")) != -1) {
		switch (ch) {
		case 's' :
			apisrv = optarg;
			break;
		case 'r' :
			if (!inet_pton (AF_INET, optarg, &adv_router)) {
				D ("invalid adv router %s", optarg);
				return 1;
			}
			break;
		default :
			usage ();
			return 1;
		}
	}

	if (!apisrv) {
		D ("-s api server must be specified\n");
		return 1;
	}

	oc = ospf_apiclient_connect (apisrv, ASYNCPORT);
	if (!oc) {
		D ("Connecting to OSPF daemon of %s failed!\n", apisrv);
		exit (1);
	}
	
	ospf_apiclient_register_callback (oc, NULL, NULL, NULL, NULL, NULL,
					  lsa_update_callback,
					  lsa_delete_callback);

	ospf_apiclient_sync_lsdb (oc);

	/* schedule thread that handles asynchronous messages */
	thread_add_read (master, iplbospfd_lsa_read, oc, oc->fd_async);

	while (1) {
		thread_fetch (master, &thread);
		thread_call (&thread);
	}

	/* not reached */
	return 0;
}

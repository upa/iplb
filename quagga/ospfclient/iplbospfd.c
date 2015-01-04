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



struct in_addr adv_router = { 0, };	// The router for own node
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
	int state;		/* OSPF_VERTEX_STATE */
#define OSPF_VERTEX_NOVISIT	0
#define OSPF_VERTEX_CANDIDATE	1
#define OSPF_VERTEX_VISITED	2

	struct vertex * parent;	/* parent */

	struct list * incoming;	/* incoming vertexes */
	struct list * outgoing;	/* outgoing vertexes */
	struct list * stacks;	/* list of stacks of relaying vertexes.
					 * stacks = [ [v,v,v] [v,v,v] [v,v] ].
					 */
};

struct vertex_graph {
	struct route_table * rv_table;	/* table for router LSA vertexes */
	struct route_table * nv_table;	/* table for network LSA vertexes */
	struct vertex * root;		/* root of spf tree */

	struct list * candidate; /* candidate vertexes for spf calculation */
};


static struct vertex *
vertex_new (struct ospf_lsa * lsa)
{
	struct vertex * new;

	new = (struct vertex *) malloc (sizeof (struct vertex));
	memset (new, 0, sizeof (struct vertex));

	new->type = lsa->data->type;
	new->id = lsa->data->id;
	new->lsa = lsa->data;

	new->parent = NULL;

	new->incoming = list_new ();
	new->outgoing = list_new ();
	new->stacks = list_new ();

	new->distance = 0;
	new->state = OSPF_VERTEX_NOVISIT;

	return new;
}

static void
vertex_free (struct vertex * v)
{
	list_delete (v->incoming);
	list_delete (v->outgoing);
	list_delete (v->stacks);

	free (v);

	return;
}

/*
 * Calculate LSDB related
 */

static void
id_prefix_set (struct prefix_ls * lp, struct ospf_lsa * lsa)
{
	if (lp && lsa && lsa->data) {
		lp->family = 0;
		lp->prefixlen = 32;
		lp->id = lsa->data->id;
	}
}

static void
vertex_table_destroy (struct route_table * rt)
{
	struct route_node * rn;

	for (rn = route_top (rt); rn; rn = route_next (rn)) {
		if (rn->info) {
			vertex_free (rn->info);
			rn->info = NULL;
		}
	}
	route_table_finish (rt);

	return;
}

static struct vertex *
vertex_table_lookup_by_id (struct route_table * vt, struct in_addr id)
{
	struct prefix_ls lp;
	struct route_node * rn;
	struct ospf_lsa * find;

	memset (&lp, 0, sizeof (struct prefix_ls));
	lp.family = 0;
	lp.prefixlen = 32;
	lp.id = id;

	rn = route_node_lookup (vt, (struct prefix *) &lp);
	if (rn)
	{
		find = rn->info;
		route_unlock_node (rn);
		return (struct vertex *) find;
	}

	return NULL;
}

static struct vertex *
vertex_table_lookup (struct route_table * vt, struct in_addr id,
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

	rn = route_node_lookup (vt, (struct prefix *) &lp);
	if (rn) {
		find = rn->info;
		route_unlock_node (rn);
		return (struct vertex *) find;
	}

	return NULL;
}

static int
ospf_lsdb_to_vertex_graph (struct ospf_lsdb * db, struct vertex_graph * graph)
{
	/* create complete graph from LSDB */
	char addrbuf1[16], addrbuf2[16];
	struct prefix_ls lp;
	struct ospf_lsa * lsa;
	struct route_node * rn, * lrn;
	struct vertex * v;
	struct route_table * nv, * rv;

	/* create vertex table for router LSA */
	rv = route_table_init ();

	LSDB_LOOP (db->type[OSPF_ROUTER_LSA].db, lrn, lsa) {
		v = vertex_new (lsa);
		ls_prefix_set (&lp, lsa);
		rn = route_node_get (rv, (struct prefix *) &lp);

		if (rn->info) {
			inet_ntop (AF_INET, &lsa->data->adv_router, addrbuf1,
				   sizeof (addrbuf1));
			inet_ntop (AF_INET, &lsa->data->id, addrbuf1,
				   sizeof (addrbuf1));
			D ("Duplicated ROUTER LSA adv=%s id=%s",
			   addrbuf1, addrbuf2);

			vertex_table_destroy (rv);
			return 0;
		}

		rn->info = v;
	}

	/* create vertex table for network LSA */
	nv = route_table_init ();

	LSDB_LOOP (db->type[OSPF_NETWORK_LSA].db, lrn, lsa) {
		v = vertex_new (lsa);
		id_prefix_set (&lp, lsa);
		rn = route_node_get (nv, (struct prefix *) &lp);

		if (rn->info) {
			inet_ntop (AF_INET, &lsa->data->adv_router, addrbuf1,
				   sizeof (addrbuf1));
			inet_ntop (AF_INET, &lsa->data->id, addrbuf1,
				   sizeof (addrbuf1));
			D ("Duplicated Network LSA adv=%s id=%s",
			   addrbuf1, addrbuf2);
			vertex_table_destroy (rv);
			vertex_table_destroy (nv);
			return 0;
		}

		rn->info = v;
	}

	graph->rv_table = rv;
	graph->nv_table = nv;
	graph->candidate = list_new ();

	return 1;
}


static void
vertex_graph_destroy (struct vertex_graph * graph)
{
	vertex_table_destroy (graph->rv_table);
	vertex_table_destroy (graph->nv_table);
	list_delete (graph->candidate);

	return;
}

static void
vertex_candidate_add_router (struct vertex * v, struct vertex * nei,
			     struct list * candidate)
{
	if (nei->state == OSPF_VERTEX_NOVISIT) {
		/* 1st visited. add to candidate. */
		nei->distance = v->distance + 1;
		nei->state = OSPF_VERTEX_CANDIDATE;
		nei->parent = v;
		listnode_add (candidate, nei);
	} else if (nei->state == OSPF_VERTEX_CANDIDATE &&
		   nei->distance > v->distance + 1) {
		/* new shorter route to candidate vertex is found.
		 * update cost and parent.
		 */
		nei->distance = v->distance + 1;
		nei->parent = v;
	} else if (nei->state == OSPF_VERTEX_VISITED && nei->parent != v &&
		   nei->distance == v->distance + 1) {
		/* This link is ECMP. Add link. */
		listnode_add (nei->incoming, v);
		listnode_add (v->outgoing, nei);
	}

	return;
}

static void
vertex_candidate_add_network (struct vertex * v, struct vertex * net,
			      struct list * candidate, struct route_table * rv)
{
	int len;
	char ab1[16], ab2[16];
	struct vertex * nei;
	struct in_addr * attached;
	struct network_lsa * nlsa;

	nlsa = (struct network_lsa *) net->lsa;

	len = ntohs (net->lsa->length) - sizeof (struct lsa_header) - 4;

	for (attached = nlsa->routers; len > 0;
	     len -= sizeof (struct in_addr)) {

		nei = vertex_table_lookup (rv, *attached, *attached);
		if (!nei) {
			inet_ntop (AF_INET, attached, ab1, sizeof (ab1));
			inet_ntop (AF_INET, &net->id, ab2, sizeof (ab2));
			D ("Neighbor Router %s of %s is not found", ab1, ab2);
			assert (nei);
		}
		vertex_candidate_add_router (v, nei, candidate);

		attached++;
	}

	return;
}

static void
vertex_candidate_add (struct vertex * v, struct list * candidate,
		      struct vertex_graph * graph)
{
	int len, links;
	char ab1[16], ab2[16];
	struct vertex * nei;
	struct router_lsa * rlsa;
	struct router_lsa_link * llsa;
	struct route_table * rv, * nv;

	rv = graph->rv_table;
	nv = graph->nv_table;

	/* find neighbor */
	if (v->type != OSPF_ROUTER_LSA) {
		D ("this vertex is not router !!");
		return;
	}

	rlsa = (struct router_lsa *) v->lsa;

	len = ntohs (v->lsa->length) - sizeof (struct lsa_header) - 4;
	links = ntohs (rlsa->links);

	for (llsa = (struct router_lsa_link *)rlsa->link; len > 0 && links > 0;
	     len -= sizeof (struct router_lsa_link), links--) {

		switch (llsa->m[0].type) {
		case LSA_LINK_TYPE_POINTOPOINT :
			/* link id and adv router are router id of neighbor */

			nei = vertex_table_lookup (rv, llsa->link_id,
						   llsa->link_id);
			if (!nei) {
				inet_ntop (AF_INET, &v->id, ab1, sizeof (ab1));
				inet_ntop (AF_INET, &llsa->link_id,
					   ab2, sizeof (ab2));
				D ("Neighbor %s of %s is not found", ab1, ab2);
				assert (nei);
			}

			vertex_candidate_add_router (v, nei, candidate);
			break;

		case LSA_LINK_TYPE_TRANSIT :
			/* link id is interface address of DR.
			 * 1. Find network vertex, and
			 * 2. candidate_add_router for each router vertexes
			 * connected to the network vertex.
			 */
			nei = vertex_table_lookup_by_id (nv, llsa->link_id);
			if (!nei) {
				inet_ntop (AF_INET, &v->id, ab1, sizeof (ab1));
				inet_ntop (AF_INET, &llsa->link_id,
					   ab2, sizeof (ab2));
				D ("Network %s of %s is not found", ab2, ab1);
				assert (nei);
			}

			vertex_candidate_add_network (v, nei, candidate, rv);
			break;
		}

		llsa++;
	}

	return;
}

static struct vertex *
vertex_candidate_decide (struct list * candidate)
{
	u_int32_t distance = 0xFFFFFFFF;
	struct vertex * v, * next;
	struct listnode * node;

	v = NULL;
	next = NULL;

	for (ALL_LIST_ELEMENTS_RO (candidate, node, v)) {
		if (v->distance < distance) {
			next = v;
			distance = v->distance;
		}
	}

	if (next) {
		/* This candidate is decided.
		 * mark visited, and create new link
		 */
		next->state = OSPF_VERTEX_VISITED;
		if (next->parent) {
			listnode_add (next->incoming, next->parent);
			listnode_add (next->parent->outgoing, next);
		}

		listnode_delete (candidate, next);
	}

	return next;
}

static void
candidate_dump (struct list * candidate)
{
	struct listnode * node, * next;
	struct vertex * v;

	for (node = candidate->head; node; node = next) {
		next = node->next;
		v = node->data;
		D ("Vertex ID : %s", inet_ntoa (v->id));
	}
}

static struct vertex_graph
iplb_relay_calculate (struct ospf_lsdb * db, struct in_addr adv_router)
{
	int ret;
	struct vertex * v, * root;
	struct vertex_graph graph;
	struct list * candidate;

	memset (&graph, 0, sizeof (struct vertex_graph));

	ret = ospf_lsdb_to_vertex_graph (db, &graph);

	if (!ret) {
		D ("convert lsdb to graph failed.");
		return graph;
	}

	/* caluculate spf with ECMP relay points */
	candidate = list_new ();

	root = vertex_table_lookup (graph.rv_table, adv_router, adv_router);
	listnode_add (candidate, root);



	while (listcount (candidate)) {
		D ("candidate count is %d", listcount (candidate));
		candidate_dump (candidate);

		v = vertex_candidate_decide (candidate);
		vertex_candidate_add (v, candidate, &graph);
	}

	list_delete (candidate);

	return graph;
}



/*
 * Callback functions for asyncronous events.
 */

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
	struct vertex_graph graph;;
	struct pollfd x[1];

	oc = THREAD_ARG (thread);
	fd = THREAD_FD (thread);

	ret = ospf_apiclient_handle_async (oc);	// do callback functions.
	if (ret < 0) {
		D ("%s: ospf_apiclient_handle_async failed", __func__);
		exit (1);
	}

	/* check is the fd read buffer available */
	x[0].fd = fd;
	x[0].events = POLLIN;
	if (poll (x, 1, 0) == 0) {
		/* no LSA message in the fd. re-compute LSDB ! */
		D ("re-compute LSDB !!");
		ospf_lsdb_dump (lsdb);
		graph = iplb_relay_calculate (lsdb, adv_router);

		vertex_graph_destroy (&graph);
	}

	thread_add_read (master, iplbospfd_lsa_read, oc, fd);

	return 0;
}

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
		"\t -r : router id for root of psf tree\n"
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
		D ("-s api server must be specified");
		return 1;
	}
	if (adv_router.s_addr == 0) {
		D ("-r router id for root of tree must be specified");
		return 1;
	}

	oc = ospf_apiclient_connect (apisrv, ASYNCPORT);
	if (!oc) {
		D ("Connecting to OSPF daemon of %s failed!", apisrv);
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

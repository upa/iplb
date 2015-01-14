/* iplb controller using ospf */

#include <poll.h>
#include <unistd.h>
#include <linux/genetlink.h>

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

#include "libnetlink.h"
#include "libgenl.h"
#include "../../iplb_netlink.h"

/* copied from nm_util.h */
#define D(format, ...)                                  \
        fprintf(stderr, "%s [%d] " format "\n",         \
                __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define ASYNCPORT	4000

/* netlink related.
 */

#define NLREQ_SIZE	1024
static struct rtnl_handle genl_rth;
static int genl_family = -1;


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

#define DEBUG

struct in_addr adv_router = { 0, };	// The router for own node
struct thread_master * master;
struct ospf_apiclient * oc;
struct ospf_lsdb * lsdb;
int enable_iplb = 0;


/* misc
 */
static void
list_copy (struct list * src, struct list * dst)
{
	void * data;
	struct listnode * node;

	for (ALL_LIST_ELEMENTS_RO (src, node, data)) {
		listnode_add (dst, data);
	}
}

static void *
list_tail_data (struct list * list)
{
	return list->tail->data;
}

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

	struct list * incoming;	/* incoming vertexes */
	struct list * outgoing;	/* outgoing vertexes */
	struct list * stacks;	/* list of stacks of relaying vertexes.
					 * stacks = [ [v,v,v] [v,v,v] [v,v] ].
					 */
};

struct vertex_graph {
	struct route_table * rv_table;	/* table for router LSA vertexes */
	struct route_table * nv_table;	/* table for network LSA vertexes */
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
	struct list * stack;
	struct listnode * node;

	list_delete (v->incoming);
	list_delete (v->outgoing);

	for (ALL_LIST_ELEMENTS_RO (v->stacks, node, stack)) {
		list_delete (stack);
	}
	list_delete (v->stacks);

	return;
}

/*
 * for iplb netlink
 */


struct prefix_relay {
	struct in_addr network;	/* destination prefix */
	struct in_addr netmask;
	struct in_addr relay_point[IPLB_MAX_RELAY_POINTS];
};
#define IS_EMPTY_ADDR(a) ((a).s_addr == 0)

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
ospf_lsa_compare (struct lsa_header * la, struct lsa_header * lb)
{
	/* if la is newer than lb, return 1*/

	/* first, compare LS seqnumber */
	if (la->ls_seqnum > lb->ls_seqnum)
		return 1;
	else if (la->ls_seqnum < lb->ls_seqnum)
		return -1;

	/* second, compare LS age */
	if (la->ls_age < lb->ls_age)
		return 1;
	else if (la->ls_age > lb->ls_age)
		return -1;

	/* XXX: finally, should compare checksum */

	return 0;
}

static int
ospf_lsdb_to_vertex_graph (struct ospf_lsdb * db, struct vertex_graph * graph)
{
	/* create complete graph from LSDB */
	struct prefix_ls lp;
	struct ospf_lsa * lsa;
	struct route_node * rn, * lrn;
	struct vertex * v;
	struct route_table * nv, * rv;

	/* create vertex table for router LSA */
	rv = route_table_init ();

	LSDB_LOOP (db->type[OSPF_ROUTER_LSA].db, lrn, lsa) {

		ls_prefix_set (&lp, lsa);
		rn = route_node_get (rv, (struct prefix *) &lp);

		if (rn->info) {
			v = rn->info;
			if (ospf_lsa_compare (lsa->data, v->lsa) > 0) {
				/* processing lsa is newer !! */
				vertex_free (v);
			} else {
				/* existing vertex is newer !! */
				continue;
			}
		}

		rn->info = vertex_new (lsa);
	}

	/* create vertex table for network LSA */
	nv = route_table_init ();

	LSDB_LOOP (db->type[OSPF_NETWORK_LSA].db, lrn, lsa) {

		id_prefix_set (&lp, lsa);
		rn = route_node_get (nv, (struct prefix *) &lp);

		if (rn->info) {
			v = rn->info;
			if (ospf_lsa_compare (lsa->data, v->lsa) > 0) {
				vertex_free (v);
			} else {
				continue;
			}
		}

		rn->info = vertex_new (lsa);
	}

	graph->rv_table = rv;
	graph->nv_table = nv;

	return 1;
}


static void
vertex_graph_destroy (struct vertex_graph * graph)
{
	vertex_table_destroy (graph->rv_table);
	vertex_table_destroy (graph->nv_table);

	return;
}

static void
vertex_candidate_add_router (struct vertex * v, struct vertex * nei,
			     struct list * candidate)
{
	struct listnode * node;
	struct vertex * vo;

	if (nei->state == OSPF_VERTEX_NOVISIT) {
		/* 1st visited. add to candidate. */
		nei->distance = v->distance + 1;
		nei->state = OSPF_VERTEX_CANDIDATE;

		listnode_add (nei->incoming, v);
		listnode_add (v->outgoing, nei);
		listnode_add (candidate, nei);

	} else if (nei->state == OSPF_VERTEX_CANDIDATE &&
		   nei->distance > v->distance + 1) {
		/* new shorter route to candidate vertex is found.
		 * update cost and links.
		 */
		nei->distance = v->distance + 1;

		for (ALL_LIST_ELEMENTS_RO (nei->incoming, node, vo)) {
			listnode_delete (vo->outgoing, nei);
		}
		list_delete (nei->incoming);

		listnode_add (nei->incoming, v);
		listnode_add (v->outgoing, nei);

	} else if (nei->state == OSPF_VERTEX_CANDIDATE &&
		   !listnode_lookup (nei->incoming, v) &&
		   nei->distance == v->distance + 1) {
		/* new ECMP link to candidate vertex is found.
		 * add link.
		 */
		listnode_add (nei->incoming, v);
		listnode_add (v->outgoing, nei);

	}

#if 0
	/* XXX: is threre a possibility that new ecmp link to VISITED vertex
	 * is found on dijkstra algorithm ?
	 */
	else if (nei->state == OSPF_VERTEX_VISITED &&
		   !listnode_lookup (nei->incoming, v) &&
		   nei->distance == v->distance + 1) {
		/* new ECMP link to visited vertex is found.
		 * add link.
		 */
		listnode_add (nei->incoming, v);
		listnode_add (v->outgoing, nei);
	}
#endif

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

static int
check_same_vertex_on_stacks (struct list * incoming)
{
	struct prefix_ls lp;
	struct list * stack;
	struct route_table * rt;
	struct vertex * v, * r;
	struct listnode * n1, * n2;
	struct route_node * rn;

	rt = route_table_init ();

	for (ALL_LIST_ELEMENTS_RO (incoming, n1, v)) {
		for (ALL_LIST_ELEMENTS_RO (v->stacks, n2, stack)) {
			r = list_tail_data (stack);
			if (r == NULL)
				continue;

			memset (&lp, 0, sizeof (struct prefix_ls));
			lp.family = 0;
			lp.prefixlen = 64;
			lp.id = r->lsa->id;
			lp.adv_router = r->lsa->adv_router;

			rn = route_node_get (rt, (struct prefix *) &lp);
			if (!rn->info) {
				/* same vertex found !! */
				route_table_finish (rt);
				return 1;
			}
			rn->info = r;
		}
	}

	route_table_finish (rt);

	return 0;
}

static struct vertex *
vertex_candidate_decide (struct list * candidate)
{
	int ecmped = 0, duplicated = 0;
	u_int32_t distance = 0xFFFFFFFF;
	struct vertex * v, * next;
	struct list * relays, * stack;
	struct listnode * node, * nnode;


	v = NULL;
	next = NULL;

	for (ALL_LIST_ELEMENTS_RO (candidate, node, v)) {
		if (v->distance < distance) {
			next = v;
			distance = v->distance;
		}
	}

	if (!next)
		return NULL;

	/* This candidate is decided. mark visited. */
	next->state = OSPF_VERTEX_VISITED;
	listnode_delete (candidate, next);

	/* copy relay point stacks. */
	/* if incoming multiple incoming links exist, ECMPed vertex.
	 * 1. if there is same vertex in top of multiple stacks,
	      push incoming vertexes to each stacks.
	 * 2. if stack of incoming vertex is null, push the incoming vertex.
	 */

	if (listcount (next->incoming) > 1)
		ecmped = 1;

	if (check_same_vertex_on_stacks (next->incoming))
		duplicated = 1;

#ifdef DEBUG
	printf ("Next vertex is %s, ecmped=%d, duplicated=%d\n",
		inet_ntoa (next->id), ecmped, duplicated);
#endif

	for (ALL_LIST_ELEMENTS_RO (next->incoming, node, v)) {
		/* copy stacks */
		for (ALL_LIST_ELEMENTS_RO (v->stacks, nnode, stack)) {
			relays = list_new ();
			list_copy (stack, relays);

			if (ecmped && duplicated) {
				/* ECMP, and term 1 is fulfilled !!
				 * push vertex to relay points stack !!.
				 */
				listnode_add (relays, v);
			}

			listnode_add (next->stacks, relays);
		}

		if (ecmped && listcount (v->stacks) == 0) {
			/* ECMP, and term 2 is fulfilled !!
			 * push vertex to relay points stack !!.
			 * (copy stack process does not run because
			 * v->stacks * has 0 listnodes).
			 */
			relays = list_new ();
			listnode_add (relays, v);
			listnode_add (next->stacks, relays);
		}
	}

	return next;
}

#ifdef DEBUG
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
#endif

static void
graph_dump (struct vertex_graph * graph)
{
	struct vertex * v, * o, * r;
	struct route_node * rn;
	struct list * stack;
	struct listnode * node, * n1, * n2;

	printf ("\nGRAPH DUMP\n");

	for (rn = route_top (graph->rv_table); rn; rn = route_next (rn)) {
		if (!rn->info) {
			continue;
		}

		v = rn->info;

		printf ("Vertex: %s\n", inet_ntoa (v->id));

		for (ALL_LIST_ELEMENTS_RO (v->outgoing, node, o)) {
			o = node->data;
			printf ("         -> %s\n", inet_ntoa (o->id));
		}

		printf ("    Relay Points\n");
		for (ALL_LIST_ELEMENTS_RO (v->stacks, n1, stack)) {
			printf ("        [ ");
			for (ALL_LIST_ELEMENTS_RO (stack, n2, r)) {
				printf ("%s ", inet_ntoa (r->id));
			}
			printf ("]\n");
		}
	}
}

static struct vertex_graph
prefix_relay_calculate (struct ospf_lsdb * db, struct in_addr adv_router)
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
	if (!root) {
		D ("specified router as root node is not found in LSDB");
		return graph;
	}

	listnode_add (candidate, root);

	while (listcount (candidate)) {

#ifdef DEBUG
		D ("candidate count is %d", listcount (candidate));
		candidate_dump (candidate);
#endif


		v = vertex_candidate_decide (candidate);
		vertex_candidate_add (v, candidate, &graph);
	}

	list_delete (candidate);

	return graph;
}


static void
vertex_to_prefix_relay (struct vertex * v, struct list * prefix_relays)
{
	int n, len, links;
	struct router_lsa * rlsa;
	struct router_lsa_link * llsa;
	struct prefix_relay * pr;
	struct vertex * r;
	struct list * stack;
	struct listnode * n1, * n2;

	rlsa = (struct router_lsa *) v->lsa;

	len = ntohs (v->lsa->length) - sizeof (struct lsa_header) - 4;
	links = ntohs (rlsa->links);

	for (llsa = (struct router_lsa_link *)rlsa->link; len > 0 && links > 0;
	     len -= sizeof (struct router_lsa_link), links--) {
		if (llsa->m[0].type != LSA_LINK_TYPE_STUB)
			goto next;

		for (ALL_LIST_ELEMENTS_RO (v->stacks, n1, stack)) {

			pr = (struct prefix_relay *) malloc
				(sizeof (struct prefix_relay));
			memset (pr, 0, sizeof (struct prefix_relay));
			pr->network = llsa->link_id;
			pr->netmask = llsa->link_data;

			n = 0;
			for (ALL_LIST_ELEMENTS_RO (stack, n2, r)) {
				pr->relay_point[n++] = r->id;
			}

			listnode_add (prefix_relays, pr);
		}
	next:
		llsa++;
	}

	return;
}

static struct list *
gather_prefix_relays (struct vertex_graph * graph)
{
	struct vertex * v;
	struct route_node * rn;
	struct list * prefix_relays;

	prefix_relays = list_new ();

	for (rn = route_top (graph->rv_table); rn; rn = route_next (rn)) {
		if (!rn->info)
			continue;

		v = rn->info;

		vertex_to_prefix_relay (v, prefix_relays);
	}

	return prefix_relays;
}

static void
prefix_relays_dump (struct list * prefix_relays)
{
	int n;
	char ab1[16], ab2[16];
	struct listnode * node;
	struct prefix_relay * pr;

	printf ("\nPREFIX RELAY DUMP\n");

	for (ALL_LIST_ELEMENTS_RO (prefix_relays, node, pr)) {
		inet_ntop (AF_INET, &pr->network, ab1, sizeof (ab1));
		inet_ntop (AF_INET, &pr->netmask, ab2, sizeof (ab2));
		printf ("Destination prefix %s, %s\n", ab1, ab2);

		printf ("    [ ");
		for (n = 0; n < IPLB_MAX_RELAY_POINTS; n++) {
			if (IS_EMPTY_ADDR (pr->relay_point[n]))
				break;
			printf ("%s ", inet_ntoa (pr->relay_point[n]));
		}
		printf ("]\n");
	}
}

static void
prefix_relays_destroy (struct list * prefix_relays)
{
	prefix_relays->del = free;
	list_delete (prefix_relays);
}

/*
 * functions to controll iplb kernel module
 */

static void
netlink_socket_init (void)
{
	/* setup rtnl_handle */
	if (rtnl_open_byproto (&genl_rth, 0, NETLINK_GENERIC) < 0)  {
		D ("can not open genetlink socket");
		exit (1);
	}

	genl_family = genl_resolve_family (&genl_rth, IPLB_GENL_NAME);
	if (genl_family < 0) {
		D ("can not resolve genl name \"%s\"", IPLB_GENL_NAME);
		exit (1);
	}
}

static void
netlink_socket_destroy (void)
{
	rtnl_close (&genl_rth);
	genl_family = -1;
}

static int
mask2len (struct in_addr netmask)
{
	int n;
	__u32 mask = 0x00000000;

	for (n = 0; n <= 32; n++) {
		if (ntohl (netmask.s_addr) == mask)
			return n;

		mask = (mask >> 1) | 0x80000000;
	}

	return 0;
}

static int
prefix_relay_install (struct prefix_relay * pr)
{
	int n, prefix_len;
	char ab1[16], ab2[16];
	struct iplb_relay ir;



	prefix_len = mask2len (pr->netmask);

	inet_ntop (AF_INET, &pr->network, ab1, sizeof (ab1));

	GENL_REQUEST (req, NLREQ_SIZE, genl_family, 0, IPLB_GENL_VERSION,
		      IPLB_CMD_RELAY4_ADD, NLM_F_REQUEST | NLM_F_ACK);

	addattr8 (&req.n, NLREQ_SIZE, IPLB_ATTR_PREFIX_LENGTH, prefix_len);
	addattr32 (&req.n, NLREQ_SIZE, IPLB_ATTR_PREFIX4, pr->network.s_addr);

	/* setup iplb_relay */
	printf ("prefix relay install %s/%d ->", ab1, prefix_len);
	memset (&ir, 0, sizeof (struct iplb_relay));
	for (n = 0; n < IPLB_MAX_RELAY_POINTS &&
		     !IS_EMPTY_ADDR (pr->relay_point[n]); n++) {
		*ir.relay_ip4[n] = pr->relay_point[n].s_addr;
		inet_ntop (AF_INET, ir.relay_ip4[n], ab2, sizeof (ab2));
		printf (" %s", ab2);
	}
	printf ("\n");

	ir.relay_count = n;
	addattr_l (&req.n, NLREQ_SIZE, IPLB_ATTR_RELAY,
		   &ir, sizeof (struct iplb_relay));

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 1;
}

static int
prefix_relay_flush (void)
{
	GENL_REQUEST (req, NLREQ_SIZE, genl_family, 0, IPLB_GENL_VERSION,
		      IPLB_CMD_PREFIX4_FLUSH, NLM_F_REQUEST | NLM_F_ACK);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 1;
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
	struct vertex_graph graph;
	struct pollfd x[1];
	struct list * prefix_relays;
	struct prefix_relay * pr;
	struct listnode * node;

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

		graph = prefix_relay_calculate (lsdb, adv_router);
		graph_dump (&graph);

		prefix_relays = gather_prefix_relays (&graph);
		prefix_relays_dump (prefix_relays);

		/* install iplb entires */
		if (enable_iplb) {
			prefix_relay_flush ();
			for (ALL_LIST_ELEMENTS_RO (prefix_relays, node, pr)) {
				prefix_relay_install (pr);
			}
		}

		vertex_graph_destroy (&graph);
		prefix_relays_destroy (prefix_relays);
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
		"\t -i : enable iplb\n"
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

	while ((ch = getopt (argc, argv, "s:r:i")) != -1) {
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
		case 'i' :
			enable_iplb = 1;
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

	if (enable_iplb) {
		netlink_socket_init ();
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

	netlink_socket_destroy ();

	return 0;
}

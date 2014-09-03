/*
 * ipiplb.c control for IPLB
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/genetlink.h>
#include "../../iplb_netlink.h"


#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"
#include "libgenl.h"



/* netlink socket handler */
static struct rtnl_handle genl_rth;
static int genl_family = -1;

struct iplb_param {

	union {
		struct in_addr	prefix4;
		struct in6_addr	prefix6;
	} prefix;

	union {
		struct in_addr	relay4;
		struct in6_addr	relay6;
	} relay;
	
	__u8		length;
	__u8		weight;

	int	family;
	int	prefix_family;
	int	relay_family;
	int	weight_flag;

	int	lookup_weightbase;
	int	lookup_hashbase;
};

static void usage (void) __attribute ((noreturn));


static int
split_prefixlen (char * str, void * prefix, __u8 * length)
{
	int n, len, family;
	char * p, * pp, * lp, addrbuf[64];
	
	p = pp = addrbuf;
	strncpy (addrbuf, str, sizeof (addrbuf));

	for (n = 0; n < strlen (addrbuf); n++) {
		if (*(p + n) == '/') {
			*(p + n) = '\0';
			lp = p + n + 1;
		}
	}

	len = atoi (lp);

	if (inet_pton (AF_INET, pp, prefix) > 0) {
		family = AF_INET;
		if (len > 32)
			return 0;

	} else if (inet_pton (AF_INET6, pp, prefix) > 0) {
		family = AF_INET6;
		if (len > 128)
			return 0;
	} else {
		return 0;
	}
	
	*length = len;

	return family;
}


static int
parse_args (int argc, char ** argv, struct iplb_param * p)
{
	int rc;

	memset (p, 0, sizeof (struct iplb_param));

	while (argc > 0) {

		if (strcmp (*argv, "prefix") == 0) {
			NEXT_ARG ();
			rc = split_prefixlen (*argv, &p->prefix, &p->length);
			if (!rc) {
				invarg ("invalid prefix", *argv);
				exit (-1);
			}
			p->prefix_family = rc;
		} else if (strcmp (*argv, "relay") == 0) {
			NEXT_ARG ();
			if (inet_pton (AF_INET, *argv, &p->relay) > 0)
				p->relay_family = AF_INET;
			else if (inet_pton (AF_INET6, *argv, &p->relay) > 0)
				p->relay_family = AF_INET6;
			else {
				invarg ("invalid relay", *argv);
				exit (-1);
			}
		} else if (strcmp (*argv, "weight") == 0) {
			NEXT_ARG ();
			if (get_u8 (&p->weight, *argv, 0)) {
				invarg ("invalid weight", * argv);
				exit (-1);
			}
			p->weight_flag = 1;
		} else if (strcmp (*argv, "inet") == 0) {
			p->family = AF_INET;
		} else if (strcmp (*argv, "inet6") == 0) {
			p->family = AF_INET6;
		} else if (strcmp (*argv, "weightbase") == 0) {
			p->lookup_weightbase = 1;
		} else if (strcmp (*argv, "hashbase") == 0) {
			p->lookup_hashbase = 1;
		}

		argc--;
		argv++;
	}

	return 0;
}


static void
usage (void)
{
	fprintf (stderr,
		 "\n"
		 "Usage: ip iplb [ { add | del } ] [ { prefix | relay } ]\n"
		 "             [ prefix PREFIX/LEN ]\n"
		 "             [ relay ADDRESS ]\n"
		 "             [ weight WEIGHT ]\n"
		 "\n"
		 "       ip iplb set weight\n"
		 "             [ prefix PREFIX/LEN ]\n"
		 "             [ relay ADDRESS ]\n"
		 "             [ weight WEIGHT ]\n"
		 "\n"
		 "       ip iplb set lookup [ { weightbase | hashbase } ]\n"
		 "\n"
		 "       ip iplb show [ inet | inet6 ]\n"
		);

		exit (-1);
}



static int
do_add_prefix (int argc, char ** argv)
{
	int cmd;
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (!p.prefix_family) {
		fprintf (stderr, "prefix is not specified\n");
		exit (-1);
	}
	
	cmd = (p.prefix_family == AF_INET) ?
		IPLB_CMD_PREFIX4_ADD : IPLB_CMD_PREFIX6_ADD;

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.prefix_family) {
	case AF_INET :
		addattr_l (&req.n, 1024, IPLB_ATTR_PREFIX4,
			   &p.prefix, sizeof (struct in_addr));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, IPLB_ATTR_PREFIX6,
			   &p.prefix, sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid prefix family %d\n",
			 p.prefix_family);
		return -1;
	}

	addattr8 (&req.n, 1024, IPLB_ATTR_PREFIX_LENGTH, p.length);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}


static int
do_add_relay (int argc, char ** argv)
{
	int cmd;
	__u8 weight;
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (!p.prefix_family) {
		fprintf (stderr, "prefix is not specified\n");
		exit (-1);
	}
	
	if (p.prefix_family != p.relay_family) {
		fprintf (stderr, "protocol family mismatch\n");
		exit (-1);
	}

	weight = p.weight_flag ? p.weight : 100; /* default value of weight */

	cmd = (p.prefix_family == AF_INET) ?
		IPLB_CMD_RELAY4_ADD : IPLB_CMD_RELAY6_ADD;

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_REQUEST | NLM_F_ACK);


	switch (p.prefix_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, IPLB_ATTR_PREFIX4,
			   *((__u32 *)&p.prefix));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, IPLB_ATTR_PREFIX6,
			   &p.prefix, sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid prefix family %d\n",
			 p.prefix_family);
		return -1;
	}

	addattr8 (&req.n, 1024, IPLB_ATTR_PREFIX_LENGTH, p.length);

	switch (p.relay_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, IPLB_ATTR_RELAY4,
			   *((__u32 *)&p.relay));
		break;
	case AF_INET6:
		addattr_l (&req.n, 1024, IPLB_ATTR_RELAY6,
			   &p.relay, sizeof (struct in6_addr));
		break;
	}

	addattr8 (&req.n, 1024, IPLB_ATTR_WEIGHT, weight);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}


static int
do_add (int argc, char ** argv)
{
	if (argc < 1) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}

	if (strcmp (*argv, "prefix") == 0)
		return do_add_prefix (argc - 1, argv + 1);

	if (strcmp (*argv, "relay") == 0)
		return do_add_relay (argc - 1, argv + 1);

	fprintf (stderr, "unknown command \"%s\".\n", *argv);

	return -1;
}

static int
do_del_prefix (int argc, char ** argv)
{
	int cmd;
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (!p.prefix_family) {
		fprintf (stderr, "prefix is not specified\n");
		exit (-1);
	}
	
	cmd = (p.prefix_family == AF_INET) ? 
		IPLB_CMD_PREFIX4_DELETE : IPLB_CMD_PREFIX6_DELETE;

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.prefix_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, IPLB_ATTR_PREFIX4,
			   *((__u32 *)&p.prefix));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, IPLB_ATTR_PREFIX6,
			   &p.prefix, sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid prefix family %d\n",
			 p.prefix_family);
		return -1;
	}

	addattr8 (&req.n, 1024, IPLB_ATTR_PREFIX_LENGTH, p.length);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}


static int
do_del_relay (int argc, char ** argv)
{
	int cmd;
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (!p.prefix_family) {
		fprintf (stderr, "prefix is not specified\n");
		exit (-1);
	}
	
	if (p.prefix_family != p.relay_family) {
		fprintf (stderr, "protocol family mismatch\n");
		exit (-1);
	}

	cmd = (p.prefix_family == AF_INET) ? 
		IPLB_CMD_RELAY4_DELETE : IPLB_CMD_RELAY6_DELETE;

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.prefix_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, IPLB_ATTR_PREFIX4,
			   *((__u32 *)&p.prefix));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, IPLB_ATTR_PREFIX6,
			   &p.prefix, sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid prefix family %d\n",
			 p.prefix_family);
		return -1;
	}

	addattr8 (&req.n, 1024, IPLB_ATTR_PREFIX_LENGTH, p.length);

	switch (p.relay_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, IPLB_ATTR_RELAY4,
			   *((__u32 *)&p.relay));
		break;
	case AF_INET6:
		addattr_l (&req.n, 1024, IPLB_ATTR_RELAY6,
			   &p.relay, sizeof (struct in6_addr));
		break;
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_del (int argc, char ** argv)
{
	if (argc < 1) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}

	if (strcmp (*argv, "prefix") == 0)
		return do_del_prefix (argc - 1, argv + 1);

	if (strcmp (*argv, "relay") == 0)
		return do_del_relay (argc - 1, argv + 1);

	fprintf (stderr, "unknown command \"%s\".\n", *argv);
	return -1;
}

static int
do_set_weight (int argc, char ** argv)
{
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (p.prefix_family != p.relay_family) {
		fprintf (stderr, "prefix and relay family mismatch\n");
		exit (-1);
	}

	if (!p.weight_flag) {
		fprintf (stderr, "weight is not specified\n");
		exit (-1);
	}

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      IPLB_CMD_WEIGHT_SET, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.prefix_family) {
	case AF_INET :
		addattr32 (&req.n, 1024, IPLB_ATTR_PREFIX4,
			   *((__u32 *)&p.prefix));
		addattr32 (&req.n, 1024, IPLB_ATTR_RELAY4,
			   *((__u32 *)&p.relay));
		break;
	case AF_INET6 :
		addattr_l (&req.n, 1024, IPLB_ATTR_PREFIX6,
			   &p.prefix, sizeof (struct in6_addr));
		addattr_l (&req.n, 1024, IPLB_ATTR_RELAY6,
			   &p.relay, sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid prefix family %d\n",
			 p.prefix_family);
		exit (-1);
	}

	addattr8 (&req.n, 1024, IPLB_ATTR_PREFIX_LENGTH, p.length);
	addattr8 (&req.n, 1024, IPLB_ATTR_WEIGHT, p.weight);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_set_lookup (int argc, char ** argv)
{
	int cmd;
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (p.lookup_weightbase) {
		cmd = IPLB_CMD_LOOKUP_WEIGHTBASE;
	} else if (p.lookup_hashbase) {
		cmd = IPLB_CMD_LOOKUP_HASHBASE;
	} else {
		fprintf (stderr, "invalid lookup type\n");
		return -1;
	}

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_REQUEST | NLM_F_ACK);

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_set (int argc, char ** argv)
{
	if (argc < 1) {
		fprintf (stderr, "invalid argument.\n");
		return -1;
	}

	if (strcmp (*argv, "weight") == 0)
		return do_set_weight (argc - 1, argv + 1);

	if (strcmp (*argv, "lookup") == 0)
		return do_set_lookup (argc - 1, argv + 1);

	fprintf (stderr, "unknown command \"%s\".\n", *argv);
	return -1;
}

static int
prefix_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len, family = 0, prefix_family = 0, relay_family = 0;
	__u8 weight, length;
	char addr[16], addrbuf1[64], addrbuf2[64];
	struct genlmsghdr * ghdr;
	struct rtattr *attrs[IPLB_ATTR_MAX + 1];

	memset (addr, 0, sizeof (addr));
	memset (addrbuf1, 0, sizeof (addrbuf1));
	memset (addrbuf2, 0, sizeof (addrbuf2));

	if (n->nlmsg_type == NLMSG_ERROR) {
		fprintf (stderr, "%s: nlmsg_error\n", __func__);
		return -EBADMSG;
	}

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0) {
		fprintf (stderr, "%s: nlmsg length error\n", __func__);
		return -1;
	}

	parse_rtattr (attrs, IPLB_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);

	if (attrs[IPLB_ATTR_PREFIX4]) {
		family = AF_INET;
		prefix_family = IPLB_ATTR_PREFIX4;
	} else if (attrs[IPLB_ATTR_PREFIX6]) {
		family = AF_INET6;
		prefix_family = IPLB_ATTR_PREFIX6;
	} else {
		fprintf (stderr, "%s: empty prefix\n", __func__);
		return -1;
	}

	if (attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		length = rta_getattr_u8 (attrs[IPLB_ATTR_PREFIX_LENGTH]);
	} else {
		fprintf (stderr, "%s: prefix length does not exist\n", 
			 __func__);
		return -1;
	}


	inet_ntop (family, RTA_DATA(attrs[prefix_family]),
		   addrbuf1, sizeof (addrbuf1));

	
	if (attrs[IPLB_ATTR_RELAY4]) {
		family = AF_INET;
		relay_family = IPLB_ATTR_RELAY4;
	} else if (attrs[IPLB_ATTR_RELAY6]) {
		family = AF_INET6;
		relay_family = IPLB_ATTR_RELAY6;
	}

	if (relay_family) {
		if (attrs[IPLB_ATTR_WEIGHT]) {
			weight = rta_getattr_u8 (attrs[IPLB_ATTR_WEIGHT]);
		} else {
			fprintf (stderr, "%s: weight does not exist\n", 
				 __func__);
			return -1;
		}
	}


	if (relay_family) {
		inet_ntop (family, RTA_DATA (attrs[relay_family]),
			   addrbuf2, sizeof (addrbuf2));

		fprintf (stdout, "prefix %s/%d relay %s weight %d\n",
			 addrbuf1, length, addrbuf2, weight);
	} else {
		fprintf (stdout, "prefix %s/%d relay none\n",
			 addrbuf1, length);
	}

	return 0;
}

static int
do_show (int argc, char ** argv)
{
	int cmd, ret;
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (p.family == 0) {
		p.family = AF_INET;
	}

	switch (p.family) {
	case AF_INET :
		cmd = IPLB_CMD_PREFIX4_GET;
		break;
	case AF_INET6 :
		cmd = IPLB_CMD_PREFIX6_GET;
		break;
	default :
		fprintf (stderr, "invalid family\n");
		return -1;
	}

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if ((ret = rtnl_send (&genl_rth, &req, req.n.nlmsg_len)) < 0) {
		fprintf (stderr, "%s:%d: error\n", __func__, __LINE__);
		return -2;
	}

	if (rtnl_dump_filter (&genl_rth, prefix_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (1);
	}

	return 0;
}

int
do_ipiplb (int argc, char ** argv)
{
	if (genl_family < 0) {
		if (rtnl_open_byproto (&genl_rth, 0, NETLINK_GENERIC) < 0) {
			fprintf (stderr, "Can't open genetlink socket\n");
			exit (1);
		}
		genl_family = genl_resolve_family (&genl_rth, IPLB_GENL_NAME);

		if (genl_family < 0) 
			exit (1);
	}

	if (argc < 1)
		usage ();

	if (matches (*argv, "add") == 0)
		return do_add (argc - 1, argv + 1);
	
	if (matches (*argv, "del") == 0)
		return do_del (argc - 1, argv + 1);

	if (matches (*argv, "set") == 0)
		return do_set (argc - 1, argv + 1);

	if (matches (*argv, "delete") == 0)
		return do_del (argc - 1, argv + 1);

	if (matches (*argv, "show") == 0)
		return do_show (argc - 1, argv + 1);

	if (matches (*argv, "help") == 0)
		usage ();

        fprintf (stderr,
                 "Command \"%s\" is unknown, try \"ip ov help\".\n", *argv);

	return -1;
}

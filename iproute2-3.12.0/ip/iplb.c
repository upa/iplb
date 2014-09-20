/*
 * iplb.c control for IPLB
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


/* XXX: this value comes from FLOW_AGE_INTERVAL on iplb_main.c */
#define COUNTER_PUSHBACK_INTERVAL	10



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
	
	union {
		struct in_addr	src4;
		struct in6_addr	src6;
	} src;

	union {
		struct in_addr	src4;
		struct in6_addr	src6;
	} dst;

	__u8	length;
	__u8	weight;
	__u8	encap_type;

	int	prefix_family;
	int	relay_family;
	int	weight_flag;
	int	encap_type_flag;
	int	src_family;
	int	detail_flag;

	int	lookup_weightbase;
	int	lookup_hashbase;
	int	lookup_flowbase;

	/* set flow related */
	int	sport;
	int	dport;
	int	protocol;
	int	index;
};

static struct iplb_param show_p;

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
				invarg ("invalid weight", *argv);
				exit (-1);
			}
			p->weight_flag = 1;
		} else if (strcmp (*argv, "type") == 0) {
			NEXT_ARG ();
			if (strcmp (*argv, "gre") == 0) {
				p->encap_type = IPLB_ENCAP_TYPE_GRE;
			} else if (strcmp (*argv, "ipip") == 0) {
				p->encap_type = IPLB_ENCAP_TYPE_IPIP;
			} else if (strcmp (*argv, "lsrr") == 0) {
				p->encap_type = IPLB_ENCAP_TYPE_LSRR;
			} else {
				invarg ("invalid type \"%s\"", *argv);
				exit (-1);
			}
			p->encap_type_flag = 1;
		} else if (strcmp (*argv, "src") == 0) {
			NEXT_ARG ();
			if (inet_pton (AF_INET, *argv, &p->src) > 0)
				p->src_family = AF_INET;
			else if (inet_pton (AF_INET6, *argv, &p->src) > 0)
				p->src_family = AF_INET6;
			else {
				invarg ("invalid src", *argv);
				exit (-1);
			}
		} else if (strcmp (*argv, "dst") == 0) {
			NEXT_ARG ();
			if (inet_pton (AF_INET, *argv, &p->dst) > 0)
				p->src_family = AF_INET;
			else if (inet_pton (AF_INET6, *argv, &p->dst) > 0)
				p->src_family = AF_INET6;
			else {
				invarg ("invalid dst", *argv);
				exit (-1);
			}
		} else if (strcmp (*argv, "weightbase") == 0) {
			p->lookup_weightbase = 1;
		} else if (strcmp (*argv, "hashbase") == 0) {
			p->lookup_hashbase = 1;
		} else if (strcmp (*argv, "flowbase") == 0) {
			p->lookup_flowbase = 1;
		} else if (strcmp (*argv, "proto") == 0 ||
			   strcmp (*argv, "protocol") == 0) {
			NEXT_ARG ();
			if (strcmp (*argv, "tcp") == 0) {
				p->protocol = IPPROTO_TCP;
			} else if (strcmp (*argv, "udp") == 0) {
				p->protocol = IPPROTO_UDP;
			} else if (strcmp (*argv, "icmp") == 0) {
				p->protocol = IPPROTO_ICMP;
			} else {
				p->protocol = atoi (*argv);
				if (p->protocol < 0) {
					invarg ("invalid protocol", *argv);
					exit (-1);
				}
			}
		} else if (strcmp (*argv, "sport") == 0) {
			NEXT_ARG ();
			p->sport = atoi (*argv);
			if (p->sport < 0 || p->sport > 65535) {
				invarg ("invalid source port number", *argv);
				exit (-1);
			}
		} else if (strcmp (*argv, "dport") == 0) {
			NEXT_ARG ();
			p->dport = atoi (*argv);
			if (p->dport < 0 || p->dport > 65535) {
				invarg ("invalid destination port number",
					*argv);
				exit (-1);
			}
		} else if (strcmp (*argv, "index") == 0 ||
			   strcmp (*argv, "idx") == 0) {
			NEXT_ARG ();
			p->index = atoi (*argv);
			if (p->index < 0) {
				invarg ("invalid relay index",
					*argv);
				exit (-1);
			}
		} else if (strcmp (*argv, "detail") == 0) {
			p->detail_flag = 1;
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
		 "Usage: ip lb [ { add | del } ]\n"
		 "             [ prefix PREFIX/LEN ]\n"
		 "             [ relay ADDRESS ]\n"
		 "             [ weight WEIGHT ]\n"
		 "             [ type { gre | ipip | lsrr } ]\n"
		 "\n"
		 "       ip lb set weight\n"
		 "             [ prefix PREFIX/LEN ]\n"
		 "             [ relay ADDRESS ]\n"
		 "             [ weight WEIGHT ]\n"
		 "\n"
		 "       ip lb set lookup\n"
		 "             [ { weightbase | hashbase | flowbase } ]\n"
		 "\n"
		 "       ip lb set tunnel src [ ADDRESS ]\n"
		 "\n"
		 "       ip lb set flow\n"
		 "             [ proto PROTONUM]\n"
		 "             [ src ADDRESS ]\n"
		 "             [ dst ADDRESS ]\n"
		 "             [ sport PORTNUM ]\n"
		 "             [ dport PORTNUM ]\n"
		 "             [ index INDEX ]\n"
		 "\n"
		 "       ip lb show { detail | flow [ detail ] }\n"
		 "\n"
		);

		exit (-1);
}



static int
do_add_prefix (struct iplb_param p)
{
	int cmd;

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
do_add_relay (struct iplb_param p)
{
	int cmd;
	__u8 weight;

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

	if (p.encap_type_flag) {
		addattr8 (&req.n, 1024, IPLB_ATTR_ENCAP_TYPE, p.encap_type);
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}


static int
do_add (int argc, char ** argv)
{
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (p.prefix_family && ! p.relay_family)
		return do_add_prefix (p);
	else if (p.prefix_family && p.relay_family)
		return do_add_relay (p);
	else
		fprintf (stdout, "invalid arguments\n");

	return -1;
}

static int
do_del_prefix (struct iplb_param p)
{
	int cmd;

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
do_del_relay (struct iplb_param p)
{
	int cmd;

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
	struct iplb_param p;

	parse_args (argc, argv, &p);

	if (p.prefix_family && ! p.relay_family)
		return do_del_prefix (p);
	else if (p.prefix_family && p.relay_family)
		return do_del_relay (p);
	else
		fprintf (stderr, "invalid arguments\n");

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
	} else if (p.lookup_flowbase) {
		cmd = IPLB_CMD_LOOKUP_FLOWBASE;
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
do_set_tunnel (int argc, char ** argv)
{
	struct iplb_param p;

	parse_args (argc, argv, &p);

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      0, NLM_F_REQUEST | NLM_F_ACK);

	switch (p.src_family) {
	case AF_INET :
		req.g.cmd = IPLB_CMD_SRC4_SET;
		addattr_l (&req.n, 1024, IPLB_ATTR_SRC4, &p.src,
			   sizeof (struct in_addr));
		break;
	case AF_INET6 :
		req.g.cmd = IPLB_CMD_SRC6_SET;
		addattr_l (&req.n, 1024, IPLB_ATTR_SRC6, &p.src,
			   sizeof (struct in6_addr));
		break;
	default :
		fprintf (stderr, "invalid tunnel src type\n");;
		return -1;
	}

	if (rtnl_talk (&genl_rth, &req.n, 0, 0, NULL) < 0)
		return -2;

	return 0;
}

static int
do_set_flow (int argc, char ** argv)
{
	int cmd;
	struct iplb_param p;
	struct iplb_flow4_info info;

	memset (&info, 0, sizeof (struct iplb_flow4_info));

	parse_args (argc, argv, &p);

	switch (preferred_family) {
	case AF_UNSPEC :
	case AF_INET :
		cmd = IPLB_CMD_FLOW4_SET;
		break;
	case AF_INET6 :
		/* flow6_set will be implemented here */
	default :
		fprintf (stderr, "%s: invalid family \"%d\"\n",
			 __func__, preferred_family);
		return -1;
	}

	GENL_REQUEST (req, 128, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_REQUEST | NLM_F_ACK);

	info.family	= AF_INET;
	info.protocol	= p.protocol;
	info.sport	= htons (p.sport);
	info.dport	= htons (p.dport);
	info.relay_index = p.index;
	memcpy (&info.saddr, &p.src, sizeof (struct in_addr));
	memcpy (&info.daddr, &p.dst, sizeof (struct in_addr));

	addattr_l (&req.n, 128, IPLB_ATTR_FLOW4,
		   &info, sizeof (struct iplb_flow4_info));

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

	if (strcmp (*argv, "tunnel") == 0)
		return do_set_tunnel (argc - 1, argv + 1);

	if (strcmp (*argv, "flow") == 0)
		return do_set_flow (argc - 1, argv + 1);

	fprintf (stderr, "unknown command \"%s\".\n", *argv);
	return -1;
}

static int
prefix_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len, ai_family = 0, prefix_family = 0, relay_family = 0;
	__u8 weight, length, encap_type = 0, index;
	char addr[16], addrbuf1[64], addrbuf2[64];
	struct genlmsghdr * ghdr;
	struct rtattr * attrs[IPLB_ATTR_MAX + 1];
	struct iplb_stats stats;

	char * encap_type_name[] = {
		"gre", "ipip", "lsrr"
	};

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
		ai_family = AF_INET;
		prefix_family = IPLB_ATTR_PREFIX4;
	} else if (attrs[IPLB_ATTR_PREFIX6]) {
		ai_family = AF_INET6;
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

	inet_ntop (ai_family, RTA_DATA(attrs[prefix_family]),
		   addrbuf1, sizeof (addrbuf1));
	

	if (attrs[IPLB_ATTR_RELAY4]) {
		ai_family = AF_INET;
		relay_family = IPLB_ATTR_RELAY4;
	} else if (attrs[IPLB_ATTR_RELAY6]) {
		ai_family = AF_INET6;
		relay_family = IPLB_ATTR_RELAY6;
	}

	if (relay_family) {
		inet_ntop (ai_family, RTA_DATA (attrs[relay_family]),
			   addrbuf2, sizeof (addrbuf2));

		if (attrs[IPLB_ATTR_WEIGHT]) {
			weight = rta_getattr_u8 (attrs[IPLB_ATTR_WEIGHT]);
		} else {
			fprintf (stderr, "%s: weight does not exist\n", 
				 __func__);
			return -1;
		}
	}


	if (attrs[IPLB_ATTR_ENCAP_TYPE]) {
		encap_type = rta_getattr_u8 (attrs[IPLB_ATTR_ENCAP_TYPE]);
	} else {
		fprintf (stderr, "%s: encap type does not exist\n",
			 __func__);
		return -1;
	}


	if (attrs[IPLB_ATTR_STATS]) {
		memcpy (&stats, RTA_DATA (attrs[IPLB_ATTR_STATS]),
			sizeof (stats));
	} else {
		fprintf (stderr, "%s: stats does not exist\n",
			 __func__);
		return -1;
	}


	if (attrs[IPLB_ATTR_RELAY_INDEX]) {
		index = rta_getattr_u8 (attrs[IPLB_ATTR_RELAY_INDEX]);
	} else {
		fprintf (stderr, "%s: relay index does not exist\n",
			 __func__);
		return -1;
	}

	if (!show_p.detail_flag) {
		if (relay_family) {
			fprintf (stdout,
				 "prefix %s/%d relay %s weight %d type %s\n",
				 addrbuf1, length, addrbuf2, weight,
				 encap_type_name[encap_type]);
		} else if (!relay_family){
			fprintf (stdout, "prefix %s/%d relay none\n",
				 addrbuf1, length);
		}
	} else {
		if (relay_family) {
			fprintf (stdout,
				 "prefix %s/%d relay %s weight %d type %s "
				 "txpkt %u txbyte %u index %u\n",
				 addrbuf1, length, addrbuf2, weight,
				 encap_type_name[encap_type],
				 stats.pkt_count, stats.byte_count,
				 index);
		}
	}


	return 0;
}

static int
tunnel_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len;
	char addrbuf[16];
	struct genlmsghdr * ghdr;
	struct rtattr * attrs[IPLB_ATTR_MAX + 1];

	if (n->nlmsg_type == NLMSG_ERROR)
		return -EBADMSG;

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0)
		return -1;

	parse_rtattr (attrs, IPLB_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);

	if (attrs[IPLB_ATTR_SRC4]) {
		inet_ntop (AF_INET, RTA_DATA (attrs[IPLB_ATTR_SRC4]),
			   addrbuf, sizeof (addrbuf));
		printf ("%s\n", addrbuf);
	}

	if (attrs[IPLB_ATTR_SRC6]) {
		inet_ntop (AF_INET6, RTA_DATA (attrs[IPLB_ATTR_SRC6]),
			   addrbuf, sizeof (addrbuf));
		printf ("%s\n", addrbuf);
	}

	return 0;
}

static int
do_show_tunnel (void)
{
	int ret, cmd;

	switch (preferred_family) {
	case AF_UNSPEC :
	case AF_INET :
		cmd = IPLB_CMD_SRC4_GET;
		break;
	case AF_INET6 :
		cmd = IPLB_CMD_SRC6_GET;
		break;
	default :
		fprintf (stderr, "%s: invalid family \"%d\"\n",
			 __func__, cmd);
		return -1;
	}

	GENL_REQUEST (req, 128, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_REQUEST | NLM_F_ACK);

	if ((ret = rtnl_send (&genl_rth, &req.n, req.n.nlmsg_len)) < 0) {
		fprintf (stderr, "%s: rtnl_send failed \"%d\"\n",
			 __func__, ret);
		return ret;
	}

	if (rtnl_dump_filter (&genl_rth, tunnel_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (1);
	}

	return 0;
}

static int
flow4_nlmsg (const struct sockaddr_nl * who, struct nlmsghdr * n, void * arg)
{
	int len;
	char proto[16], srcaddr[16], dstaddr[16];
	struct iplb_flow4_info * info;
	struct genlmsghdr * ghdr;
	struct rtattr * attrs[IPLB_ATTR_MAX + 1];

	memset (srcaddr, 0, sizeof (srcaddr));
	memset (dstaddr, 0, sizeof (dstaddr));

	if (n->nlmsg_type == NLMSG_ERROR) {
		fprintf (stderr, "%s: nlmsg_error\n", __func__);
		return -EBADMSG;
	}

	ghdr = NLMSG_DATA (n);
	len = n->nlmsg_len - NLMSG_LENGTH (sizeof (*ghdr));
	if (len < 0) {
		fprintf (stderr, "%s: nlmsg length error\n", __func__);
		return -EBADMSG;
	}

	parse_rtattr (attrs, IPLB_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);

	if (attrs[IPLB_ATTR_FLOW4]) {
		info = RTA_DATA (attrs[IPLB_ATTR_FLOW4]);
	} else {
		fprintf (stderr, "%s: flow4 does not exist\n", __func__);
		return -1;
	}

	switch (info->protocol) {
	case IPPROTO_TCP :
		snprintf (proto, sizeof (proto), "%s", "tcp");
		break;
	case IPPROTO_UDP :
		snprintf (proto, sizeof (proto), "%s", "udp");
		break;
	case IPPROTO_ICMP :
		snprintf (proto, sizeof (proto), "%s", "icmp");
		break;
	default :
		snprintf (proto, sizeof (proto), "%d", info->protocol);
	}

	inet_ntop (AF_INET, &info->saddr, srcaddr, sizeof (srcaddr));
	inet_ntop (AF_INET, &info->daddr, dstaddr, sizeof (dstaddr));

	if (!show_p.detail_flag) {
		printf ("%s %s:%u->%s:%u index %u\n", proto,
			srcaddr, ntohs (info->sport),
			dstaddr, ntohs (info->dport),
			info->relay_index);
	} else {
		float pps, bps;

		pps = (float)(info->stats[1].pkt_count -
			      info->stats[2].pkt_count) / 10;

		bps = (float)(info->stats[1].byte_count -
			      info->stats[2].byte_count) / 10 * 8;

		printf ("%s %s:%u->%s:%u index %u "
			"txpkt %u txbyte %u "
			"txpps %f txbps %f\n",
			proto,
			srcaddr, ntohs (info->sport),
			dstaddr, ntohs (info->dport),
			info->relay_index,
			info->stats[0].pkt_count,
			info->stats[0].byte_count,
			pps, bps);

	}

	return 0;
}

static int
do_show_flow (void)
{
	int ret, cmd;

	switch (preferred_family) {
	case AF_UNSPEC :
	case AF_INET :
		cmd = IPLB_CMD_FLOW4_GET;
		break;
	case AF_INET6 :
		/* flow6_get will be implemented here */
	default :
		fprintf (stderr, "%s: invalid family \"%d\"\n",
			 __func__, cmd);
		return -1;
	}

	GENL_REQUEST (req, 1024, genl_family, 0, IPLB_GENL_VERSION,
		      cmd, NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	if ((ret = rtnl_send (&genl_rth, &req.n, req.n.nlmsg_len)) < 0) {
		fprintf (stderr, "%s: rtnl_send failed \"%d\"\n",
			 __func__, ret);
		return ret;
	}

	if (rtnl_dump_filter (&genl_rth, flow4_nlmsg, NULL) < 0) {
		fprintf (stderr, "Dump terminated\n");
		exit (1);
	}

	return 0;
}

static int
do_show (int argc, char ** argv)
{
	int cmd, ret;

	if (*argv && strcmp (*argv, "tunnel") == 0) {
		return do_show_tunnel ();
	}

	if (*argv && strcmp (*argv, "flow") == 0) {
		parse_args (--argc, ++argv, &show_p);
		return do_show_flow ();
	}

	parse_args (argc, argv, &show_p);

	switch (preferred_family) {
	case AF_UNSPEC :
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
do_iplb (int argc, char ** argv)
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

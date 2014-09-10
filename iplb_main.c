
/*
 * IP-in-IP based Load Balancing
 */

/*
 * TODO:
 * support IPv4 in IPv6 and IPv6 in IPv4.
 * It requires isolation of prefix and relay address.
 */


#ifndef DEBUG
#define DEBUG
#endif

#define WITH_GRE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/rwlock.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <uapi/linux/netfilter_ipv6.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/genetlink.h>


#include "patricia/patricia.h"

#include "iplb_netlink.h"

#define IPLB_VERSION "0.0.1"

MODULE_VERSION (IPLB_VERSION);
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("upa@haeena.net");


#ifdef WITH_GRE
#define IPV4_IPIP_HEADROOM	(8 + 20 + 16)
#define IPV6_IPIP_HEADROOM	(8 + 40 + 16)
#else
#define IPV4_IPIP_HEADROOM	(20 + 16)
#define IPV6_IPIP_HEADROOM	(40 + 16)
#endif



#define ADDR4COPY(s, d) *(((u32 *)(d))) = *(((u32 *)(s)))
#define ADDR6COPY(s, d) do {					\
		*(((u32 *)(d)) + 0) = *(((u32 *)(s)) + 0);	\
		*(((u32 *)(d)) + 1) = *(((u32 *)(s)) + 1);	\
		*(((u32 *)(d)) + 2) = *(((u32 *)(s)) + 2);	\
		*(((u32 *)(d)) + 3) = *(((u32 *)(s)) + 3);	\
	} while (0)

#define ADDRCMP(af, s, d)					\
	(af == AF_INET) ? (*(((u32 *)(d))) == *(((u32 *)(s)))) : \
	(*(((u32 *)(d)) + 0) == *(((u32 *)(s)) + 0) &&		 \
	 *(((u32 *)(d)) + 1) == *(((u32 *)(s)) + 1) &&		 \
	 *(((u32 *)(d)) + 2) == *(((u32 *)(s)) + 2) &&		 \
	 *(((u32 *)(d)) + 3) == *(((u32 *)(s)) + 3))		 \


#define IPTRANSPORTHDR(ip) (((char *)(ip)) + ((ip)->ihl << 2))


static unsigned int iplb_net_id;
static u32 iplb_salt __read_mostly;


/* routing table */
struct iplb_rtable {
	rwlock_t		lock;
	struct list_head	rlist;
	patricia_tree_t		* rtable;
};

#define INIT_IPLB_RTABLE(rt, maxbits)			\
	do {						\
		(rt)->rtable = New_Patricia (maxbits);	\
		INIT_LIST_HEAD (&(rt)->rlist);		\
		rwlock_init (&(rt)->lock);	\
	} while (0)


#define DESTROY_IPLB_RTABLE(rt)						\
	do {								\
		write_lock_bh (&(rt)->lock);				\
		Destroy_Patricia ((rt)->rtable,				\
				  patricia_destroy_detour_tuple);	\
		(rt)->rtable = NULL;					\
		write_unlock_bh (&(rt)->lock);				\
	} while (0)



/* detour address for one next hop */
struct detour_addr {
	struct list_head	list;
	struct rcu_head		rcu;

	struct detour_tuple 	* tuple;	/* parent */

	u8			family;
	u8			weight;
	u8			encap_type;

	union {
		__be32		__detour_addr4[1];
		__be32		__detour_addr6[4];
	} detour_ip;
#define detour_ip4	detour_ip.__detour_addr4
#define detour_ip6	detour_ip.__detour_addr6
};

struct detour_tuple {
	struct list_head	list;		/* private */

	prefix_t		* prefix;	/* prefix of route table */

	u32			weight_sum;	
	int			detour_count;

	struct list_head	detour_list;	/* list of detour_addr */
};

/* per network namespace structure */
struct iplb_net {

	/* tunnel source address (not used for routing) */
	__be32			tunnel_src;	/* default 10.0.0.1	*/
	struct in6_addr		tunnel_src6;	/* default 2001:db8::1	*/

	/* lookup function for detour_addr from tuple. */
	struct detour_addr * (* lookup_fn) (struct detour_tuple * , u32);

	/* routing tables for IPv4 and IPv6 */
	struct iplb_rtable	rtable4;
	struct iplb_rtable	rtable6;
};



/********************************
 ****   Source route table for prefixes
 ********************************/

/* from netmap pkt-gen.c */

static uint16_t
checksum(const void * data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
        uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
        /*
         * If there's a single byte left over, checksum it, too.
         * Network byte order is big-endian, so the remaining byte is
         * the high byte.
         */

        if (i < len) {
                sum += addr[i] << 8;
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

        return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
        sum = ~sum & 0xFFFF;
        return (htons(sum));
}


static inline void
dst2prefix (u8 af, void * addr, u16 len, prefix_t * prefix)
{
	prefix->family = af;
	prefix->bitlen = len;
	prefix->ref_count = 1;

	switch (af) {
	case (AF_INET) : 
		ADDR4COPY (addr, &prefix->add);
		break;
	case (AF_INET6) :
		ADDR6COPY (addr, &prefix->add);
		break;
	default :
		printk (KERN_ERR "%s: invalid family %u\n", __func__, af);
	};

	return;
}

static struct detour_tuple *
find_detour_tuple (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
{
	prefix_t prefix;
	patricia_node_t * pn;

	dst2prefix (af, dst, len, &prefix);

	read_lock_bh (&rt->lock);
	pn = patricia_search_best (rt->rtable, &prefix);
	read_unlock_bh (&rt->lock);

	if (pn)
		return pn->data;

	return NULL;
}

static struct detour_tuple *
find_detour_tuple_exact (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
{
	prefix_t prefix;
	patricia_node_t * pn;

	dst2prefix (af, dst, len, &prefix);

	read_lock_bh (&rt->lock);
	pn = patricia_search_exact (rt->rtable, &prefix);
	read_unlock_bh (&rt->lock);

	if (pn)
		return pn->data;

	return NULL;
}

static struct detour_tuple *
add_detour_tuple (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
{
	prefix_t		* prefix;
	patricia_node_t		* pn;
	struct detour_tuple	* tuple;

	prefix = kmalloc (sizeof (prefix_t), GFP_KERNEL);
	memset (prefix, 0, sizeof (prefix_t));

	dst2prefix (af, dst, len, prefix);

	write_lock_bh (&rt->lock);
	pn = patricia_lookup (rt->rtable, prefix);


	if (pn->data != NULL) {
		write_unlock_bh (&rt->lock);
		return pn->data;
	}

	tuple = (struct detour_tuple *) kmalloc (sizeof (struct detour_tuple),
						 GFP_KERNEL);
	memset (tuple, 0, sizeof (struct detour_tuple));

	tuple->prefix		= prefix;
	tuple->weight_sum	= 0;
	tuple->detour_count	= 0;
	INIT_LIST_HEAD (&tuple->detour_list);

	pn->data = tuple;

	list_add_rcu (&tuple->list, &rt->rlist);

	write_unlock_bh (&rt->lock);

	return tuple;
}


static void
destroy_detour_tuple (struct detour_tuple * tuple)
{
	struct list_head	* p, * tmp;
	struct detour_addr	* detour;

	if (tuple == NULL)
		return;

	list_for_each_safe (p, tmp, &tuple->detour_list) {
		detour = list_entry (p, struct detour_addr, list);
		list_del_rcu (p);
		kfree_rcu (detour, rcu);
	}

	kfree (tuple);

	return;
}


static int
delete_detour_tuple (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
{
	prefix_t		prefix;
	patricia_node_t		* pn;
	struct detour_tuple	* tuple;


	dst2prefix (af, dst, len, &prefix);

	write_lock_bh (&rt->lock);
	pn = patricia_search_exact (rt->rtable, &prefix);

	if (!pn) {
		write_unlock_bh (&rt->lock);
		return 0;
	}

	tuple = (struct detour_tuple *) pn->data;
	
	list_del_rcu (&tuple->list);

	pn->data = NULL;
	destroy_detour_tuple (tuple);
	patricia_remove (rt->rtable, pn);

	write_unlock_bh (&rt->lock);

	return 1;
}



static void
add_detour_addr_to_tuple (struct detour_tuple * tuple, 
			  u8 af, void * addr, u8 weight, u8 encap_type)
{
	struct detour_addr * detour;

	detour = (struct detour_addr *) kmalloc (sizeof (struct detour_addr),
						 GFP_KERNEL);
	memset (detour, 0, sizeof (struct detour_addr));


	detour->tuple	= tuple;
	detour->family	= af;
	detour->weight	= weight;
	detour->encap_type = encap_type;

	switch (af) {
	case (AF_INET) :
		ADDR4COPY (addr, &detour->detour_ip4);
		break;
	case (AF_INET6) :
		ADDR6COPY (addr, &detour->detour_ip6);
		break;
	default :
		printk (KERN_ERR "%s:%d: invalid family %u\n", 
			__FUNCTION__, __LINE__, af);
		kfree (detour);
		return;
	}
	
	list_add_rcu (&detour->list, &tuple->detour_list);

	tuple->weight_sum += weight;
	tuple->detour_count++;

	return;
}

static void
delete_detour_addr_from_tuple (struct detour_tuple * tuple, u8 af, void * addr)
{
	struct list_head	* p, * tmp;
	struct detour_addr	* detour;

	list_for_each_safe (p, tmp, &(tuple->detour_list)) {
		detour = list_entry (p, struct detour_addr, list);
		if (ADDRCMP (af, &detour->detour_ip, addr)) {
			tuple->weight_sum -= detour->weight;
			list_del_rcu (p);
			tuple->detour_count--;
			kfree_rcu (detour, rcu);
			return;
		}
	}

	return;
}

static struct detour_addr *
lookup_detour_addr_from_tuple_weightbase (struct detour_tuple *tuple, u32 hash)
{
	u32 w;
	struct detour_addr * detour;
	
	detour = NULL;
	w = hash % tuple->weight_sum;

	list_for_each_entry_rcu (detour, &tuple->detour_list, list) {
		if (detour->weight >= w) {
			break;
		}
		w -= detour->weight;
	}

	return detour;
}

static struct detour_addr *
lookup_detour_addr_from_tuple_hashbase (struct detour_tuple * tuple, u32 hash)
{
	u32 h;
	struct detour_addr * detour;

	/* hashbase means all locator weights are 100. */

	if (tuple->detour_count == 0)
		return NULL;

	detour = NULL;
	h = hash % (tuple->detour_count * 100);

	list_for_each_entry_rcu (detour, &tuple->detour_list, list) {
		if (100 >= h)
			break;
		h -= 100;
	}

	return detour;
}


static struct detour_addr *
find_detour_addr_from_tuple (struct detour_tuple * tuple, u8 af, void * addr)
{
	struct detour_addr * detour;

	detour = NULL;

	list_for_each_entry_rcu (detour, &tuple->detour_list, list) {
		if (ADDRCMP (af, &detour->detour_ip, addr)) 
			return detour;
	}

	return NULL;
}


static void
patricia_destroy_detour_tuple (void * data)
{
	destroy_detour_tuple ((struct detour_tuple *) data);

	return;
}



/********************************
 ****   nf hook ops
 ********************************/

static inline void
move_header (void * srcp, void * dstp, size_t len)
{
	int n;
	__u32 * src = srcp;
	__u32 * dst = dstp;
	size_t rest = len % 4;
	len = (len - rest) / 4;

	/* move header from src to dst */

	for (n = 0; n < len; n++) {
		*(dst + n) = *(src + n);
	}

	if (rest) {
		char * s, * d;
		s = (char *) (src + n);
		d = (char *) (dst + n);
		for (n = 0; n < rest % 4; n++) {
			*(d + n) = *(s + n);
		}
	}
	return;
}
#define move_front_ipv4_header(sip, dip) \
	move_header ((sip), (dip), (sip)->ihl * 4)

#define move_front_ipv6_header(sip, dip) \
	move_header ((sip), (dip), sizeof (struct ipv6hdr));


static inline void
ipv4_set_gre_encap (struct sk_buff * skb, struct detour_addr * detour,
		    struct iplb_net * iplb_net)
{
	struct iphdr	* iph, * ipiph;
	struct grehdr {
		__be16	flags;
		__be16	protocol;
	};
	struct grehdr * greh;

	iph = (struct iphdr *) skb_network_header (skb);

	if (skb_cow_head (skb, IPV4_IPIP_HEADROOM)) {
		printk (KERN_INFO "%s:%d: skb_cow_head failed\n",
			__func__, __LINE__);
		return;
	}

	ipiph = (struct iphdr *) __skb_push (skb, sizeof (struct iphdr) + 
					     sizeof (struct grehdr));
	skb_reset_network_header (skb);

	ipiph->version	= IPVERSION;
	ipiph->ihl	= sizeof (struct iphdr) >> 2;
	ipiph->tos	= 0;
	ipiph->frag_off	= 0;
	ipiph->ttl	= 16;


	ipiph->tot_len	= htons (ntohs (iph->tot_len) + sizeof (struct grehdr)
		+ sizeof (struct iphdr));
	ipiph->protocol = IPPROTO_GRE;
	ipiph->check	= 0;
	ipiph->saddr	= iplb_net->tunnel_src;
	ipiph->daddr	= *detour->detour_ip4;
	ipiph->check	= wrapsum (checksum (ipiph, sizeof (struct iphdr), 0));

	greh = (struct grehdr *) (ipiph + 1);
	greh->flags	= 0;
	greh->protocol	= htons (ETH_P_IP);

	return;
}

static inline void
ipv4_set_ipip_encap (struct sk_buff * skb, struct detour_addr * detour,
		     struct iplb_net * iplb_net)
{
	struct iphdr	* iph, * ipiph;

	iph = (struct iphdr *) skb_network_header (skb);

	if (skb_cow_head (skb, IPV4_IPIP_HEADROOM)) {
		printk (KERN_INFO "%s:%d: skb_cow_head failed\n",
			__func__, __LINE__);
		return;
	}

	ipiph = (struct iphdr *) __skb_push (skb, sizeof (struct iphdr));
	skb_reset_network_header (skb);

	ipiph->version	= IPVERSION;
	ipiph->ihl	= sizeof (struct iphdr) >> 2;
	ipiph->tos	= 0;
	ipiph->frag_off	= 0;
	ipiph->ttl	= 16;
	ipiph->tot_len	= htons (ntohs (iph->tot_len) + sizeof (struct iphdr));
	ipiph->protocol = IPPROTO_IPIP;
	ipiph->check	= 0;
	ipiph->saddr	= iplb_net->tunnel_src;
	ipiph->daddr	= *detour->detour_ip4;
	ipiph->check	= wrapsum (checksum (ipiph, sizeof (struct iphdr), 0));

	return;
}

static inline void
ipv4_set_lsrr_encap (struct sk_buff * skb, struct detour_addr * detour,
		     struct iplb_net * iplb_net)
{
	__be32 old_dst;
	struct iphdr * new_iph, * old_iph;

	struct optlsrr {
		u8 nop;
		u8 type;
		u8 length;
		u8 pointer;
		u32 detour_addr[1];
	} __attribute__ ((__packed__));

	struct optlsrr * lsrr;

	old_iph = (struct iphdr *) skb_network_header (skb);
	old_dst = old_iph->daddr;

	if (skb_cow_head (skb, sizeof (struct optlsrr) + 16)) {
		printk (KERN_INFO "%s:%d: skb_cow_head failed\n",
			__func__, __LINE__);
		return;
	}

	new_iph = (struct iphdr *) __skb_push (skb, sizeof (struct optlsrr));
	move_front_ipv4_header (old_iph, new_iph);

	skb_reset_network_header (skb);
	lsrr = (struct optlsrr *) (skb->data + new_iph->ihl * 4) ;

	lsrr->nop	= IPOPT_NOOP;
	lsrr->type	= IPOPT_LSRR;
	lsrr->length	= sizeof (struct optlsrr) - 1; /* - nop */
	lsrr->pointer   = 4;	/* XXX: number of records is always 1 */
	lsrr->detour_addr[0] = old_dst;
	// lsrr->detour_addr[1] = old_dst;

	new_iph->daddr	= *detour->detour_ip4;
	new_iph->ihl	+= sizeof (struct optlsrr) / 4;
	new_iph->tot_len	+= htons (sizeof (struct optlsrr));
	new_iph->check	= 0;
	new_iph->check	= wrapsum (checksum (new_iph, sizeof (struct iphdr) +
					     sizeof (struct optlsrr), 0));

	return;
}

static void (* ipv4_set_encap_func[]) (struct sk_buff * skb,
				       struct detour_addr * detour,
				       struct iplb_net * iplb_net) = {
	ipv4_set_ipip_encap,
	ipv4_set_gre_encap,
	ipv4_set_lsrr_encap
};


/*
void (*ipv6_set_encap_func)[] (struct sk_buff * skb,
			       struct detour_addr * detour,
			       struct iplb_net * iplb_net);
*/


static inline u32
ipv4_flow_hash (struct sk_buff * skb)
{
	__be32		val1, val2;
	struct iphdr	* ip;
	struct tcphdr	* tcp;
	struct udphdr	* udp;

	ip = (struct iphdr *) skb_network_header (skb);

	switch (ip->protocol) {
	case IPPROTO_TCP :
		tcp = (struct tcphdr *) IPTRANSPORTHDR (ip);
		val1 = tcp->source;
		val1 <<= 16;
		val1 += tcp->dest;
		break;
	case IPPROTO_UDP :
		udp = (struct udphdr *) IPTRANSPORTHDR (ip);
		val1 = udp->source;
		val1 <<= 16;
		val1 += udp->dest;
		break;
	default :
		val1 = 1;
	}

	val2 = ip->daddr + ip->saddr;

	return hash_32 (val1 + val2, 16);
}

static unsigned int
nf_iplb_v4_localout (const struct nf_hook_ops * ops,
		    struct sk_buff * skb,
		    const struct net_device * in,
		    const struct net_device * out,
		    int (*okfn)(struct sk_buff *))
{
	struct iphdr		* ip;
	struct detour_tuple	* tuple;
	struct detour_addr	* detour;
	struct net		* net = get_net_ns_by_pid (1);
	struct iplb_net 	* iplb_net = net_generic (net, iplb_net_id);

	ip = (struct iphdr *) skb->data;

	tuple = find_detour_tuple (&iplb_net->rtable4,
				   AF_INET, &ip->daddr, 32);
	if (!tuple)
		return NF_ACCEPT;

	detour = iplb_net->lookup_fn (tuple, ipv4_flow_hash (skb));
	if (!detour)
		return NF_ACCEPT;
	
	if (unlikely (detour->encap_type > IPLB_ENCAP_TYPE_MAX)) {
		printk (KERN_ERR "%s: invalid encap type %u\n",
			__func__, detour->encap_type);
		return NF_ACCEPT;
	}

	ipv4_set_encap_func[detour->encap_type] (skb, detour, iplb_net);

	return NF_ACCEPT;
}


static inline u32
ipv6_flow_hash (struct sk_buff * skb)
{
	int n;
	u32 hash = 0, * d, * s;
	struct ipv6hdr	* ip6;
	struct tcphdr	* tcp;
	struct udphdr	* udp;

	ip6 = (struct ipv6hdr *) skb_network_header (skb);

	switch (ip6->nexthdr) {
	case IPPROTO_TCP :
		tcp = (struct tcphdr *) skb_transport_header (skb);
		hash += tcp->source;
		hash <<= 16;
		hash += tcp->dest;
		break;
	case IPPROTO_UDP :
		udp = (struct udphdr *) skb_transport_header (skb);
		hash += udp->source;
		hash <<= 16;
		hash += udp->dest;
	}

	d = (u32 *) &ip6->daddr;
	s = (u32 *) &ip6->saddr;

	for (n = 0; n < 4; n++) {
		hash += *(d + n);
		hash += *(s + n);
	}

	return hash_32 (hash, 16);
}


static inline void
ipv6_set_ip6ip6_encap (struct sk_buff * skb, struct detour_addr * detour,
		       struct iplb_net * iplb_net)
{
	struct ipv6hdr	* ip6;
	struct ipv6hdr	* ip6ip6h;

	ip6 = (struct ipv6hdr *) skb->data;

	if (skb_cow_head (skb, IPV6_IPIP_HEADROOM)) {
		printk (KERN_INFO "%s:%d: skb_cow_head failed\n",
			__func__, __LINE__);
		return;
	}

	ip6ip6h = (struct ipv6hdr *) __skb_push (skb, sizeof(struct ipv6hdr));
	skb_reset_network_header (skb);

	ip6ip6h->version		= 6;
	ip6ip6h->priority	= IPV6_PRIORITY_UNCHARACTERIZED;
	ip6ip6h->flow_lbl[0]	= 0;
	ip6ip6h->flow_lbl[1]	= 0;
	ip6ip6h->flow_lbl[2]	= 0;
	ip6ip6h->payload_len	= htons (ntohs (ip6->payload_len) +
					 sizeof (struct ipv6hdr));
	ip6ip6h->nexthdr	= IPPROTO_IPV6;
	ip6ip6h->hop_limit	= 16;
	ADDR6COPY (&iplb_net->tunnel_src6, &ip6ip6h->saddr);
	ADDR6COPY (detour->detour_ip6, &ip6ip6h->daddr);
	
	return;
}

static unsigned int
nf_iplb_v6_localout (const struct nf_hook_ops * ops,
		    struct sk_buff * skb,
		    const struct net_device * in,
		    const struct net_device * out,
		    int (*okfn)(struct sk_buff *))
{
	struct ipv6hdr		* ip6;
	struct detour_tuple	* tuple;
	struct detour_addr	* detour;
	struct net		* net = get_net_ns_by_pid (1);
	struct iplb_net 	* iplb_net = net_generic (net, iplb_net_id);

	ip6 = (struct ipv6hdr *) skb->data;

	tuple = find_detour_tuple (&iplb_net->rtable6,
				   AF_INET6, &ip6->daddr, 64);
	if (!tuple)
		return NF_ACCEPT;

	detour = iplb_net->lookup_fn (tuple, ipv6_flow_hash (skb));
	if (!detour)
		return NF_ACCEPT;

	ipv6_set_ip6ip6_encap (skb, detour, iplb_net);

	return NF_ACCEPT;
}


static struct nf_hook_ops nf_iplb_ops[] __read_mostly = {
	{
		.hook		= nf_iplb_v4_localout,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FIRST,
	},
	{
		.hook		= nf_iplb_v6_localout,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP6_PRI_FIRST,
	},
};


static __net_init int
iplb_init_net (struct net * net)
{
	struct iplb_net * iplb_net = net_generic (net, iplb_net_id);
	
	memset (iplb_net, 0, sizeof (struct iplb_net));

	iplb_net->tunnel_src = 0x0100000A;	/* 10.0.0.1 */

	iplb_net->lookup_fn = lookup_detour_addr_from_tuple_weightbase;
	INIT_IPLB_RTABLE (&iplb_net->rtable4, 32);
	INIT_IPLB_RTABLE (&iplb_net->rtable6, 64);

	return 0;
};


static __net_exit void
iplb_exit_net (struct net * net)
{
	struct iplb_net * iplb_net = net_generic (net, iplb_net_id);

	DESTROY_IPLB_RTABLE (&iplb_net->rtable4);
	DESTROY_IPLB_RTABLE (&iplb_net->rtable6);

	return;
}



static struct pernet_operations iplb_net_ops = {
	.init	= iplb_init_net,
	.exit	= iplb_exit_net,
	.id	= &iplb_net_id,
	.size	= sizeof (struct iplb_net),
};


/********************************
 ****   Generic netlink operations
 ********************************/

static struct genl_family iplb_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= IPLB_GENL_NAME,
	.version	= IPLB_GENL_VERSION,
	.maxattr	= IPLB_ATTR_MAX,
};

static struct nla_policy iplb_nl_policy[IPLB_ATTR_MAX + 1] = {
	[IPLB_ATTR_NONE]		= { .type = NLA_UNSPEC, },
	[IPLB_ATTR_PREFIX4]		= { .type = NLA_U32, },
	[IPLB_ATTR_PREFIX6]		= { .type = NLA_BINARY,
					    .len = sizeof (struct in6_addr), },
	[IPLB_ATTR_PREFIX_LENGTH]      	= { .type = NLA_U8, },
	[IPLB_ATTR_RELAY4]		= { .type = NLA_U32, },
	[IPLB_ATTR_RELAY6]		= { .type = NLA_BINARY,
					    .len = sizeof (struct in6_addr), },
	[IPLB_ATTR_WEIGHT]      	= { .type = NLA_U8, },
};

static int
iplb_nl_cmd_prefix4_add (struct sk_buff * skb, struct genl_info * info)
{
	u8		length;
	__be32		prefix;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX4]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	prefix = nla_get_be32 (info->attrs[IPLB_ATTR_PREFIX4]);

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);


	tuple = find_detour_tuple_exact (&iplb_net->rtable4,
					 AF_INET, &prefix, length);
	if (tuple)
		return -EEXIST;

	tuple = add_detour_tuple (&iplb_net->rtable4,
				  AF_INET, &prefix, length);

	if (!tuple) {
		return -EINVAL;
	}

	return 0;
}

static int
iplb_nl_cmd_prefix6_add (struct sk_buff * skb, struct genl_info * info)
{
	u8		length;
	struct in6_addr	prefix;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX6]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	nla_memcpy (&prefix, info->attrs[IPLB_ATTR_PREFIX6], sizeof (prefix));

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	if (length > 64) {
		pr_debug ("%s: invalid prefix length %d\n. "
			  "prefix len must be shorter than 65.",
			  __func__, length);
		return -EINVAL;
	}


	tuple = find_detour_tuple_exact (&iplb_net->rtable6,
					 AF_INET6, &prefix, length);
	if (tuple)
		return -EEXIST;

	tuple = add_detour_tuple (&iplb_net->rtable6,
				  AF_INET6, &prefix, length);

	if (!tuple)
		return -EINVAL;

	return 0;
}

static int
iplb_nl_cmd_prefix4_delete (struct sk_buff * skb, struct genl_info * info)
{
	int		rc;
	u8		length;
	__be32		prefix;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX4]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	prefix = nla_get_be32 (info->attrs[IPLB_ATTR_PREFIX4]);

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);


	tuple = find_detour_tuple_exact (&iplb_net->rtable4,
					 AF_INET, &prefix, length);
	if (!tuple)
		return -ENOENT;

	rc = delete_detour_tuple (&iplb_net->rtable4,
				  AF_INET, &prefix, length);
	if (!rc)
		return -ENOENT;

	return 0;
}

static int
iplb_nl_cmd_prefix6_delete (struct sk_buff * skb, struct genl_info * info)
{
	int		rc;
	u8		length;
	struct in6_addr	prefix;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX6]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	nla_memcpy (&prefix, info->attrs[IPLB_ATTR_PREFIX6], sizeof (prefix));

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	if (length > 64) {
		pr_debug ("%s: invalid prefix length %d\n. "
			  "prefix len must be shorter than 65.",
			  __func__, length);
		return -EINVAL;
	}


	tuple = find_detour_tuple_exact (&iplb_net->rtable6,
					 AF_INET6, &prefix, length);
	if (!tuple)
		return -ENOENT;

	rc = delete_detour_tuple (&iplb_net->rtable6,
				  AF_INET6, &prefix, length);
	if (!rc)
		return -ENOENT;

	return 0;
}

static int
iplb_nl_cmd_relay4_add (struct sk_buff * skb, struct genl_info * info)
{
	u8		length, weight, encap_type;
	__be32		prefix, relay;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX4]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	prefix = nla_get_be32 (info->attrs[IPLB_ATTR_PREFIX4]);

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	if (!info->attrs[IPLB_ATTR_RELAY4]) {
		pr_debug ("%s: relay addr is not specified\n", __func__);
		return -EINVAL;
	}
	relay = nla_get_be32 (info->attrs[IPLB_ATTR_RELAY4]);

	if (!info->attrs[IPLB_ATTR_WEIGHT]) {
		weight = 100;
	} else {
		weight = nla_get_u8 (info->attrs[IPLB_ATTR_WEIGHT]);
	}

	if (weight > 255) {
		pr_debug ("%s: weight must be smaller than 256", __func__);
		return -EINVAL;
	}

	if (!info->attrs[IPLB_ATTR_ENCAP_TYPE]) {
		encap_type = IPLB_ENCAP_TYPE_GRE;
	} else {
		encap_type = nla_get_u8 (info->attrs[IPLB_ATTR_ENCAP_TYPE]);
	}

	tuple = find_detour_tuple_exact (&iplb_net->rtable4,
					 AF_INET, &prefix, length);
	if (!tuple)
		tuple = add_detour_tuple (&iplb_net->rtable4,
					  AF_INET, &prefix, length);

	add_detour_addr_to_tuple (tuple, AF_INET, &relay, weight, encap_type);

	return 0;
}

static int
iplb_nl_cmd_relay6_add (struct sk_buff * skb, struct genl_info * info)
{
	u8		length, weight, encap_type;
	struct in6_addr	prefix, relay;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX6]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	nla_memcpy (&prefix, info->attrs[IPLB_ATTR_PREFIX6], sizeof (prefix));

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	if (!info->attrs[IPLB_ATTR_RELAY6]) {
		pr_debug ("%s: relay addr is not specified\n", __func__);
		return -EINVAL;
	}
	nla_memcpy (&relay, info->attrs[IPLB_ATTR_RELAY6], sizeof (prefix));

	if (!info->attrs[IPLB_ATTR_WEIGHT]) {
		weight = 100;
	}
	weight = nla_get_u8 (info->attrs[IPLB_ATTR_WEIGHT]);

	if (weight > 255) {
		pr_debug ("%s: weight must be smaller than 256", __func__);
		return -EINVAL;
	}

	if (!info->attrs[IPLB_ATTR_ENCAP_TYPE]) {
		encap_type = IPLB_ENCAP_TYPE_GRE;
	} else {
		encap_type = nla_get_u8 (info->attrs[IPLB_ATTR_ENCAP_TYPE]);
	}

	tuple = find_detour_tuple_exact (&iplb_net->rtable6,
					 AF_INET6, &prefix, length);
	if (!tuple)
		tuple = add_detour_tuple (&iplb_net->rtable6,
					  AF_INET6, &prefix, length);

	add_detour_addr_to_tuple (tuple, AF_INET6, &relay, weight, encap_type);

	return 0;
}

static int
iplb_nl_cmd_relay4_delete (struct sk_buff * skb, struct genl_info * info)
{
	u8		length;
	__be32		prefix, relay;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX4]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	prefix = nla_get_be32 (info->attrs[IPLB_ATTR_PREFIX4]);

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	if (!info->attrs[IPLB_ATTR_RELAY4]) {
		pr_debug ("%s: relay addr is not specified\n", __func__);
		return -EINVAL;
	}
	relay = nla_get_be32 (info->attrs[IPLB_ATTR_RELAY4]);


	tuple = find_detour_tuple_exact (&iplb_net->rtable4,
					 AF_INET, &prefix, length);
	if (!tuple)
		return -ENOENT;

	delete_detour_addr_from_tuple (tuple, AF_INET, &relay);

	return 0;
}

static int
iplb_nl_cmd_relay6_delete (struct sk_buff * skb, struct genl_info * info)
{
	u8		length;
	struct in6_addr	prefix, relay;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	if (!info->attrs[IPLB_ATTR_PREFIX6]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	nla_memcpy (&prefix, info->attrs[IPLB_ATTR_PREFIX6], sizeof (prefix));

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	if (!info->attrs[IPLB_ATTR_RELAY6]) {
		pr_debug ("%s: relay addr is not specified\n", __func__);
		return -EINVAL;
	}
	nla_memcpy (&relay, info->attrs[IPLB_ATTR_RELAY6], sizeof (relay));


	tuple = find_detour_tuple_exact (&iplb_net->rtable6,
					 AF_INET6, &prefix, length);
	if (!tuple)
		return -ENOENT;

	delete_detour_addr_from_tuple (tuple, AF_INET6, &relay);

	return 0;
}

static int
iplb_nl_prefix_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
		     int cmd, struct detour_tuple * tuple) 
{
	void * hdr;
	int prefix_attr, addrlen;

	if (!skb || !tuple)
		return -1;

	hdr = genlmsg_put (skb, pid, seq, &iplb_nl_family, flags, cmd);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	/* put prefix, length, relay, weight */

	switch (tuple->prefix->family) {
	case (AF_INET) :
		prefix_attr = IPLB_ATTR_PREFIX4;
		addrlen = sizeof (struct in_addr);
		break;
	case (AF_INET6) :
		prefix_attr = IPLB_ATTR_PREFIX6;
		addrlen = sizeof (struct in6_addr);
		break;
	default :
		printk (KERN_ERR "%s: invalid family of prefix %d",
			__func__, tuple->prefix->family);
		return -1;
	}

	if (nla_put (skb, prefix_attr, addrlen, &tuple->prefix->add) ||
	    nla_put_u8 (skb, IPLB_ATTR_PREFIX_LENGTH, tuple->prefix->bitlen))
		goto error_out;

	return genlmsg_end (skb, hdr);

error_out:
	genlmsg_cancel (skb, hdr);
	return -1;
	
}

static int
iplb_nl_relay_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
		     int cmd, struct detour_addr * detour)
{
	void * hdr;
	int prefix_attr, relay_attr, addrlen;

	if (!skb || !detour)
		return -1;

	hdr = genlmsg_put (skb, pid, seq, &iplb_nl_family, flags, cmd);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	/* put prefix, length, relay, weight */

	switch (detour->family) {
	case (AF_INET) :
		prefix_attr = IPLB_ATTR_PREFIX4;
		relay_attr = IPLB_ATTR_RELAY4;
		addrlen = sizeof (struct in_addr);
		break;
	case (AF_INET6) :
		prefix_attr = IPLB_ATTR_PREFIX6;
		relay_attr = IPLB_ATTR_RELAY6;
		addrlen = sizeof (struct in6_addr);
		break;
	default :
		printk (KERN_ERR "%s: invalid family of detour %d",
			__func__, detour->family);
		goto error_out;
	}

	if (nla_put (skb, prefix_attr, addrlen, &detour->tuple->prefix->add) ||
	    nla_put (skb, relay_attr, addrlen, &detour->detour_ip) ||
	    nla_put_u8 (skb, IPLB_ATTR_PREFIX_LENGTH,
			detour->tuple->prefix->bitlen) ||
	    nla_put_u8 (skb, IPLB_ATTR_WEIGHT, detour->weight))
		goto error_out;

	return genlmsg_end (skb, hdr);

error_out:
	genlmsg_cancel (skb, hdr);
	return -1;
}

static int
iplb_nl_tuple_send (struct sk_buff * skb, struct netlink_callback * cb,
		    int cmd, struct detour_tuple * tuple)
{
	struct detour_addr * detour;

	if (tuple->detour_count == 0) {
		iplb_nl_prefix_send (skb, NETLINK_CB (cb->skb).portid,
				     cb->nlh->nlmsg_seq, NLM_F_MULTI, cmd,
				     tuple);
	} else {
		list_for_each_entry_rcu (detour, &tuple->detour_list, list) {
			iplb_nl_relay_send (skb, NETLINK_CB (cb->skb).portid,
					     cb->nlh->nlmsg_seq, NLM_F_MULTI, 
					     cmd, detour);
		}
	}


	return 1;
}


static int
iplb_nl_cmd_prefix4_get (struct sk_buff * skb, struct genl_info * info)
{
	u8	length;
	__be32	prefix;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net * iplb_net = net_generic (net, iplb_net_id);
	struct sk_buff	* msg;
	struct detour_tuple	* tuple;
	struct detour_addr	* detour;

	if (!info) {
		pr_debug ("%s: genl_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (info->attrs[IPLB_ATTR_PREFIX4]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	prefix = nla_get_be32 (info->attrs[IPLB_ATTR_PREFIX4]);

	if (info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefix length is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	msg = nlmsg_new (NLMSG_DEFAULT_SIZE, GFP_KERNEL);


	tuple = find_detour_tuple (&iplb_net->rtable4, AF_INET,
				   &prefix, length);

	if(tuple->detour_count == 0)
		iplb_nl_prefix_send (skb, info->snd_portid, info->snd_seq,
				     0, IPLB_CMD_PREFIX4_GET, tuple);
	else {
		list_for_each_entry_rcu (detour, &tuple->detour_list, list) {
			iplb_nl_relay_send (skb, info->snd_portid,
					     info->snd_seq, 0,
					     IPLB_CMD_PREFIX4_GET, detour);
		}
	}


	return 1;
}

static int
iplb_nl_cmd_prefix4_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	int 		n = 0, idx = cb->args[0];
	struct net	* net = sock_net (skb->sk);
	struct iplb_net * iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;

	list_for_each_entry_rcu (tuple, &iplb_net->rtable4.rlist, list) {
		if (n == idx) {
			/* send tuple info */

			iplb_nl_tuple_send (skb, cb, IPLB_CMD_PREFIX4_GET,
					    tuple);

			cb->args[0] = n + 1;

			break;
		}
		n++;
	}

	return skb->len;
}

static int
iplb_nl_cmd_prefix6_get (struct sk_buff * skb, struct genl_info * info)
{
	u8	length;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net * iplb_net = net_generic (net, iplb_net_id);
	struct in6_addr	prefix;
	struct sk_buff	* msg;
	struct detour_tuple	* tuple;
	struct detour_addr	* detour;

	if (info->attrs[IPLB_ATTR_PREFIX6]) {
		pr_debug ("%s: prefix is not specified\n", __func__);
		return -EINVAL;
	}
	nla_memcpy (&prefix, info->attrs[IPLB_ATTR_PREFIX6],
		    sizeof (struct in6_addr));

	if (info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefix length is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);

	msg = nlmsg_new (NLMSG_DEFAULT_SIZE, GFP_KERNEL);


	tuple = find_detour_tuple (&iplb_net->rtable6, AF_INET6,
				   &prefix, length);

	if(tuple->detour_count == 0)
		iplb_nl_prefix_send (skb, info->snd_portid, info->snd_seq,
				     0, IPLB_CMD_PREFIX6_GET, tuple);
	else {
		list_for_each_entry_rcu (detour, &tuple->detour_list, list) {
			iplb_nl_relay_send (skb, info->snd_portid,
					     info->snd_seq, 0,
					     IPLB_CMD_PREFIX6_GET, detour);
		}
	}


	return 1;
}

static int
iplb_nl_cmd_prefix6_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	int 		n = 0, idx = cb->args[0];
	struct net	* net = sock_net (skb->sk);
	struct iplb_net * iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;
	
	list_for_each_entry_rcu (tuple, &iplb_net->rtable6.rlist, list) {
		if (n == idx) {
			/* send tuple info */

			iplb_nl_tuple_send (skb, cb, IPLB_CMD_PREFIX6_GET,
					    tuple);

			cb->args[0] = n + 1;

			break;
		}
		n++;
	}

	return skb->len;
}

static int
iplb_nl_cmd_weight_set (struct sk_buff * skb, struct genl_info * info)
{
	u8	length, weight;
	int	prefix_family, relay_family;
	__be32	prefix[4], relay[4];
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct detour_tuple * tuple;
	struct detour_addr  * detour;
	
	length = weight = 0;
	prefix_family = relay_family = 0;

	if (info->attrs[IPLB_ATTR_PREFIX4]) {
		prefix[0] = nla_get_be32 (info->attrs[IPLB_ATTR_PREFIX4]);
		prefix_family = AF_INET;
	}
	if (info->attrs[IPLB_ATTR_PREFIX6]) {
		nla_memcpy (prefix, info->attrs[IPLB_ATTR_PREFIX6], 
			    sizeof (prefix));
		prefix_family = AF_INET6;
	}

	if (info->attrs[IPLB_ATTR_RELAY4]) {
		relay[0] = nla_get_be32 (info->attrs[IPLB_ATTR_RELAY4]);
		relay_family = AF_INET;
	}
	if (info->attrs[IPLB_ATTR_RELAY6]) {
		nla_memcpy (relay, info->attrs[IPLB_ATTR_RELAY6],
			    sizeof (relay));
		relay_family = AF_INET6;
	}

	if (prefix_family != relay_family) {
		pr_debug ("%s: prefix and relay family does not match\n",
			  __func__);
		return -EINVAL;
	}

	if (!info->attrs[IPLB_ATTR_PREFIX_LENGTH]) {
		pr_debug ("%s: prefixlen is not specified\n", __func__);
		return -EINVAL;
	}
	length = nla_get_u8 (info->attrs[IPLB_ATTR_PREFIX_LENGTH]);
	
	if (!info->attrs[IPLB_ATTR_WEIGHT]) {
		pr_debug ("%s: weight is not specified\n", __func__);
		return -EINVAL;
	}
	weight = nla_get_u8 (info->attrs[IPLB_ATTR_WEIGHT]);


	tuple = find_detour_tuple_exact (&iplb_net->rtable4,
					 prefix_family, prefix, length);

	if (!tuple)
		return -ENOENT;
	
	detour = find_detour_addr_from_tuple (tuple, relay_family, relay);
	
	if (detour) {
		tuple->weight_sum -= detour->weight;
		tuple->weight_sum += weight;
		detour->weight = weight;
	} else {
		return -ENOENT;
	}

	return 0;
}

static int
iplb_nl_cmd_lookup_weightbase (struct sk_buff * skb, struct genl_info * info)
{
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	iplb_net->lookup_fn = lookup_detour_addr_from_tuple_weightbase;

	printk (KERN_INFO "iplb: set lookup function \"weightbase\"\n");

	return 0;
}

static int
iplb_nl_cmd_lookup_hashbase (struct sk_buff * skb, struct genl_info * info)
{
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	iplb_net->lookup_fn = lookup_detour_addr_from_tuple_hashbase;

	printk (KERN_INFO "iplb: set lookup function \"hashbase\"\n");

	return 0;
}

static struct genl_ops iplb_nl_ops[] = {
	{
		.cmd	= IPLB_CMD_PREFIX4_ADD,
		.doit	= iplb_nl_cmd_prefix4_add,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_PREFIX6_ADD,
		.doit	= iplb_nl_cmd_prefix6_add,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_PREFIX4_DELETE,
		.doit	= iplb_nl_cmd_prefix4_delete,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_PREFIX6_DELETE,
		.doit	= iplb_nl_cmd_prefix6_delete,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_RELAY4_ADD,
		.doit	= iplb_nl_cmd_relay4_add,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_RELAY6_ADD,
		.doit	= iplb_nl_cmd_relay6_add,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_RELAY4_DELETE,
		.doit	= iplb_nl_cmd_relay4_delete,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_RELAY6_DELETE,
		.doit	= iplb_nl_cmd_relay6_delete,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_PREFIX4_GET,
		.doit	= iplb_nl_cmd_prefix4_get,
		.dumpit	= iplb_nl_cmd_prefix4_dump,
		.policy	= iplb_nl_policy,
	},
	{
		.cmd	= IPLB_CMD_PREFIX6_GET,
		.doit	= iplb_nl_cmd_prefix6_get,
		.dumpit	= iplb_nl_cmd_prefix6_dump,
		.policy	= iplb_nl_policy,
	},
	{
		.cmd	= IPLB_CMD_WEIGHT_SET,
		.doit	= iplb_nl_cmd_weight_set,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_LOOKUP_WEIGHTBASE,
		.doit	= iplb_nl_cmd_lookup_weightbase,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_LOOKUP_HASHBASE,
		.doit	= iplb_nl_cmd_lookup_hashbase,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
};


/********************************
 ****   init/exit module 
 ********************************/

#ifdef TEST
static void
test_load (void)
{
	struct net * net;
	struct iplb_net * iplb_net;
	struct detour_tuple * tuple;

	__be32 dst = 0x08080808;	/* 8.8.8.8 */
	__be32 relay = 0x568fb2cb;	/* 203.178.143.86 */

	net = get_net_ns_by_pid (1);
	iplb_net = (struct iplb_net *) net_generic (net, iplb_net_id);

	tuple = add_detour_tuple (&iplb_net->rtable4,
				  AF_INET, &dst, 24);
	add_detour_addr_to_tuple (tuple, AF_INET, &relay, 10);

	tuple = add_detour_tuple (&iplb_net->rtable4,
				  AF_INET, &relay, 32);
	add_detour_addr_to_tuple (tuple, AF_INET, &dst, 100);

	return;
}
#endif

static int
__init iplb_init_module (void)
{
	int rc;

	get_random_bytes (&iplb_salt, sizeof (iplb_salt));

	rc = register_pernet_subsys (&iplb_net_ops);
	if (rc != 0)
		return rc;

	rc = genl_register_family_with_ops (&iplb_nl_family, iplb_nl_ops);
	if (rc < 0)
		goto genl_err;

	rc = nf_register_hooks (nf_iplb_ops, ARRAY_SIZE (nf_iplb_ops));
	if (rc < 0)
		goto nf_err;

	printk (KERN_INFO "iplb (%s) is loaded\n", IPLB_VERSION);

#ifdef TEST
	test_load ();
#endif

	return 0;

nf_err:
	genl_unregister_family (&iplb_nl_family);
genl_err:
	unregister_pernet_subsys (&iplb_net_ops);
	return rc;
}
module_init (iplb_init_module);


static void
__exit iplb_exit_module (void)
{
	unregister_pernet_subsys (&iplb_net_ops);
	nf_unregister_hooks (nf_iplb_ops, ARRAY_SIZE (nf_iplb_ops));
	genl_unregister_family (&iplb_nl_family);

	printk (KERN_INFO "iplb (%s) is unloaded\n", 
		IPLB_VERSION);

	return;
}
module_exit (iplb_exit_module);

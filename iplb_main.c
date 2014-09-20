
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
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


#define IPV4_GRE_HEADROOM	(8 + 20 + 14)
#define IPV6_GRE_HEADROOM	(8 + 40 + 14)
#define IPV4_IPIP_HEADROOM	(20 + 14)
#define IPV6_IPIP_HEADROOM	(40 + 14)

#define FLOW_HASH_BITS		8
#define FLOW_AGE_LIFETIME	(60 * HZ)
#define FLOW_AGE_INTERVAL	(10 * HZ)

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
				  patricia_destroy_relay_tuple);	\
		(rt)->rtable = NULL;					\
		write_unlock_bh (&(rt)->lock);				\
	} while (0)


/* relay address for one next hop */
struct relay_addr {
	struct list_head	list;
	struct rcu_head		rcu;

	struct relay_tuple 	* tuple;	/* parent */
	struct iplb_stats	stats;

	u8			family;
	u8			weight;
	u8			encap_type;

	union {
		__be32		__relay_addr4[1];
		__be32		__relay_addr6[4];
	} relay_ip;
#define relay_ip4	relay_ip.__relay_addr4
#define relay_ip6	relay_ip.__relay_addr6
};

struct relay_tuple {
	struct list_head	list;		/* private */

	prefix_t		* prefix;	/* prefix of route table */

	u32			weight_sum;	
	int			relay_count;

	struct list_head	relay_list;	/* list of relay_addr */
};


/* Flow classifier for flow scheduling */

struct iplb_flow4 {
	struct hlist_node	hash;	/* private for linux/hashtable */
	struct rcu_head		rcu;	/* private */
	unsigned long		key;	/* private */

	int	updated;	/* lifetime to live. jiffies. */

	u8	protocol;	/* tcp or udp		*/
	__be32	saddr, daddr;	/* src/dst address	*/
	u16	sport, dport;	/* src/dst port number. (network byte order) */

	u32	pkt_count;
	u32	byte_count;

	u32	relay_number;	/* the place of relay on relay_list */
	/*
	 * if relay_number is larger than relay_count of tuple,
	 * relay_number is changed to 1. 0 means "unspecified".
	 */
};


/* XXX: hashtable for flow should be declared in netns structure. */
static DEFINE_HASHTABLE (flow4_table, FLOW_HASH_BITS);
static struct timer_list iplb_age_timer;


/* Per network namespace structure */
struct iplb_net {

	/* tunnel source address (not used for routing) */
	__be32			tunnel_src;	/* default 10.0.0.1	*/
	struct in6_addr		tunnel_src6;	/* default 2001:db8::1	*/

	/* lookup function for relay_addr from tuple. */
	struct relay_addr * (* lookup_fn) (struct sk_buff *,
					   struct relay_tuple * );

	/* routing tables for IPv4 and IPv6 */
	struct iplb_rtable	rtable4;
	struct iplb_rtable	rtable6;
};



/********************************
 ****   routing table operations
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

static struct relay_tuple *
find_relay_tuple (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
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

static struct relay_tuple *
find_relay_tuple_exact (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
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

static struct relay_tuple *
add_relay_tuple (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
{
	prefix_t		* prefix;
	patricia_node_t		* pn;
	struct relay_tuple	* tuple;

	prefix = kmalloc (sizeof (prefix_t), GFP_KERNEL);
	memset (prefix, 0, sizeof (prefix_t));

	dst2prefix (af, dst, len, prefix);

	write_lock_bh (&rt->lock);
	pn = patricia_lookup (rt->rtable, prefix);


	if (pn->data != NULL) {
		write_unlock_bh (&rt->lock);
		return pn->data;
	}

	tuple = (struct relay_tuple *) kmalloc (sizeof (struct relay_tuple),
						GFP_KERNEL);
	memset (tuple, 0, sizeof (struct relay_tuple));

	tuple->prefix		= prefix;
	tuple->weight_sum	= 0;
	tuple->relay_count	= 0;
	INIT_LIST_HEAD (&tuple->relay_list);

	pn->data = tuple;

	list_add_rcu (&tuple->list, &rt->rlist);

	write_unlock_bh (&rt->lock);

	return tuple;
}


static void
destroy_relay_tuple (struct relay_tuple * tuple)
{
	struct list_head	* p, * tmp;
	struct relay_addr	* relay;

	if (tuple == NULL)
		return;

	list_for_each_safe (p, tmp, &tuple->relay_list) {
		relay = list_entry (p, struct relay_addr, list);
		list_del_rcu (p);
		kfree_rcu (relay, rcu);
	}

	kfree (tuple);

	return;
}


static int
delete_relay_tuple (struct iplb_rtable * rt, u8 af, void * dst, u16 len)
{
	prefix_t		prefix;
	patricia_node_t		* pn;
	struct relay_tuple	* tuple;


	dst2prefix (af, dst, len, &prefix);

	write_lock_bh (&rt->lock);
	pn = patricia_search_exact (rt->rtable, &prefix);

	if (!pn) {
		write_unlock_bh (&rt->lock);
		return 0;
	}

	tuple = (struct relay_tuple *) pn->data;
	
	list_del_rcu (&tuple->list);

	pn->data = NULL;
	destroy_relay_tuple (tuple);
	patricia_remove (rt->rtable, pn);

	write_unlock_bh (&rt->lock);

	return 1;
}



static void
add_relay_addr_to_tuple (struct relay_tuple * tuple, 
			  u8 af, void * addr, u8 weight, u8 encap_type)
{
	struct relay_addr * relay;

	relay = (struct relay_addr *) kmalloc (sizeof (struct relay_addr),
						 GFP_KERNEL);
	memset (relay, 0, sizeof (struct relay_addr));


	relay->tuple	= tuple;
	relay->family	= af;
	relay->weight	= weight;
	relay->encap_type	= encap_type;
	relay->stats.pkt_count	= 0;
	relay->stats.byte_count = 0;

	switch (af) {
	case (AF_INET) :
		ADDR4COPY (addr, &relay->relay_ip4);
		break;
	case (AF_INET6) :
		ADDR6COPY (addr, &relay->relay_ip6);
		break;
	default :
		printk (KERN_ERR "%s:%d: invalid family %u\n", 
			__FUNCTION__, __LINE__, af);
		kfree (relay);
		return;
	}
	
	list_add_rcu (&relay->list, &tuple->relay_list);

	tuple->weight_sum += weight;
	tuple->relay_count++;

	return;
}

static void
delete_relay_addr_from_tuple (struct relay_tuple * tuple, u8 af, void * addr)
{
	struct list_head	* p, * tmp;
	struct relay_addr	* relay;

	list_for_each_safe (p, tmp, &(tuple->relay_list)) {
		relay = list_entry (p, struct relay_addr, list);
		if (ADDRCMP (af, &relay->relay_ip, addr)) {
			tuple->weight_sum -= relay->weight;
			tuple->relay_count--;
			list_del_rcu (p);
			kfree_rcu (relay, rcu);
			return;
		}
	}

	return;
}

static void
update_iplb_stats (struct relay_addr * relay, struct sk_buff * skb)
{
	relay->stats.pkt_count++;
	relay->stats.byte_count += skb->len;

	return;
}

static struct relay_addr *
find_relay_addr_from_tuple (struct relay_tuple * tuple, u8 af, void * addr)
{
	struct relay_addr * relay;

	relay = NULL;

	list_for_each_entry_rcu (relay, &tuple->relay_list, list) {
		if (ADDRCMP (af, &relay->relay_ip, addr))
			return relay;
	}

	return NULL;
}


static void
patricia_destroy_relay_tuple (void * data)
{
	destroy_relay_tuple ((struct relay_tuple *) data);

	return;
}


/********************************
 ****   flow classifier related
 ********************************/

#define FLOW4_HASH_KEY(proto, saddr, daddr, sport, dport) \
	hash_32 (proto + saddr + daddr + sport + dport, FLOW_HASH_BITS)

static struct iplb_flow4 *
find_flow4 (u8 proto, __be32 saddr, __be32 daddr,
	    u16 sport, u16 dport)
{
	unsigned long key;
	struct iplb_flow4 * flow4 = NULL;

	key = FLOW4_HASH_KEY (proto, saddr, daddr, sport, dport);

	hash_for_each_possible_rcu (flow4_table, flow4, hash, key) {
		if (flow4->protocol == proto &&
		    flow4->dport == dport && flow4->sport == sport &&
		    flow4->daddr == daddr && flow4->saddr == saddr) {
			return flow4;
		}
	}

	return NULL;
}

static struct iplb_flow4 *
create_flow4 (u8 proto, __be32 saddr, __be32 daddr, u16 sport, u16 dport,
	      int f)
{
	struct iplb_flow4 * flow4;

	flow4 = (struct iplb_flow4 *) kmalloc (sizeof (struct iplb_flow4), f);
	if (!flow4) {
		printk (KERN_ERR "iplb:%s: failed to allocate memory\n",
			__func__);
		return NULL;
	}

	flow4->protocol	= proto;
	flow4->saddr	= saddr;
	flow4->daddr	= daddr;
	flow4->sport	= sport;
	flow4->dport	= dport;
	flow4->key	= FLOW4_HASH_KEY (proto, saddr, dport, sport, dport);
	flow4->pkt_count  = 0;
	flow4->byte_count = 0;
	flow4->relay_number = 0;
	flow4->updated	= jiffies;

	return flow4;
}

static void
cleanup_flow (unsigned long arg)
{
	int n;
	struct iplb_flow4 * flow4;
	struct hlist_node * tmp;
	unsigned long timeout;
	unsigned long next_timer = jiffies + FLOW_AGE_INTERVAL;

	hash_for_each_safe (flow4_table, n, tmp, flow4, hash) {

		timeout = flow4->updated + FLOW_AGE_LIFETIME;

		if (time_before_eq (timeout, jiffies)) {
			hash_del_rcu (&flow4->hash);
			kfree_rcu (flow4, rcu);
		}
	}

	mod_timer (&iplb_age_timer, next_timer);

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
ipv4_set_gre_encap (struct sk_buff * skb, struct relay_addr * relay,
		    struct iplb_net * iplb_net)
{
	struct iphdr	* iph, * ipiph;
	struct grehdr {
		__be16	flags;
		__be16	protocol;
	};
	struct grehdr * greh;

	iph = (struct iphdr *) skb_network_header (skb);

	if (skb_cow_head (skb, IPV4_GRE_HEADROOM)) {
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
	ipiph->daddr	= *relay->relay_ip4;
	ipiph->check	= wrapsum (checksum (ipiph, sizeof (struct iphdr), 0));

	greh = (struct grehdr *) (ipiph + 1);
	greh->flags	= 0;
	greh->protocol	= htons (ETH_P_IP);

	return;
}

static inline void
ipv4_set_ipip_encap (struct sk_buff * skb, struct relay_addr * relay,
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
	ipiph->daddr	= *relay->relay_ip4;
	ipiph->check	= wrapsum (checksum (ipiph, sizeof (struct iphdr), 0));

	return;
}

static inline void
ipv4_set_lsrr_encap (struct sk_buff * skb, struct relay_addr * relay,
		     struct iplb_net * iplb_net)
{
	__be32	old_dst;
	struct iphdr * new_iph, * old_iph;

	struct optlsrr {
		u8 nop;
		u8 type;
		u8 length;
		u8 pointer;
		u32 relay_addr[1];
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
	lsrr->relay_addr[0] = old_dst;
	// lsrr->relay_addr[1] = old_dst;

	new_iph->daddr	= *relay->relay_ip4;
	new_iph->ihl	+= sizeof (struct optlsrr) / 4;
	new_iph->tot_len	+= htons (sizeof (struct optlsrr));
	new_iph->check	= 0;
	new_iph->check	= wrapsum (checksum (new_iph, sizeof (struct iphdr) +
					     sizeof (struct optlsrr), 0));

	return;
}

static void (* ipv4_set_encap_func[]) (struct sk_buff * skb,
				       struct relay_addr * relay,
				       struct iplb_net * iplb_net) = {
	ipv4_set_gre_encap,
	ipv4_set_ipip_encap,
	ipv4_set_lsrr_encap
};

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
	case IPPROTO_ICMP :
		val1 = 1;
		break;
	default :
		/* unspported protocol is forwarded natively. */
		return 0;
	}

	val2 = ip->daddr + ip->saddr;

	return hash_32 (val1 + val2, 16);
}

static inline u32
ipv4_flow_classify (struct sk_buff * skb, struct relay_tuple * tuple)
{
	u16	sport, dport;
	struct iplb_flow4 * flow4;
	struct iphdr 	* ip;
	struct tcphdr	* tcp;
	struct udphdr	* udp;

	ip = (struct iphdr *) skb_network_header (skb);
	switch (ip->protocol) {
	case IPPROTO_TCP :
		tcp = (struct tcphdr *) IPTRANSPORTHDR (ip);
		sport = tcp->source;
		dport = tcp->dest;
		break;
	case IPPROTO_UDP :
		udp = (struct udphdr *) IPTRANSPORTHDR (ip);
		sport = udp->source;
		dport = udp->dest;
		break;
	case IPPROTO_ICMP :
		sport = dport = 0;
		break;
	default :
		/* unspported protocol is forwarded natively. */
		return 0;
	}

	flow4 = find_flow4 (ip->protocol, ip->saddr, ip->daddr,
			    sport, dport);
	if (flow4 == NULL) {
		flow4 = create_flow4 (ip->protocol,ip->saddr, ip->daddr,
				      sport, dport, GFP_ATOMIC);
		if (flow4 == NULL)
			return 0;
		hash_add_rcu (flow4_table, &flow4->hash, flow4->key);
	}

	if (unlikely (flow4->relay_number > tuple->relay_count)) {
		flow4->relay_number = 0;
	}

	flow4->pkt_count  += 1;
	flow4->byte_count += skb->len;
	flow4->updated    = jiffies;

	return flow4->relay_number;
}


static struct relay_addr *
lookup_relay_addr_from_tuple_weightbase (struct sk_buff * skb,
					 struct relay_tuple *tuple)
{
	u32 hash, w;
	struct relay_addr * relay;

	hash = ipv4_flow_hash (skb);
	if (unlikely (!hash))
		return NULL;

	relay = NULL;
	w = hash % tuple->weight_sum;

	list_for_each_entry_rcu (relay, &tuple->relay_list, list) {
		if (relay->weight >= w) {
			break;
		}
		w -= relay->weight;
	}

	return relay;
}

static struct relay_addr *
lookup_relay_addr_from_tuple_hashbase (struct sk_buff * skb,
					struct relay_tuple * tuple)
{
	u32 hash, h;
	struct relay_addr * relay;

	/* hashbase means all locator weights are 100. */

	hash = ipv4_flow_hash (skb);
	if (unlikely (!hash))
		return NULL;

	if (tuple->relay_count == 0)
		return NULL;

	relay = NULL;
	h = hash % (tuple->relay_count * 100);

	list_for_each_entry_rcu (relay, &tuple->relay_list, list) {
		if (100 >= h)
			break;
		h -= 100;
	}

	return relay;
}

static struct relay_addr *
lookup_relay_addr_from_tuple_flowbase (struct sk_buff * skb,
				       struct relay_tuple * tuple)
{
	u32 hash;
	struct relay_addr * relay = NULL;

	hash = ipv4_flow_classify (skb, tuple);
	if (!hash)
		return NULL;

	list_for_each_entry_rcu (relay, &tuple->relay_list, list) {
		if (--hash == 0)
			break;
	}

	return relay;
}

static unsigned int
nf_iplb_v4_localout (const struct nf_hook_ops * ops,
		    struct sk_buff * skb,
		    const struct net_device * in,
		    const struct net_device * out,
		    int (*okfn)(struct sk_buff *))
{
	struct iphdr		* ip;
	struct relay_tuple	* tuple;
	struct relay_addr	* relay;
	struct net		* net = get_net_ns_by_pid (1);
	struct iplb_net 	* iplb_net = net_generic (net, iplb_net_id);

	ip = (struct iphdr *) skb->data;

	tuple = find_relay_tuple (&iplb_net->rtable4,
				   AF_INET, &ip->daddr, 32);
	if (!tuple)
		return NF_ACCEPT;

	relay = iplb_net->lookup_fn (skb, tuple);
	if (!relay)
		return NF_ACCEPT;
	
	if (unlikely (relay->encap_type > IPLB_ENCAP_TYPE_MAX)) {
		printk (KERN_ERR "%s: invalid encap type %u\n",
			__func__, relay->encap_type);
		return NF_ACCEPT;
	}

	ipv4_set_encap_func[relay->encap_type] (skb, relay, iplb_net);
	update_iplb_stats (relay, skb);

	return NF_ACCEPT;
}





/*
void (*ipv6_set_encap_func)[] (struct sk_buff * skb,
			       struct relay_addr * relay,
			       struct iplb_net * iplb_net);
*/


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
ipv6_set_ip6ip6_encap (struct sk_buff * skb, struct relay_addr * relay,
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
	ADDR6COPY (relay->relay_ip6, &ip6ip6h->daddr);
	
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
	struct relay_tuple	* tuple;
	struct relay_addr	* relay;
	struct net		* net = get_net_ns_by_pid (1);
	struct iplb_net 	* iplb_net = net_generic (net, iplb_net_id);

	ip6 = (struct ipv6hdr *) skb->data;

	tuple = find_relay_tuple (&iplb_net->rtable6,
				   AF_INET6, &ip6->daddr, 64);
	if (!tuple)
		return NF_ACCEPT;

	relay = iplb_net->lookup_fn (skb, tuple);
	if (!relay)
		return NF_ACCEPT;

	ipv6_set_ip6ip6_encap (skb, relay, iplb_net);

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

	/* tunnel_src = 10.0.0.1 */
	iplb_net->tunnel_src = 0x0100000A;

	/* tunnel_src6 = 2001:db8::1 */
	iplb_net->tunnel_src6.in6_u.u6_addr32[0] = 0xb80d0120;
	iplb_net->tunnel_src6.in6_u.u6_addr32[1] = 0x00000000;
	iplb_net->tunnel_src6.in6_u.u6_addr32[2] = 0x00000000;
	iplb_net->tunnel_src6.in6_u.u6_addr32[3] = 0x01000000;

	iplb_net->lookup_fn = lookup_relay_addr_from_tuple_weightbase;
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
	[IPLB_ATTR_ENCAP_TYPE]		= { .type = NLA_U8, },
	[IPLB_ATTR_SRC4]		= { .type = NLA_U32, },
	[IPLB_ATTR_SRC6]		= { .type = NLA_BINARY,
					    .len = sizeof (struct in6_addr), },
	[IPLB_ATTR_STATS]		= { .type = NLA_BINARY,
					    .len =
					    sizeof (struct iplb_stats), },
	[IPLB_ATTR_FLOW4]		= { .type = NLA_BINARY,
					    .len =
					    sizeof (struct iplb_flow4), },
};

static int
iplb_nl_cmd_prefix4_add (struct sk_buff * skb, struct genl_info * info)
{
	u8		length;
	__be32		prefix;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct relay_tuple * tuple;

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


	tuple = find_relay_tuple_exact (&iplb_net->rtable4,
					AF_INET, &prefix, length);
	if (tuple)
		return -EEXIST;

	tuple = add_relay_tuple (&iplb_net->rtable4,
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
	struct relay_tuple * tuple;

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


	tuple = find_relay_tuple_exact (&iplb_net->rtable6,
					AF_INET6, &prefix, length);
	if (tuple)
		return -EEXIST;

	tuple = add_relay_tuple (&iplb_net->rtable6,
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
	struct relay_tuple * tuple;

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


	tuple = find_relay_tuple_exact (&iplb_net->rtable4,
					AF_INET, &prefix, length);
	if (!tuple)
		return -ENOENT;

	rc = delete_relay_tuple (&iplb_net->rtable4,
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
	struct relay_tuple * tuple;

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


	tuple = find_relay_tuple_exact (&iplb_net->rtable6,
					AF_INET6, &prefix, length);
	if (!tuple)
		return -ENOENT;

	rc = delete_relay_tuple (&iplb_net->rtable6,
				 AF_INET6, &prefix, length);
	if (!rc)
		return -ENOENT;

	return 0;
}

static int
iplb_nl_cmd_relay4_add (struct sk_buff * skb, struct genl_info * info)
{
	u8		length, weight, encap_type;
	__be32		prefix, addr;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct relay_tuple * tuple;

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
	addr = nla_get_be32 (info->attrs[IPLB_ATTR_RELAY4]);

	if (!info->attrs[IPLB_ATTR_WEIGHT]) {
		weight = 100;
	} else {
		weight = nla_get_u8 (info->attrs[IPLB_ATTR_WEIGHT]);
	}

	if (!info->attrs[IPLB_ATTR_ENCAP_TYPE]) {
		encap_type = IPLB_ENCAP_TYPE_GRE;
	} else {
		encap_type = nla_get_u8 (info->attrs[IPLB_ATTR_ENCAP_TYPE]);
	}

	tuple = find_relay_tuple_exact (&iplb_net->rtable4,
					AF_INET, &prefix, length);
	if (!tuple)
		tuple = add_relay_tuple (&iplb_net->rtable4,
					 AF_INET, &prefix, length);

	add_relay_addr_to_tuple (tuple, AF_INET, &addr, weight, encap_type);

	return 0;
}

static int
iplb_nl_cmd_relay6_add (struct sk_buff * skb, struct genl_info * info)
{
	u8		length, weight, encap_type;
	struct in6_addr	prefix, addr;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct relay_tuple * tuple;

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
	nla_memcpy (&addr, info->attrs[IPLB_ATTR_RELAY6], sizeof (addr));

	if (!info->attrs[IPLB_ATTR_WEIGHT]) {
		weight = 100;
	}
	weight = nla_get_u8 (info->attrs[IPLB_ATTR_WEIGHT]);

	if (!info->attrs[IPLB_ATTR_ENCAP_TYPE]) {
		encap_type = IPLB_ENCAP_TYPE_GRE;
	} else {
		encap_type = nla_get_u8 (info->attrs[IPLB_ATTR_ENCAP_TYPE]);
	}

	tuple = find_relay_tuple_exact (&iplb_net->rtable6,
					AF_INET6, &prefix, length);
	if (!tuple)
		tuple = add_relay_tuple (&iplb_net->rtable6,
					 AF_INET6, &prefix, length);

	add_relay_addr_to_tuple (tuple, AF_INET6, &addr, weight, encap_type);

	return 0;
}

static int
iplb_nl_cmd_relay4_delete (struct sk_buff * skb, struct genl_info * info)
{
	u8		length;
	__be32		prefix, addr;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct relay_tuple * tuple;

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
	addr = nla_get_be32 (info->attrs[IPLB_ATTR_RELAY4]);


	tuple = find_relay_tuple_exact (&iplb_net->rtable4,
					AF_INET, &prefix, length);
	if (!tuple)
		return -ENOENT;

	delete_relay_addr_from_tuple (tuple, AF_INET, &addr);

	return 0;
}

static int
iplb_nl_cmd_relay6_delete (struct sk_buff * skb, struct genl_info * info)
{
	u8		length;
	struct in6_addr	prefix, addr;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct relay_tuple * tuple;

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
	nla_memcpy (&addr, info->attrs[IPLB_ATTR_RELAY6], sizeof (addr));


	tuple = find_relay_tuple_exact (&iplb_net->rtable6,
					AF_INET6, &prefix, length);
	if (!tuple)
		return -ENOENT;

	delete_relay_addr_from_tuple (tuple, AF_INET6, &addr);

	return 0;
}

static int
iplb_nl_prefix_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
		     int cmd, struct relay_tuple * tuple) 
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
		     int cmd, struct relay_addr * relay)
{
	void * hdr;
	int prefix_attr, relay_attr, addrlen;

	if (!skb || !relay)
		return -1;

	hdr = genlmsg_put (skb, pid, seq, &iplb_nl_family, flags, cmd);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	/* put prefix, length, relay, weight, stats */

	switch (relay->family) {
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
		printk (KERN_ERR "%s: invalid family of relay %d",
			__func__, relay->family);
		goto error_out;
	}

	if (nla_put (skb, prefix_attr, addrlen, &relay->tuple->prefix->add) ||
	    nla_put (skb, relay_attr, addrlen, &relay->relay_ip) ||
	    nla_put_u8 (skb, IPLB_ATTR_PREFIX_LENGTH,
			relay->tuple->prefix->bitlen) ||
	    nla_put_u8 (skb, IPLB_ATTR_WEIGHT, relay->weight) ||
	    nla_put_u8 (skb, IPLB_ATTR_ENCAP_TYPE, relay->encap_type) ||
	    nla_put (skb, IPLB_ATTR_STATS, sizeof (struct relay_addr),
		     &relay->stats))
		goto error_out;

	return genlmsg_end (skb, hdr);

error_out:
	genlmsg_cancel (skb, hdr);
	return -1;
}

static int
iplb_nl_tuple_send (struct sk_buff * skb, struct netlink_callback * cb,
		    int cmd, struct relay_tuple * tuple)
{
	struct relay_addr * relay;

	if (tuple->relay_count == 0) {
		iplb_nl_prefix_send (skb, NETLINK_CB (cb->skb).portid,
				     cb->nlh->nlmsg_seq, NLM_F_MULTI, cmd,
				     tuple);
	} else {
		list_for_each_entry_rcu (relay, &tuple->relay_list, list) {
			iplb_nl_relay_send (skb, NETLINK_CB (cb->skb).portid,
					    cb->nlh->nlmsg_seq, NLM_F_MULTI, 
					    cmd, relay);
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
	struct relay_tuple	* tuple;
	struct relay_addr	* relay;

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


	tuple = find_relay_tuple (&iplb_net->rtable4, AF_INET,
				  &prefix, length);

	if(tuple->relay_count == 0)
		iplb_nl_prefix_send (skb, info->snd_portid, info->snd_seq,
				     0, IPLB_CMD_PREFIX4_GET, tuple);
	else {
		list_for_each_entry_rcu (relay, &tuple->relay_list, list) {
			iplb_nl_relay_send (skb, info->snd_portid,
					    info->snd_seq, 0,
					    IPLB_CMD_PREFIX4_GET, relay);
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
	struct relay_tuple * tuple;

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
	struct relay_tuple	* tuple;
	struct relay_addr	* relay;

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


	tuple = find_relay_tuple (&iplb_net->rtable6, AF_INET6,
				  &prefix, length);

	if(tuple->relay_count == 0)
		iplb_nl_prefix_send (skb, info->snd_portid, info->snd_seq,
				     0, IPLB_CMD_PREFIX6_GET, tuple);
	else {
		list_for_each_entry_rcu (relay, &tuple->relay_list, list) {
			iplb_nl_relay_send (skb, info->snd_portid,
					    info->snd_seq, 0,
					    IPLB_CMD_PREFIX6_GET, relay);
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
	struct relay_tuple * tuple;
	
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
	__be32	prefix[4], addr[4];
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);
	struct relay_tuple * tuple;
	struct relay_addr  * relay;
	
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
		addr[0] = nla_get_be32 (info->attrs[IPLB_ATTR_RELAY4]);
		relay_family = AF_INET;
	}
	if (info->attrs[IPLB_ATTR_RELAY6]) {
		nla_memcpy (addr, info->attrs[IPLB_ATTR_RELAY6],
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


	tuple = find_relay_tuple_exact (&iplb_net->rtable4,
					prefix_family, prefix, length);

	if (!tuple)
		return -ENOENT;
	
	relay = find_relay_addr_from_tuple (tuple, relay_family, addr);
	
	if (relay) {
		tuple->weight_sum -= relay->weight;
		tuple->weight_sum += weight;
		relay->weight = weight;
	} else {
		return -ENOENT;
	}

	return 0;
}

static int
iplb_nl_cmd_src4_set (struct sk_buff * skb, struct genl_info * info)
{
	__be32 src;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	if (!info->attrs[IPLB_ATTR_SRC4]) {
		pr_debug ("%s: address is not specified\n",  __func__);
		return -EINVAL;
	}

	src = nla_get_be32 (info->attrs[IPLB_ATTR_SRC4]);

	iplb_net->tunnel_src = src;

	pr_debug ("%s: set tunnel src %pI4\n",
		  __func__, &iplb_net->tunnel_src);

	return 0;
}

static int
iplb_nl_cmd_src6_set (struct sk_buff * skb, struct genl_info * info)
{
	struct in6_addr src6;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	if (!info->attrs[IPLB_ATTR_SRC6]) {
		pr_debug ("%s: address is not specified\n", __func__);
		return -EINVAL;
	}

	nla_memcpy (&src6, info->attrs[IPLB_ATTR_SRC6], sizeof (src6));

	iplb_net->tunnel_src6 = src6;

	pr_debug ("%s: set tunnel src %pI6\n",
		  __func__, &iplb_net->tunnel_src6);

	return 0;
}

static int
iplb_nl_cmd_src4_get (struct sk_buff * skb, struct genl_info * info)
{
	void * hdr;
	struct sk_buff	* msg;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	msg = nlmsg_new (NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		return -ENOMEM;
	}

	hdr = genlmsg_put (msg, info->snd_portid, info->snd_seq,
			   &iplb_nl_family, NLM_F_ACK, IPLB_CMD_SRC4_GET);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32 (skb, IPLB_ATTR_SRC4, iplb_net->tunnel_src)) {
		genlmsg_cancel (msg, hdr);
		return -EINVAL;
	}

	if (genlmsg_end (msg, hdr) < 0) {
		nlmsg_free (msg);
		return -EINVAL;
	}

	return genlmsg_unicast (net, msg, info->snd_portid);
}

static int
iplb_nl_cmd_src6_get (struct sk_buff * skb, struct genl_info * info)
{
	void * hdr;
	struct sk_buff	* msg;
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	msg = nlmsg_new (NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		return -ENOMEM;
	}

	hdr = genlmsg_put (msg, info->snd_portid, info->snd_seq,
			   &iplb_nl_family, NLM_F_ACK, IPLB_CMD_SRC4_GET);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put (skb, IPLB_ATTR_SRC6, sizeof (struct in6_addr),
		     &iplb_net->tunnel_src6)) {
		genlmsg_cancel (msg, hdr);
		return -EINVAL;
	}

	if (genlmsg_end (msg, hdr) < 0) {
		nlmsg_free (msg);
		return -EINVAL;
	}

	return genlmsg_unicast (net, msg, info->snd_portid);
}

static int
iplb_nl_flow4_send (struct sk_buff * skb, u32 pid, u32 seq, int flags,
		    struct iplb_flow4 * flow4)
{
	void * hdr;
	struct iplb_flow4_info info;
	
	if (!skb || ! flow4)
		return -1;

	hdr = genlmsg_put (skb, pid, seq, &iplb_nl_family,
			   flags, IPLB_CMD_FLOW4_GET);

	if (IS_ERR (hdr))
		PTR_ERR (hdr);

	info.protocol = flow4->protocol;
	info.saddr = flow4->saddr;
	info.daddr = flow4->daddr;
	info.sport = flow4->sport;
	info.dport = flow4->dport;
	info.pkt_count = flow4->pkt_count;
	info.byte_count = flow4->byte_count;
	info.relay_number = flow4->relay_number;
	
	if (nla_put (skb, IPLB_ATTR_FLOW4, sizeof (struct iplb_flow4_info),
		    &info))
		goto error_out;

	return genlmsg_end (skb, hdr);

error_out:
	genlmsg_cancel (skb, hdr);
	return -1;
}

static int
iplb_nl_cmd_flow4_dump (struct sk_buff * skb, struct netlink_callback * cb)
{
	int	n = 0, i, idx = cb->args[0];
	struct iplb_flow4 * flow4;

	hash_for_each_rcu (flow4_table, i, flow4, hash) {
		if (n == idx) {
			iplb_nl_flow4_send (skb, NETLINK_CB (cb->skb).portid,
					    cb->nlh->nlmsg_seq, NLM_F_MULTI,
					    flow4);
			cb->args[0] = n + 1;
			break;
		}
		n++;
	}

	return skb->len;
}

static int
iplb_nl_cmd_lookup_weightbase (struct sk_buff * skb, struct genl_info * info)
{
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	iplb_net->lookup_fn = lookup_relay_addr_from_tuple_weightbase;

	printk (KERN_INFO "iplb: set lookup function \"weightbase\"\n");

	return 0;
}

static int
iplb_nl_cmd_lookup_hashbase (struct sk_buff * skb, struct genl_info * info)
{
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	iplb_net->lookup_fn = lookup_relay_addr_from_tuple_hashbase;

	printk (KERN_INFO "iplb: set lookup function \"hashbase\"\n");

	return 0;
}

static int
iplb_nl_cmd_lookup_flowbase (struct sk_buff * skb, struct genl_info * info)
{
	struct net	* net = sock_net (skb->sk);
	struct iplb_net	* iplb_net = net_generic (net, iplb_net_id);

	iplb_net->lookup_fn = lookup_relay_addr_from_tuple_flowbase;

	printk (KERN_INFO "iplb: set lookup function \"flowbase\"\n");

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
		.cmd	= IPLB_CMD_SRC4_SET,
		.doit	= iplb_nl_cmd_src4_set,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_SRC6_SET,
		.doit	= iplb_nl_cmd_src6_set,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IPLB_CMD_SRC4_GET,
		.doit	= iplb_nl_cmd_src4_get,
		.policy	= iplb_nl_policy,
	},
	{
		.cmd	= IPLB_CMD_SRC6_GET,
		.doit	= iplb_nl_cmd_src6_get,
		.policy	= iplb_nl_policy,
	},
	{
		.cmd	= IPLB_CMD_FLOW4_GET,
		.dumpit	= iplb_nl_cmd_flow4_dump,
		.policy	= iplb_nl_policy,
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
	{
		.cmd	= IPLB_CMD_LOOKUP_FLOWBASE,
		.doit	= iplb_nl_cmd_lookup_flowbase,
		.policy	= iplb_nl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
};


/********************************
 ****   init/exit module 
 ********************************/

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

	/* init timer for aging flow tuple  */
	init_timer_deferrable (&iplb_age_timer);
	iplb_age_timer.function = cleanup_flow;
	iplb_age_timer.data = 0;
	mod_timer (&iplb_age_timer, jiffies + FLOW_AGE_INTERVAL);

	printk (KERN_INFO "iplb (%s) is loaded\n", IPLB_VERSION);

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



#ifndef _LINUX_IPLB_NETLINK_H_
#define _LINUX_IPLB_NETLINK_H_


/*
 *	NETLINK_GENERIC family iplb operations
 */

#define IPLB_GENL_NAME		"iplb"
#define IPLB_GENL_VERSION	0x01


/*
 * - prefix of commands is "IPLB_CMD_" - 
 * ROUTE4_ADD		- v4pref, len : add deatination prefix
 * ROUTE6_ADD		- v6pref, len : add deatination prefix
 * ROUTE4_DELETE	- v4pref, len : delete deatination prefix
 * ROUTE6_DELETE	- v6pref, len : delete deatination prefix
 * RELAY4_ADD		- v4pref, len, rec4, (weight), (encap)
 * RELAY6_ADD		- v6pref, len, rec6, (weight), (encap)
 * RELAY4_DELETE	- v4pref, len, rec4
 * RELAY6_DELETE	- v4pref, len, rec6
 * RELAY_ENCAP_TYPE_SET	- pref, len, rec, encap
 *
 * ROUTE4_GET		- none : get routeing entry, pre, len, rec, weight
 * ROUTE6_GET		- none : get routeing entry, pre, len, rec, weight
 *
 * WEIGHT_SET		- v4/6pref, len, rec4/rec6, weight
 * SRC4_SET		- v4 addr : set tunnel src address
 * SRC6_SET		- v6 addr : set tunnel src address
 *
 * LOOKUP_WEIGHTBASE	- none : set lookup function weightbase
 * LOOKUP_HASHTBASE	- none : set lookup function hashbase
 *
 * PREFIX_FLUSH		- none : remove all prefix and relay info
 */

enum {
	IPLB_CMD_PREFIX4_ADD,
	IPLB_CMD_PREFIX6_ADD,
	IPLB_CMD_PREFIX4_DELETE,
	IPLB_CMD_PREFIX6_DELETE,
	IPLB_CMD_RELAY4_ADD,
	IPLB_CMD_RELAY6_ADD,
	IPLB_CMD_RELAY4_DELETE,
	IPLB_CMD_RELAY6_DELETE,
	IPLB_CMD_ENCAP_TYPE_SET,
	
	IPLB_CMD_PREFIX4_GET,
	IPLB_CMD_PREFIX6_GET,
	
	IPLB_CMD_WEIGHT_SET,
	IPLB_CMD_SRC4_SET,
	IPLB_CMD_SRC6_SET,

	IPLB_CMD_SRC4_GET,
	IPLB_CMD_SRC6_GET,

	IPLB_CMD_FLOW4_SET,
	IPLB_CMD_FLOW4_GET,
	IPLB_CMD_FLOW4_FLUSH,

	IPLB_CMD_LOOKUP_WEIGHTBASE,
	IPLB_CMD_LOOKUP_HASHBASE,
	IPLB_CMD_LOOKUP_FLOWBASE,

	IPLB_CMD_PREFIX4_FLUSH,
	IPLB_CMD_PREFIX6_FLUSH,

	__IPLB_CMD_MAX,
};

#define IPLB_CMD_MAX	(__IPLB_CMD_MAX - 1)


enum {
	IPLB_ENCAP_TYPE_GRE,
	IPLB_ENCAP_TYPE_IPIP,
	IPLB_ENCAP_TYPE_LSRR,

	__IPLB_ENCAP_TYPE_MAX,
};
#define IPLB_ENCAP_TYPE_MAX	(__IPLB_ENCAP_TYPE_MAX - 1)


/* ATTR types */
enum {
	IPLB_ATTR_NONE,			/* none		*/
	IPLB_ATTR_PREFIX4,		/* 32 bit	*/
	IPLB_ATTR_PREFIX6,		/* 128 bit	*/
	IPLB_ATTR_PREFIX_LENGTH,	/* 8 bit	*/
	IPLB_ATTR_RELAY,		/* binary 	*/
	IPLB_ATTR_RELAY_INDEX,		/* 8bit		*/
	IPLB_ATTR_WEIGHT,		/* 8 bit 	*/
	IPLB_ATTR_ENCAP_TYPE,		/* 8 bit	*/
	IPLB_ATTR_SRC4,			/* 3 2bit	*/
	IPLB_ATTR_SRC6,			/* 12 bit	*/
	IPLB_ATTR_STATS,		/* binary	*/
	IPLB_ATTR_FLOW4,		/* binary	*/

	__IPLB_ATTR_MAX,
};

#define IPLB_ATTR_MAX	(__IPLB_ATTR_MAX - 1)

#define IPLB_MAX_RELAY_POINTS	16


/* relay address structure  */
/* content of IPLB_ATTR_RELAY4 */
struct iplb_relay {
	__u32	relay_count;
        union {
		__be32	__relay_addr4[IPLB_MAX_RELAY_POINTS][1];
		__be32	__relay_addr6[IPLB_MAX_RELAY_POINTS][4];
	} relay_ip;     /* relay point(s) */
};
#define relay_ip4       relay_ip.__relay_addr4
#define relay_ip6       relay_ip.__relay_addr6


/* counter structure */

struct iplb_stats {
	__u32     pkt_count;
	__u32     byte_count;
};


/* flow structure */

struct iplb_flow4_info {
	int	family;

	__u8	relay_index;
	__u8	protocol;
	__u32	saddr, daddr;
	__u16	sport, dport;

	struct iplb_stats stats[3];
};

#endif /* _LINUX_IPLB_NETLINK_H_ */

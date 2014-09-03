

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
 * RELAY4_ADD		- v4pref, len, rec4 , weight: add relay point to prefix
 * RELAY6_ADD		- v6pref, len, rec6 , weight: add relay point to prefix
 * RELAY4_DELETE	- v4pref, len, rec4 : delete relay point
 * RELAY6_DELETE	- v4pref, len, rec6 : delete relay point
 *
 * ROUTE4_GET		- none : get routeing entry, pre, len, rec, weight
 * ROUTE6_GET		- none : get routeing entry, pre, len, rec, weight
 *
 * WEIGHT_SET		- v4/6pref, len, rec4/rec6, weight
 *
 * LOOKUP_WEIGHTBASE	- none : set lookup function weightbase
 * LOOKUP_HASHTBASE	- none : set lookup function hashbase
 *
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
	
	IPLB_CMD_PREFIX4_GET,
	IPLB_CMD_PREFIX6_GET,
	
	IPLB_CMD_WEIGHT_SET,

	IPLB_CMD_LOOKUP_WEIGHTBASE,
	IPLB_CMD_LOOKUP_HASHBASE,

	__IPLB_CMD_MAX,
};

#define IPLB_CMD_MAX	(__IPLB_CMD_MAX - 1)


/* ATTR types */
enum {
	IPLB_ATTR_NONE,			/* none		*/
	IPLB_ATTR_PREFIX4,		/* 32 bit	*/
	IPLB_ATTR_PREFIX6,		/* 128 bit	*/
	IPLB_ATTR_PREFIX_LENGTH,	/* 8 bit	*/
	IPLB_ATTR_RELAY4,		/* 32 bit 	*/
	IPLB_ATTR_RELAY6,		/* 128 bit	*/
	IPLB_ATTR_WEIGHT,		/* 8 bit 	*/
	__IPLB_ATTR_MAX,
};

#define IPLB_ATTR_MAX	(__IPLB_ATTR_MAX - 1)


#endif /* _LINUX_IPLB_NETLINK_H_ */

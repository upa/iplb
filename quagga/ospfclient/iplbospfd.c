/* iplb controller using ospf */

#include <zebra.h>
#include "prefix.h"	/* needed by ospf_asbr.h */
#include "privs.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_api.h"
#include "ospf_apiclient.h"

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


#define ASYNCPORT	4000

struct thread_master * master;
struct ospf_apiclient * oc;


static int
lsa_read (struct thread * thread)
{
	int fd;
	int ret;

	oc = THREAD_ARG (thread);
	fd = THREAD_FD (thread);

	ret = ospf_apiclient_handle_async (oc);
	if (ret < 0) {
		printf ("%s: ospf_apiclient_handle_async failed\n", __func__);
		exit (1);
	}

	thread_add_read (master, lsa_read, oc, fd);

	return 0;
}


/*
 * Callback functions for asyncronous events.
 */

static void
lsa_update_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated, struct lsa_header * lsa)
{
	/* update LSDB, and calculate relay points, and re-install it */
	printf ("%s\n", __func__);

	ospf_lsa_header_dump (lsa);

	return;
}

static void
lsa_delete_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated, struct lsa_header * lsa)
{
	/* update LSDB, and calculate relay points, and re-install it */
	printf ("%s\n", __func__);

	ospf_lsa_header_dump (lsa);

	return;
}


static int
usage ()
{
	printf ("usage: iplbospfd\n");
	
	return;
}

int
main (int argc, char ** argv)
{
	struct thread thread;

	if (argc < 2) {
		usage ();
		return 1;
	}

	zprivs_init (&ospfd_privs);
	master = thread_master_create ();

	oc = ospf_apiclient_connect (argv[1], ASYNCPORT);
	if (!oc) {
		printf ("Connecting to OSPF daemon of %s failed!\n", argv[1]);
		exit (1);
	}
	
	ospf_apiclient_register_callback (oc, NULL, NULL, NULL, NULL, NULL,
					  lsa_update_callback,
					  lsa_delete_callback);

	ospf_apiclient_sync_lsdb (oc);

	/* schedule thread that handles asynchronous messages */
	thread_add_read (master, lsa_read, oc, oc->fd_async);

	while (1) {
		thread_fetch (master, &thread);
		thread_call (&thread);
	}

	/* not reached */
	return 0;
}

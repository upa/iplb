
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#ifdef __linux__
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif /* linux */

#define DSTPORT		49152
#define SRCPORTRANGEMIN	49153
#define SRCPORTRANGEMAX	65534

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


int
main (int argc, char ** argv)
{
	int rc, sock, on = 1, len, port;
	char pkt[8192];
	struct sockaddr_in saddr_in;
	struct in_addr dst_addr, src_addr;

	if (argc < 4) {
		printf ("%s [SRCADDR] [DSTADDR] [LEN]\n", argv[0]);
		return -1;
	}

	memset (pkt, 1, sizeof (pkt));

	/* parse options */
	inet_pton (AF_INET, argv[1], &src_addr);
	inet_pton (AF_INET, argv[2], &dst_addr);
	len = atoi (argv[3]);

	/* create raw socket */
	if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		err (EXIT_FAILURE, "create socket failed");

	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0)
		err (EXIT_FAILURE, "failt to setsockopt HDRINCL");
	
	
	/* fill ip header */
	struct ip * ip;
	ip = (struct ip *) pkt;

	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	ip->ip_id = 0;
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = htons (len);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 16;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_dst = dst_addr;
	ip->ip_src = src_addr;
	ip->ip_sum = 0;
	ip->ip_sum = wrapsum (checksum (ip, sizeof (*ip), 0));

	/* fill udp header */
	struct udphdr * udp;
	udp = (struct udphdr *) (ip + 1);

	udp->uh_dport	= htons (DSTPORT);
	udp->uh_sport	= 0;	/* uh_sport is filled in send loop. */
	udp->uh_ulen	= htons (len - sizeof (struct ip));
	udp->uh_sum	= 0;	/* no udp checksum*/


	saddr_in.sin_addr = ip->ip_dst;
	saddr_in.sin_family = AF_INET;

	while (1) {
		for (port = SRCPORTRANGEMIN; port < SRCPORTRANGEMAX;
		     udp->uh_sport = htons (port++)) {
			rc = sendto (sock, pkt, len, 0,
				     (struct sockaddr *) &saddr_in,
				     sizeof (saddr_in));
			if (rc < 0) {
				perror ("send");
			}
		}
	}

	return 0;
}

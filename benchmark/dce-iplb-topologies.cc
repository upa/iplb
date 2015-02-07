/*
 * iplb benchmark for some topologies on ns-3-dce
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ns3/network-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/dce-module.h"
#include "ns3/point-to-point-helper.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("DceQuaggaFattree");

static void
RunIp (Ptr<Node> node, Time at, std::string str)
{
	DceApplicationHelper process;
	ApplicationContainer apps;
	process.SetBinary ("ip");
	process.SetStackSize (1 << 16);
	process.ResetArguments ();
	process.ParseArguments (str.c_str ());
	apps = process.Install (node);
	apps.Start (at);
}



/* iplb pseudo tunnel source address */
#define IPLB_TUNNELSRC	"10.0.0.1"


/* all nodes. index 0 node is not used. */
NodeContainer	nodes;


/* for link : use NDC and NC for p2p install. */
#define MAXLINK	256

#define NDC	link_ndcs[link_ndcs_index]
#define NC	link_ncs[link_ncs_index]
int link_ndcs_index = 0;
int link_ncs_index = 0;
NetDeviceContainer link_ndcs[MAXLINK];
NodeContainer link_ncs[MAXLINK];

#define INCREMENT_LINK()			\
	do {					\
		link_ndcs_index++;		\
		link_ncs_index++;		\
	} while (0)


#define MAXNODE	256
float ntime[MAXNODE]; /* ntime[Nodeid] = Seconds */
#define NODETIME(id) ntime[id]
#define INCREMENT_NODETIME(id) ntime[(id)] += 0.01


static int
strsplit(char *str, char **args, int max)
{
        int argc;
        char *c;

        for (argc = 0, c = str; *c == ' ' || *c == '\t' || *c == '\n'; c++)
                ;
        while (*c && argc < max) {
                args[argc++] = c;
                while (*c && *c > ' ')
                        c++;
                while (*c && *c <= ' ')
                        *c++ = '\0';
        }

        return argc;
}

void
topology_info (char ** args, int argc)
{
	/* create Node */

	int nodenum, linknum, clientmin, clientmax;

	nodenum = atoi (args[2]);
	linknum = atoi (args[4]);
	clientmin = atoi (args[6]);
	clientmax = atoi (args[7]);

	for (int n = 1; n <= nodenum; n++) {
		ntime[n] = 0.01;
	}

	/* create nodes */
	nodes.Create (nodenum + 1);

        DceManagerHelper processManager;
        processManager.SetNetworkStack("ns3::LinuxSocketFdFactory", "Library",
                                       StringValue ("liblinux.so"));
	processManager.Install (nodes);

	LinuxStackHelper stack;
	stack.Install (nodes);

	return;
}



void
topology_node (char ** args, int argc)
{
	/* Set up lo address and tunnel interface */
	int id;
	char * loaddr, * greto;
	std::ostringstream loset, loup;

	id = atoi (args[1]);
	loaddr = args[3];
	greto = args[5];
	
	/* set up loopback interface */
	loset << "-f inet addr add " << loaddr << " dev lo";
	RunIp (nodes.Get (id), Seconds (NODETIME (id)), loset.str());
	INCREMENT_NODETIME (id);

	loup << "link set lo up";
	RunIp (nodes.Get (id), Seconds (NODETIME (id)), loup.str());
	INCREMENT_NODETIME (id);


	/* set up gre tunnel interface */

	std::ostringstream greadd, greup;
#if 0
	greadd << "link add type gre local " << greto;
	RunIp (nodes.Get (id), Seconds (NODETIME (id)), greadd.str());
	INCREMENT_NODETIME (id);
#endif
	/* XXX: when adding new gre interface, ns3 will be crashed.
	 * existing gre0 interface can be used for iplb evaluation.
	 */
	greup << "link set dev gre0 up";
	RunIp (nodes.Get (id), Seconds (NODETIME (id)), greup.str());
	INCREMENT_NODETIME (id);


	return;
}

void
topology_link (char ** args, int argc)
{
	/* set up p2p link and its addresses */
	int id1, id2;
	char * ip1, * ip2;
	std::ostringstream id1a, id2a, id1up, id2up;

	id1 = atoi (args[1]);
	id2 = atoi (args[4]);
	ip1 = args[2];
	ip2 = args[2];

	/* set up link */
	PointToPointHelper p2p;
	
	p2p.SetDeviceAttribute ("DataRate", StringValue ("1000Mbps"));
	p2p.SetChannelAttribute ("Delay", StringValue ("0.1ms"));
	NC = NodeContainer (nodes.Get (id1), nodes.Get (id2));
	NDC = p2p.Install (NC);

	/* set up ip addresses */
	id1a << "-f inet addr add " << ip1
	     << " dev sim" << NDC.Get(0)->GetIfIndex ();
	id2a << "-f inet addr add " << ip2
	     << " dev sim" << NDC.Get(1)->GetIfIndex ();
	RunIp (nodes.Get (id1), Seconds (NODETIME (id1)), id1a.str());
	RunIp (nodes.Get (id2), Seconds (NODETIME (id2)), id2a.str());
	INCREMENT_NODETIME (id1);
	INCREMENT_NODETIME (id2);

	/* link up */
	id1up << "link set sim" << NDC.Get(0)->GetIfIndex () << " up";
	id2up << "link set sim" << NDC.Get(1)->GetIfIndex () << " up";
	RunIp (nodes.Get (id1), Seconds (NODETIME (id1)), id1up.str());
	RunIp (nodes.Get (id2), Seconds (NODETIME (id2)), id2up.str());
	INCREMENT_NODETIME (id1);
	INCREMENT_NODETIME (id2);
	
	INCREMENT_LINK ();

	return;
}

void
topology_route (char ** args, int argc)
{
	int id;
	char * prefix;
	std::ostringstream rt;

	id = atoi (args[1]);
	prefix = args[3];

	rt << "-f inet route add to " << prefix;
	for (int n = 5; n < argc; n++)
		rt << " nexthop via " << args[n];

	RunIp (nodes.Get (id), Seconds (NODETIME (id)), rt.str());
	INCREMENT_NODETIME (id);

	return;
}

void
topology_iplb (char ** args, int argc)
{
	
}

void
read_topology (void)
{
	/*
	 * createe simulator network from topology info
	 * generated by dce-topo-gen.py
	 */

	int n;
	FILE * fp;
	char config[] = "topology.conf";
	char * args[16];
	char buf[256];
	
	fp = fopen (config, "r");
	if (!fp) {
		printf ("fopen %s failed\n", config);
		exit (1);
	}

	while (fgets (buf, sizeof (buf), fp)) {

		n = strsplit (buf, args, 16);

		if (strncmp (args[0], "INFO", 4) == 0)
			topology_info (args, n);

		else if (strncmp (args[0], "NODE", 4) == 0)
			topology_node (args, n);

		else if (strncmp (args[0], "LINK", 4) == 0)
			topology_link (args, n);

		else if (strncmp (args[0], "ROUTE", 5) == 0)
			topology_route (args, n);

		else if (strncmp (args[0], "IPLB", 4) == 0)
			topology_iplb (args, n);

		else {
			printf ("invalid topology line %s\n", args[0]);
			exit (1);
		}
	}
		return;
}

int
main (int argc, char ** argv)
{
	int stoptime = 60;
	float maxnodetime = 0;

	read_topology ();

	for (int n = 0; n < MAXNODE; n++) {
		maxnodetime = (maxnodetime > NODETIME (n)) ?
			maxnodetime : NODETIME (n);
	}
	printf ("latest command time is %.2f second\n", maxnodetime);
	
	for (int n = 1; n < nodes.GetN (); n++) {
		std::ostringstream rs, as, ls;
		rs << "route show";
		as << "addr show";
		ls << "link show";
		RunIp (nodes.Get (n), Seconds (NODETIME(n)), rs.str ());
		INCREMENT_NODETIME (n);
		RunIp (nodes.Get (n), Seconds (NODETIME(n)), as.str ());
		INCREMENT_NODETIME (n);
		RunIp (nodes.Get (n), Seconds (NODETIME(n)), ls.str ());
		INCREMENT_NODETIME (n);
	}


	Simulator::Stop (Seconds (stoptime));
	Simulator::Run ();
	Simulator::Destroy ();

	return 0;
}

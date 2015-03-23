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

bool pcap_enable = false;
bool pcapall_enable = false;
std::string topology_file;

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


/* command exec time */
#define MAXNODE	256
float ntime[MAXNODE]; /* ntime[Nodeid] = Seconds */
#define NODETIME(id) ntime[id]
#define INCREMENT_NODETIME(id) ntime[(id)] += 0.01


/* client min/max */
int clientnum = 0;
int clients[MAXNODE];

bool
is_client (int id)
{
	for (int n = 0; n < clientnum; n++)
		if (clients[n] == id)
			return true;
	return false;
}

/* FLowGen related parameters */
#define LINKSPEED	"8Mbps"	/* 1000000 Byte per sec */
#define LINKBYTESPEED	1000000	/* byte per sec */
#define FLOWNUM		20
#define FLOWENCAPLEN	1000
#define FLOWLEN		(FLOWENCAPLEN - 24)	/* - (ip + gre) */
#define FLOWPPS		(LINKBYTESPEED / FLOWENCAPLEN)
#define FLOWDURATION	30              	/* sec  */
#define FLOWINTERVAL	(1 * 1000000 / FLOWPPS)	/* usec */
#define FLOWCOUNT	(FLOWPPS * FLOWDURATION)
/* link speed 8Mbps = 1000000 byte per sec.
 * 1000000(Bps) / FLOWLEN(Byte) = PPS
 * 1 / PPS = packet gap (sec), * 1000000 = packet gap (usec)
 * PPS * DURATION (sec) = number of packet
 */

#define FLOWTIME	30
#define FLOWCOUNTSTART	(FLOWTIME + FLOWNUM)
#define STOPTIME	(FLOWTIME + FLOWDURATION + 5)

/* TcpGen related parameters */
#define TCPFLOWNUM	5


static void
RunFlowgen(Ptr<Node> node, Time at, const char * dist,
	   const char *src, const char *dst)
{
	DceApplicationHelper process;
	ApplicationContainer apps;

	std::ostringstream oss;

	oss << "-s " << src << " -d " << dst << " -n " << FLOWNUM
	    << " -t " << dist
	    << " -l " << FLOWLEN << " -r -w"
	    << " -c " << FLOWCOUNT << " -i " << FLOWINTERVAL
	    << " -m " << time (NULL) + node->GetId() << "";

	printf ("Flow %s\n", oss.str().c_str());

	process.SetBinary("flowgen");
	process.SetStackSize(1 << 20);
	process.ResetArguments();
	process.ParseArguments(oss.str().c_str());
	apps = process.Install(node);
	apps.Start(at);
	//apps.Stop(Seconds (at + FLOWDURATION));
}

static void
RunTcpgen(Ptr<Node> src_node, Ptr<Node> dst_node,
	  Time recv_at, Time send_at, const char * dist,
	  const char *src, const char *dst)
{
	/* setup server */
	DceApplicationHelper recv_process;
	ApplicationContainer recv_apps;
	std::ostringstream recv_oss;

	recv_oss << "-s";
	recv_process.SetBinary ("tcpgen");
	recv_process.SetStackSize (1 << 20);
	recv_process.ResetArguments();
	recv_process.ParseArguments(recv_oss.str().c_str());
	recv_apps = recv_process.Install (dst_node);
	recv_apps.Start (recv_at);

	/* setup client */
	DceApplicationHelper send_process;
	ApplicationContainer send_apps;
	std::ostringstream send_oss;

	send_oss << "-c -d " << dst << " -B " << src
		 << " -n " << TCPFLOWNUM
		 << " -t " << dist << " -r -m "
		 << time (NULL) + src_node->GetId() << "";
	send_process.SetBinary ("tcpgen");
	send_process.SetStackSize (1 << 20);
	send_process.ResetArguments();
	send_process.ParseArguments(send_oss.str().c_str());
	send_apps = send_process.Install (src_node);
	send_apps.Start (send_at);

	printf ("%d TCPFlow %s\n", src_node->GetId(), send_oss.str().c_str());
}

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

	int nodenum, linknum;

	nodenum = atoi (args[2]);
	linknum = atoi (args[4]);

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
topology_client (char ** args, int argc)
{
	int id;

	id = atoi (args[1]);
	clients[clientnum++] = id;

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

	/* set flowbase */
	std::ostringstream flowbase;
	flowbase << "lb set lookup flowbase";
	RunIp (nodes.Get (id), Seconds (NODETIME (id)), flowbase.str());
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
	
	p2p.SetDeviceAttribute ("DataRate", StringValue (LINKSPEED));
	p2p.SetChannelAttribute ("Delay", StringValue ("0ms"));
	NC = NodeContainer (nodes.Get (id1), nodes.Get (id2));
	NDC = p2p.Install (NC);

	if (pcapall_enable)
		p2p.EnablePcapAll ("iplb");

	if (pcap_enable) {
		if (is_client (id1) || is_client (id2)) {
			p2p.EnablePcap ("iplb", NDC);
			printf ("enable pcap for link between %d and %d\n",
				id1, id2);
		}
	}

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
	/* set up a route entry */
	/* ROUTE ID cost COST to DSTPREFIX nexthop NEXTHOP */
	int id;
	char * prefix;
	std::ostringstream rt;

	id = atoi (args[1]);
	prefix = args[5];

	rt << "-f inet route add to " << prefix;
	for (int n = 7; n < argc; n++)
		rt << " nexthop via " << args[n];

	RunIp (nodes.Get (id), Seconds (NODETIME (id)), rt.str());
	INCREMENT_NODETIME (id);

	return;
}

void
topology_iplb (char ** args, int argc)
{
	/* set up a relay entry */
	int id;
	char * prefix;
	std::ostringstream rl;

	id = atoi (args[1]);
	prefix = args[3];

	rl << "lb add prefix " << prefix << " relay " << args[5];
	for (int n = 6; n < argc; n++)
		rl << "," << args[n];

	RunIp (nodes.Get (id), Seconds (NODETIME (id)), rl.str());
	INCREMENT_NODETIME (id);

	return;
}

void
topology_flowgen (char ** args, int argc)
{
	int src, dst;
	char * flowdist, * srcip, * dstip;

	flowdist = args[1];
	src = atoi (args[2]);
	dst = atoi (args[5]);
	srcip = args[3];
	dstip = args[6];

	RunFlowgen (nodes.Get (src), Seconds (FLOWTIME),
		    flowdist, srcip, dstip);

	return;
}

void
topology_tcpgen (char ** args, int argc)
{
	int src, dst;
	char * flowdist, * srcip, * dstip;

	flowdist = args[1];
	src = atoi (args[2]);
	dst = atoi (args[5]);
	srcip = args[3];
	dstip = args[6];

	RunTcpgen (nodes.Get (src), nodes.Get (dst),
		   Seconds (FLOWTIME - 1), Seconds (FLOWTIME),
		   flowdist, srcip, dstip);

	return;
}

void
read_topology (const char * config)
{
	/*
	 * createe simulator network from topology info
	 * generated by dce-topo-gen.py
	 */

	int argc;
	FILE * fp;
	char * args[16];
	char buf[256];
	
	fp = fopen (config, "r");
	if (!fp) {
		printf ("fopen %s failed\n", config);
		exit (1);
	}

	while (fgets (buf, sizeof (buf), fp)) {

		argc = strsplit (buf, args, 16);

		if (strncmp (args[0], "INFO", 4) == 0)
			topology_info (args, argc);

		else if (strncmp (args[0], "NODE", 4) == 0)
			topology_node (args, argc);

		else if (strncmp (args[0], "CLIENT", 6) == 0)
			topology_client (args, argc);

		else if (strncmp (args[0], "LINK", 4) == 0)
			topology_link (args, argc);

		else if (strncmp (args[0], "ROUTE", 5) == 0)
			topology_route (args, argc);

		else if (strncmp (args[0], "IPLB", 4) == 0)
			topology_iplb (args, argc);

		else if (strncmp (args[0], "FLOWGEN", 7) == 0)
			topology_flowgen (args, argc);
		else if (strncmp (args[0], "TCPGEN", 6) == 0)
			topology_tcpgen (args, argc);

		else {
			printf ("invalid topology line %s\n", args[0]);
		}
	}
		return;
}

/*
 * packet trace
 */

#ifdef TRACEAALL
unsigned long mactxdrop_cnt = 0;
unsigned long phytxdrop_cnt = 0;
unsigned long macrxdrop_cnt = 0;
unsigned long phyrxdrop_cnt = 0;
#endif

unsigned long mactx_cnt = 0;
unsigned long macrx_cnt = 0;
unsigned long mactx_cnt_before = 0;
unsigned long macrx_cnt_before = 0;

unsigned long mactx_byte = 0;
unsigned long macrx_byte = 0;
unsigned long mactx_byte_before = 0;
unsigned long macrx_byte_before = 0;

#ifdef TRACEALL
void
trace_mactxdrop (std::string path, Ptr<const Packet> packet)
{
        mactxdrop_cnt++;
        return;
}

void
trace_phytxdrop (std::string path, Ptr<const Packet> packet)
{
        phytxdrop_cnt++;
        return;
}

void
trace_macrxdrop (std::string path, Ptr<const Packet> packet)
{
        macrxdrop_cnt++;
        return;
}

void
trace_phyrxdrop (std::string path, Ptr<const Packet> packet)
{
        phyrxdrop_cnt++;
        return;
}
#endif /* TRACEALL */

void
trace_mactx (std::string path, Ptr<const Packet> packet)
{

        int64_t countstart = Seconds(FLOWCOUNTSTART).GetInteger();
        int64_t sim_now = Simulator::Now().GetInteger();

        if (countstart < sim_now) {
                mactx_cnt++;
		mactx_byte += packet->GetSize();
        } else {
                mactx_cnt_before++;
		mactx_byte_before += packet->GetSize();
        }
        return;
}

void
trace_macrx (std::string path, Ptr<const Packet> packet)
{

        int64_t countstart = Seconds(FLOWCOUNTSTART).GetInteger();
        int64_t sim_now = Simulator::Now().GetInteger();

        if (countstart < sim_now) {
                macrx_cnt++;
		macrx_byte += packet->GetSize();
        } else {
                macrx_cnt_before++;
		macrx_byte_before += packet->GetSize();
        }
        return;
}


int
main (int argc, char ** argv)
{

	CommandLine cmd;
	float maxnodetime = 0;
	unsigned int start, end;

	start = time (NULL);

	cmd.AddValue ("pcap", "Enable pcap for client nodes", pcap_enable);
	cmd.AddValue ("pcapall", "Enable pcap for all links", pcapall_enable);
	cmd.AddValue ("file", "Topology file", topology_file);
	cmd.Parse (argc, argv);

	printf ("topology file is %s\n", topology_file.c_str());
	read_topology (topology_file.c_str());

	for (int n = 0; n < MAXNODE; n++) {
		maxnodetime = (maxnodetime > NODETIME (n)) ?
			maxnodetime : NODETIME (n);
	}
	printf ("latest command time is %.2f second\n", maxnodetime);
	
	for (int n = 1; n < nodes.GetN (); n++) {
		std::ostringstream rs, as, ls, lb, fs;
		rs << "route show";
		as << "addr show";
		ls << "link show";
		lb << "lb show";

		RunIp (nodes.Get (n), Seconds (NODETIME(n)), rs.str ());
		INCREMENT_NODETIME (n);
		RunIp (nodes.Get (n), Seconds (NODETIME(n)), as.str ());
		INCREMENT_NODETIME (n);
		RunIp (nodes.Get (n), Seconds (NODETIME(n)), ls.str ());
		INCREMENT_NODETIME (n);
		RunIp (nodes.Get (n), Seconds (NODETIME(n)), lb.str ());
		INCREMENT_NODETIME (n);

		fs << "lb flow show detail";
		RunIp (nodes.Get (n), Seconds (FLOWCOUNTSTART), fs.str ());
	}


	/* set trace packet counters */
	for (int n = 0; n < clientnum; n++) {

		int id = clients[n];

#define TRACE(s, p) s << "/NodeList/" << nodes.Get(id)->GetId()		\
		      << "/DeviceList/"					\
		      << nodes.Get(id)->GetDevice(0)->GetIfIndex()	\
		      << "/$ns3::PointToPointNetDevice/" << p

#ifdef TRACEALL
		std::ostringstream mactx, phytx, macrx, phyrx;
                TRACE(mactx, "MacTxDrop");
		Config::Connect (mactx.str(), MakeCallback(&trace_mactxdrop));

                TRACE(phytx, "PhyTxDrop");
		Config::Connect (phytx.str(), MakeCallback(&trace_phytxdrop));

                TRACE(macrx, "MacRxDrop");
		Config::Connect (macrx.str(), MakeCallback(&trace_macrxdrop));

                TRACE(phyrx, "PhyRxDrop");
		Config::Connect (phyrx.str(), MakeCallback(&trace_phyrxdrop));
#endif /* TRACEALL */
		std::ostringstream mactxall, macrxall;
                TRACE(mactxall, "PhyTxEnd");
		Config::Connect (mactxall.str(), MakeCallback(&trace_mactx));

                TRACE(macrxall, "PhyRxEnd");
		Config::Connect (macrxall.str(), MakeCallback(&trace_macrx));
        }


	Simulator::Stop (Seconds (STOPTIME));
	Simulator::Run ();
	Simulator::Destroy ();

	printf ("\n");
	printf ("Packet Count\n");
#ifdef TRACEALL
	printf ("MacTxDrop : %lu\n"
		"PhyTxDrop : %lu\n"
		"MacRxDrop : %lu\n"
		"PhyRxDrop : %lu\n",
		mactxdrop_cnt, phytxdrop_cnt, macrxdrop_cnt, phyrxdrop_cnt);
#endif	
	printf ("PhyTx All : %lu\n"
		"PhyRx All : %lu\n"
		"PhyTx Flowgen  : %lu\n"
		"PhyRx Flowgen  : %lu\n"
		"LinkRate  : %f\n"
		"LinkAll   : %f\n",
		mactx_cnt_before + mactx_cnt,
		macrx_cnt_before + macrx_cnt,
		mactx_cnt,
		macrx_cnt,
		(float)(macrx_cnt) / (float)(mactx_cnt) * 100,
		(float)(macrx_cnt_before + macrx_cnt) /
		(float)(mactx_cnt_before + mactx_cnt) * 100);

	printf ("\n");

	printf ("PhyTxByte All : %lu\n"
		"PhyRxByte All : %lu\n"
		"PhyTxByte Flowgen : %lu\n"
		"PhyRxByte Flowgen : %lu\n"
		"ByteRate      : %f\n",
		mactx_byte_before + mactx_byte,
		macrx_byte_before + macrx_byte,
		mactx_byte,
		macrx_byte,
		(double)(macrx_byte) / (double)(mactx_byte) * 100);

	end = time (NULL);
	printf ("finish %u second\n", end - start);

	return 0;
}

#!/usr/bin/env python

import sys
import copy
import random
import operator
from optparse import OptionParser
from argparse import ArgumentParser


# 1.0.0.NodeID/32
loprefix = "1.0.0."

global linkbase
linkbase = 0

SPF_STATE_NOVISIT = 0
SPF_STATE_CANDIDATE = 1
SPF_STATE_VISITED = 2


square = {
    1 : [ 2, 3, 5 ], 2 : [ 1, 4 ], 3 : [ 1, 4 ], 4 : [ 2, 3, 6 ],
    5 : [ 1 ], 6 : [ 4 ],
    }
square_client = [ 5, 6 ]


squaretwo = {
    1 : [ 2, 3, 8 ], 2 : [ 1, 4 ], 3 : [ 1, 4 ], 4 : [ 2, 3, 5, 6 ],
    5 : [ 4, 7 ], 6 : [ 4, 7 ], 7 : [ 5, 6, 9 ],
    8 : [ 1 ], 9 : [ 7 ],
    }
squaretwo_client = [ 8, 9 ]

kpath = {
    1 : [ 2, 3 ], 2 : [ 1, 5 ], 3: [ 1, 4 ], 4 :[ 3, 5 ], 5 : [ 2, 4 ],
}
kpath_client = [1, 5]


# 3-level 4-ary fat-tree topo
# 20 switches and 16 servers
fattree = {
    1 : [ 5, 7, 9, 11], 2 : [ 5, 7, 9, 11 ],
    3 : [ 6, 8, 10, 12 ], 4 : [ 6, 8, 10, 12 ],
    5 : [ 1, 2, 13, 14 ], 6 : [ 3, 4, 13, 14 ],
    7 : [ 1, 2, 15, 16 ], 8 : [ 3, 4, 15, 16],
    9 : [ 1, 2, 17, 18], 10 : [ 3, 4, 17, 18 ],
    11 : [ 1, 2, 19, 20 ], 12 : [ 3, 4, 19, 20],
    13 : [ 5, 6, 21, 22 ], 14 : [ 5, 6, 23, 24 ],
    15 : [ 7, 8, 25, 26 ], 16 : [ 7, 8, 27, 28 ],
    17 : [ 9, 10, 29, 30 ], 18 : [ 9, 10, 31, 32 ],
    19 : [ 11, 12, 33, 34 ], 20 : [ 11, 12, 35, 36 ],

    21 : [ 13 ], 22 : [ 13 ], 23 : [ 14 ], 24 : [ 14 ],
    25 : [ 15 ], 26 : [ 15 ], 27 : [ 16 ], 28 : [ 16 ],
    29 : [ 17 ], 30 : [ 17 ], 31 : [ 18 ], 32 : [ 18 ],
    33 : [ 19 ], 34 : [ 19 ], 35 : [ 20 ], 36 : [ 20 ],
    }
fattree_client = range (21, 36 + 1)


# n = 4, k = 1 BCube
# 8 switches and 16 servers
bcube = {
    1  : [  9, 13, 17, 21 ], 2  : [ 10, 14, 18, 22 ],
    3  : [ 11, 15, 19, 23 ], 4  : [ 12, 16, 20, 24 ],
    5  : [  9, 10, 11, 12 ], 6  : [ 13, 14, 15, 16 ],
    7  : [ 17, 18, 19, 20 ], 8  : [ 21, 22, 23, 24 ],

    9  : [  1, 5, 25 ], 10 : [  2, 5, 26 ], 11 : [  3, 5, 27 ],
    12 : [  4, 5, 28 ], 13 : [  1, 6, 29 ], 14 : [  2, 6, 30 ],
    15 : [  3, 6, 31 ], 16 : [  4, 6, 32 ], 17 : [  1, 7, 33 ],
    18 : [  2, 7, 34 ], 19 : [  3, 7, 35 ], 20 : [  4, 7, 36 ],
    21 : [  1, 8, 37 ], 22 : [  2, 8, 38 ], 23 : [  3, 8, 39 ],
    24 : [  4, 8, 49],

    25 : [  9 ], 26 : [ 10 ], 27 : [ 11 ], 28 : [ 12 ],
    29 : [ 13 ], 30 : [ 14 ], 31 : [ 15 ], 32 : [ 16 ],
    33 : [ 17 ], 34 : [ 18 ], 35 : [ 19 ], 36 : [ 20 ],
    37 : [ 21 ], 38 : [ 22 ], 39 : [ 23 ], 40 : [ 24 ],
    }
bcube_client = range (25, 40 + 1)


# 2 dimension, 4 terminal per switch, 4 switch per dimension
# 8 switches and 32 servers
hyperx = {
    1 : [ 2, 3, 4, 5, 9, 10, 11, 12 ], 2 : [ 1, 3, 4, 6, 13, 14, 15, 16 ],
    3 : [ 1, 2, 4, 7, 17, 18, 19, 20 ], 4 : [ 1, 2, 3, 8, 21, 22, 23, 24 ],
    5 : [ 6, 7, 8, 1, 25, 26, 27, 28 ], 6 : [ 5, 7, 8, 2, 29, 30, 31, 32 ],
    7 : [ 5, 6, 8, 3, 33, 34, 35, 36 ], 8 : [ 5, 6, 7, 4, 37, 38, 39, 40 ],

    9 : [1], 10 : [1], 11 : [1], 12 : [1],
    13 : [2], 14 : [2], 15 : [2], 16 : [2],
    17 : [3], 18 : [3], 19 : [3], 20 : [3],
    21 : [4], 22 : [4], 23 : [4], 24 : [4],

    25 : [5], 26 : [5], 27 : [5], 28 : [5],
    29 : [6], 30 : [6], 31 : [6], 32 : [6],
    33 : [7], 34 : [7], 35 : [7], 36 : [7],
    37 : [8], 38 : [8], 39 : [8], 40 : [8],
    }
hyperx_client = range (9, 40 + 1)



def generate_random_graph () :
    # create jellyfish topology. it is regular random graph.
    # k = 4, r = 3, 1 server per 1 swtich
    # node id 1 - 16 = switch, 17 - 32 = client
    switchnum = 16
    clientnum = 16
    portnum = 4
    servernumperswitch = 1
    jellyfish = {}

    # generate server - client links
    for x in range (1, switchnum + 1) :
        jellyfish[x] = [x + switchnum]
        jellyfish[x + switchnum] = [x]

    # generate random link between switches
    links = []
    for x in range (1, switchnum + 1) :
        for linkid in range (portnum - servernumperswitch) :
            links.append ("%d %d" % (x, linkid)) # "Node Link"

    while links :
        linkstr = random.choice (links)
        links.remove (linkstr)
        id1 = int (linkstr.split (' ')[0])

        linkstr = random.choice (links)
        links.remove (linkstr)
        id2 = int (linkstr.split (' ')[0])

        jellyfish[id1].append (id2)
        jellyfish[id2].append (id1)

    return [jellyfish,
            map (lambda x: x + switchnum, range (1, clientnum + 1))]


# 16 server, 16 switch.
[jellyfish, jellyfish_client] = generate_random_graph ()



class Link () :
    def __init__ (self, id1, id2) :
        global linkbase
        self.id1 = id1
        self.id2 = id2
        self.linkbase = linkbase
        self.id1_addr = self.id2addr (self.id1, self.linkbase)
        self.id2_addr = self.id2addr (self.id2, self.linkbase)
        linkbase += 1

        return

    def __repr__(self):
        return "<Link '%d' : '%d'>" % (self.id1, self.id2)

    def id2addr (self, id, linkbase) :
        # 100.X.X.(1|2)/24
        o2 = linkbase / 256
        o3 = linkbase - (o2) * 256
        return "100.%d.%d.%d" % (o2, o3, id)

    def address (self, id) :
        if id == self.id1 :
            return self.id1_addr
        if id == self.id2 :
            return self.id2_addr
        return None

    def neighbor_id (self, id) :
        if id == self.id1 :
            return self.id2
        if id == self.id2 :
            return self.id1

        return None


class Node () :
    def __init__ (self, id) :
        self.id = id
        self.loaddr = "%s%d" % (loprefix, id)
        self.links = {} # neighbor_id : Link, neighbor_id : Link,

        # SPF calculation related
        self.spf_distance = -1
        self.spf_state = SPF_STATE_NOVISIT
        self.spf_nexthop = set ()
        self.spf_incoming = set ()
        self.spf_stacks = []
        return

    def __repr__(self):
        return "<Node : '%d' >" % self.id

    def add_link (self, link) :
        self.links[link.neighbor_id(self.id)] = link
        return

    def list_link (self) :
        li = []
        neilist = self.links.keys ()
        neilist.sort ()
        for nei in neilist :
            li.append (self.links[nei])

        return li

    def neighbor_link (self, id) :
        if not self.links.has_key (id) :
            print self + " deos not have link to %d" % id
            return None
        return self.links[id]

class Topology () :
    def __init__ (self) :
        self.nodes = {} # id: Node()
        self.links = {} # id1: id2: Link()
        self.ecmp = False
        self.iplb = False
        return

    def enable_ecmp (self) :
        self.ecmp = True
        return

    def enable_iplb (self) :
        self.iplb = True
        return

    def add_node (self, node) :
        if self.find_node (node.id) :
            print "add_node: node id %d duplicated" % node.id
            sys.exit (1)
            return
        self.nodes[node.id] = node
        return

    def add_link (self, link) :
        if not self.links.has_key (link.id1) :
            self.links[link.id1] = {}

        self.links[link.id1][link.id2] = link
        return

    def find_node (self, id) :
        if self.nodes.has_key (id) :
            return self.nodes[id]
        return None

    def find_link (self, id1, id2) :
        if self.links.has_key (id1) :
            if self.links[id1].has_key (id2) :
                return self.links[id1][id2]

        if self.links.has_key (id2) :
            if self.links[id2].has_key (id1) :
                return self.links[id2][id1]

        return None

    def list_node (self) :
        li = []
        for id in self.nodes.keys () :
            li.append (self.nodes[id])
        return li

    def list_link (self) :
        li = []
        for id1 in self.links.keys () :
            for id2 in self.links[id1].keys () :
                li.append (self.links[id1][id2])

        return li

    def read_links (self, links) :

        for id in links :
            node = Node (id)
            self.add_node (node)

            for nei in links[id] :
                link = self.find_link (id, nei)
                if not link :
                    link = Link (id, nei)
                    self.add_link (link)
                node.add_link (link)

        return

    def dump (self) :

        for node in self.list_node () :
            print "Node %2d (%s)" % (node.id, node.loaddr)

            for link in node.list_link () :
                nei = link.neighbor_id (node.id)
                print "  -> %2d : (%s -> %s)" % \
                    (nei, link.address (node.id), link.address (nei))
            print

        return

    def info_dump (self, client) :
        print "INFO nodenum %d linknum %d clientnum %d" \
            % (len (self.list_node()), linkbase, len (client))

        for c in client :
            print "CLIENT %d" % c

    def node_dump (self) :
        for node in self.list_node () :
            print "NODE %d loaddr %s/32 greto %s" % (node.id, node.loaddr,
                                                     node.loaddr)

        return

    def link_dump (self):
        for link in self.list_link () :
            print ("LINK %d %s/24 - %d %s/24" %
                   (link.id1, link.id1_addr, link.id2, link.id2_addr))

        return

    def cleanup_for_spf (self) :
        for node in self.list_node () :
            node.spf_cost = 1
            node.spf_state = SPF_STATE_NOVISIT
            node.spf_incoming.clear ()
            node.spf_nexthop.clear ()
            while node.spf_stacks :
                l = node.spf_stacks.pop ()
                del (l)

        return

    def calculate_spf_candidate_add (self, v, candidate) :

        for link in v.list_link () :
            nei = self.find_node (link.neighbor_id (v.id))

            if nei.spf_state == SPF_STATE_NOVISIT :
                # 1st visit. add to candidate
                nei.spf_cost = v.spf_cost + 1
                nei.spf_state = SPF_STATE_CANDIDATE
                nei.spf_incoming.add (v)
                candidate.append (nei)

            elif (nei.spf_state == SPF_STATE_CANDIDATE and
                  nei.spf_cost > v.spf_cost + 1) :
                # new shorter route to candidate vertex is found.
                # update cost and incoming info.
                nei.spf_cost = v.spf_cost + 1
                nei.spf_incoming.clear ()
                nei.spf_incoming.add (v)

            elif (nei.spf_state == SPF_STATE_CANDIDATE and
                  not v in nei.spf_incoming and
                  nei.spf_cost == v.spf_cost + 1) :
                # new ECMP link is found.
                nei.spf_incoming.add (v)

        return

    def check_same_vertex_on_top_of_stacks (self, incoming) :

        hash = {}
        for v in incoming :
            for stack in v.spf_stacks :
                if hash.has_key (stack[len (stack) - 1].id) :
                    return True
                hash[stack[len (stack) - 1].id] = True

        return False

    def calculate_spf_candidate_decide (self, candidate) :

        distance = -1
        next = None

        for v in candidate :
            if not next or distance < 0 :
                next = v
                distance = v.spf_cost
            elif v.spf_cost < distance :
                next = v
                distance = v.spf_cost

        if not next :
            print "candidate_decide failed"
            sys.exit (1)
            return

        """
        iplb relay point search.
        /* copy relay point stacks. */
        /* if incoming multiple incoming links exist, ECMPed vertex.
         * 1. if there is same vertex in top of multiple stacks,
              push incoming vertexes to each stacks.
         * 2. if stack of incoming vertex is null, push the incoming vertex.
         */
        """

        ecmped = False
        duplicated = False

        if len (next.spf_incoming) > 1 :
            ecmped = True
        if self.check_same_vertex_on_top_of_stacks (next.spf_incoming) :
            duplicated = True

        for v in next.spf_incoming :
            # copy stacks
            for stack in v.spf_stacks :
                copystack = copy.deepcopy (stack)

                if ecmped and duplicated :
                    # Term 1 is fulfilled. push the v to stack
                    copystack.append (v)

                next.spf_stacks.append (copystack)

            if ecmped and not v.spf_stacks :
                # Term 2 is fullfilled. push the v to stacks as new stack
                next.spf_stacks.append ([v])

        return next


    def calculate_spf (self, root) :

        self.cleanup_for_spf ()

        candidate = []
        candidate.append (root)

        while len (candidate) > 0 :

            # select shortest next vertex
            next = self.calculate_spf_candidate_decide (candidate)

            # process decided next vertex
            next.spf_state = SPF_STATE_VISITED
            candidate.remove (next)

            if not self.ecmp :
                # if ecmp disabled, one incoming having smallest id is selected
                incoming = None
                for v in next.spf_incoming :
                    if not incoming :
                        incoming = v
                    else :
                        if incoming.id > v.id :
                            incoming = v
                if incoming == root :
                    next.spf_nexthop.add (next)
                elif incoming :
                    next.spf_nexthop |= incoming.spf_nexthop
            else :
                # if ecmp enabled, all nexthops of incomings are added
                for v in next.spf_incoming :
                    if v == root :
                        next.spf_nexthop.add (next)
                    else :
                        next.spf_nexthop |= v.spf_nexthop

            # add new candidates
            self.calculate_spf_candidate_add (next, candidate)


    def spf_dump (self, root) :

        for node in self.list_node () :
            if len (node.spf_nexthop) == 0 :
                continue

            nexthops = []
            for nexthop in node.spf_nexthop :
                link = self.find_link (root.id, nexthop.id)
                nexthops.append (link.address (nexthop.id))

            print ("ROUTE %d to %s/32 nexthop %s" %
                   (root.id, node.loaddr, ' '.join (nexthops)))

        return


    def iplb_dump (self, root, client) :

        if not self.iplb :
            return

        if not root.id in client :
            return

        for node in self.list_node () :
            if not node.spf_stacks or not node.id in client :
                continue

            for stack in node.spf_stacks :
                relays = ' '.join (map (lambda x: x.loaddr, stack))
                print ("IPLB %d to %s/32 relays %s" %
                       (root.id, node.loaddr, relays))

        return


    def bench_random (self, client, flowdist) :

        candidate = copy.deepcopy (client)
        conbinations = [] # [[src, dst], [src, dst], [src, dst]]

        if len (candidate) % 2 == 1 :
            # odd number
            rem = random.choice (candidate)
            candidate.remove (rem)

        while candidate :
            src = random.choice (candidate)
            candidate.remove (src)
            dst = random.choice (candidate)
            candidate.remove (dst)
            conbinations.append ([self.find_node (src), self.find_node (dst)])

        for [src, dst] in conbinations :
            print "FLOWGEN %s %d %s -> %d %s" % (flowdist, src.id, src.loaddr,
                                                 dst.id, dst.loaddr)


def main (links, client, options) :

    topo = Topology ()
    topo.read_links (links)

    if options.ecmp :
        topo.enable_ecmp ()

    if options.iplb :
        topo.enable_iplb ()

    topo.info_dump (client)
    topo.node_dump ()
    topo.link_dump ()

    for root in topo.list_node () :

        # calculate routing table.
        topo.calculate_spf (root)
        if len (root.links.keys ()) == 1 :
            id = root.links.keys()[0]
            link = root.links[id]
            gateway = link.address (id)
            print "ROUTE %d to default nexthop %s" % (root.id, gateway)
        else :
            topo.spf_dump (root)

        # calculate iplb routing table
        if options.iplb and root.id in client :
            topo.enable_ecmp ()
            topo.calculate_spf (root)
            topo.iplb_dump (root, client)


    topo.bench_random (client, options.flowdist)

    return


if __name__ == '__main__' :

    desc = "%prog [Args] [Options]\n"
    parser = OptionParser (desc)

    parser.add_option (
        '-t', '--topology', type = "string",
        default = 'fattree',
        dest = 'topology',
        )

    parser.add_option (
        '-e', '--ecmp', action = 'store_true', default = False,
        dest = 'ecmp'
        )

    parser.add_option (
        '-i', '--iplb', action = 'store_true', default = False,
        dest = 'iplb'
        )

    parser.add_option (
        '-f', '--flowdist', type = "string",
        default = 'same', dest = 'flowdist',
        )

    parser.add_option (
        '-k', '--k-shortestpath', type = "int",
        default = 1, dest = 'k_shortestpath',
        )


    (options, args) = parser.parse_args ()


    if options.topology == 'fattree' :
        links = fattree
        client = fattree_client
    elif options.topology == 'bcube' :
        links = bcube
        client = bcube_client
    elif options.topology == 'hyperx' :
        links = hyperx
        client = hyperx_client
    elif options.topology == 'jellyfish' :
        links = jellyfish
        client = jellyfish_client
    elif options.topology == 'square' :
        links = square
        client = square_client
    elif options.topology == 'squaretwo' :
        links = squaretwo
        client = squaretwo_client
    elif options.topology == 'kpath' :
        links = kpath
        client = kpath_client
    else :
        print "invalid topology type"

    main (links, client, options)

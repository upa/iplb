#!/usr/bin/env python

import sys
import copy
import time
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
    24 : [  4, 8, 40 ],

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

# 4-port clos topology
#
clos = {
    1 : [ 3, 4, 7, 8 ], 2: [ 3, 4, 7, 8 ],
    
    3 : [ 1, 2, 5, 6 ], 4: [ 1, 2, 5, 6 ],
    5 : [ 3, 4, 11, 12 ], 6 : [ 3, 4, 13, 14],

    7 : [ 1, 2, 9, 10 ], 8 : [ 1, 2, 9, 10 ],
    9 : [ 7, 8, 15 ,16 ], 10 : [ 7, 8, 17, 18 ],

    11 : [ 5 ], 12 : [ 5 ], 13 : [ 6 ], 14 : [ 6 ],
    15 : [ 9 ], 16 : [ 9 ], 17 : [ 10 ], 18 : [ 10 ],
    }
clos_client = range (11, 18 + 1)


def generate_random_graph () :
    # create jellyfish topology. it is regular random graph.
    # k = 4, r = 3, 1 server per 1 swtich
    # node id 1 - 16 = switch, 17 - 32 = client

    # k = 4, r = 3, 2 server per 1 switch,
    switchnum = 20
    clientnum = 16
    portnum = 4
    servernumperswitch = 2
    jellyfish = {}

    clientindex = 1 + switchnum

    # generate server - client links
    for x in range (1, switchnum + 1) :
        jellyfish[x] = []

    for x in range (1, clientnum / servernumperswitch + 1) :
        for y in range (servernumperswitch) :
            jellyfish[x].append (clientindex)
            jellyfish[clientindex] = [x]
            clientindex += 1


    # generate random link between switches
    links = []
    for x in range (1, switchnum + 1) :
        rlinknum = portnum - len (jellyfish[x])
        for linkid in range (rlinknum) :
            links.append ("%d %d" % (x, linkid)) # "Node Link"

    no_link = False

    while links :
        linkstr = random.choice (links)
        id1 = int (linkstr.split (' ')[0])
        links.remove (linkstr)

        tmplinks = copy.deepcopy (links)

        while True :
            if not tmplinks :
                # there is no suitable link
                no_link = True
                break

            linkstr = random.choice (tmplinks)
            id2 = int (linkstr.split (' ')[0])
            if id2 in jellyfish[id1] :
                # this link already exist
                tmplinks.remove (linkstr)
                continue
            links.remove (linkstr)
            break

        if no_link :
            break

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
        if isinstance (id, str) :
            [depth, node_id] = map (lambda x: int (x), id.split (' '))
            self.loaddr = "%s%d" % (loprefix, node_id)
        else :
            self.loaddr = "%s%d" % (loprefix, id)
        self.links = {} # neighbor_id : Link, neighbor_id : Link,

        # SPF calculation related
        self.spf_distance = -1
        self.spf_state = SPF_STATE_NOVISIT
        self.spf_nexthop = set ()
        self.spf_incoming = set ()
        self.spf_stacks = []

        # IPLB relay point calculation
        self.iplb_checked = False

        # kspf calculation related
        self.deviation_node = False
        self.spf_outgoing = set ()

        return

    def __repr__(self):
        if isinstance (self.id, int) :
            return "<Node : '%d' >" % self.id
        elif isinstance (self.id, str) :
            return "<Node : '%s' >" % self.id
        else :
            return "<Node : invalidinstance >"

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

class KspfPath () :
    def __init__ (self, path) :
        self.path = path
        self.destination = path[len (path) - 1]
        self.deviation_vertex = self.path[0]
        self.deviation_vertex_index = 0
        self.deviation_links = []

        return

    def __repr__(self):
        return "<KspfPath : '%s' >" % map (lambda x: x.id, self.path)

    def next_deviation_vertex (self) :

        self.deviation_vertex_index += 1

        if self.deviation_vertex_index == len (self.path) - 1:
            # destination can not be deviation vertex
            return False

        self.deviation_vertex = self.path[self.deviation_vertex_index]

        return True

    def set_deviation_vertex (self, v) :

        if not v in self.path :
            print "set_deviation_vertex failed. invalid deviation vertex"
            sys.exit (1)
            return

        self.deviation_vertex = v
        for n in range (len (self.path) - 1) :
            if self.path[n] == v :
                self.deviation_vertex_index = n
        return

    def next_of_vertex (self, v) :

        if not v in self.path :
            print "next_of_deviation_vertex failed. invalid deviation vertex"
            sys.exit (1)
            return

        for n in range (len (self.path) - 1) :
            if self.path[n] == v :
                return self.path[n + 1]

        return None

    def extract_route (self, i) :
        # extract rute from src to i
        route = []
        for v in self.path :
            route.append (v)
            if v == i :
                break

        return route


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

            node.iplb_checked = False

        return

    def cleanup_for_iplb (self) :

        for node in self.list_node () :
            while node.spf_stacks :
                l = node.spf_stacks.pop ()
                del (l)

            node.iplb_checked = False
        return

    def calculate_spf_candidate_add (self, v, candidate) :

        for link in v.list_link () :

            # check for kspf dijkstra
            nei = self.find_node (link.neighbor_id (v.id))

            if nei.deviation_node :
                continue

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

        return

    def extract_spf_route (self, root, dest) :

        v = dest
        route = [v]

        while v != root :
            before = None
            for incoming in v.spf_incoming :
                if not before or incoming.id < before.id :
                    before = incoming

            if not before :
                # there is no complete route.
                return False

            route.insert (0, before)
            v = before

        return route

    def create_deviation_path (self, i, kpath) :

        src = i
        dst = kpath.destination

        kpath_next = kpath.next_of_vertex (src)
        kpath.deviation_links.append (self.find_link (src.id, kpath_next.id))

        # set up s-i nodes lock
        self.cleanup_for_kspf ()
        for v in kpath.path :
            v.deviation_node = True
            if v == src :
                break

        # choice next of current deviation

        pathid = False
        for link in src.list_link () :
            #print "try link %d" % src.id, link
            is_deviated = False

            if self.find_node (link.neighbor_id (src.id)) in kpath.path :
                #print "    in kpath"
                is_deviated = True

            if link in kpath.deviation_links :
                #print "    in deviation_links"
                is_deviated = True

            if is_deviated :
                continue

            next = self.find_node (link.neighbor_id (src.id))

            self.calculate_spf (next)
            pathid = self.extract_spf_route (next, dst)

            if not pathid :
                kpath.deviation_links.append (link)
                continue
            else :
                break

        if not pathid :
            return None

        pathsi = kpath.extract_route (src)
        pathsi.extend (pathid)

        kipath = KspfPath (pathsi)

        # mark new deviation_link
        link = self.find_link (src.id, next.id)
        kpath.deviation_links.append (link)
        #kipath.deviation_links = kpath.deviation_links
        kipath.deviation_links.append (link)

        kipath.set_deviation_vertex (src)

        return kipath

    def find_min_kpath (self, clist) :

        minpath = None

        for kpath in clist :
            if not minpath or len (kpath.path) < len (minpath.path) :
                minpath = kpath

        if not minpath :
            return False

        clist.remove (minpath)

        return minpath


    def calculate_kspf (self, root, dest, k) :

        def check_same_kpath (klist, kpath) :
            for kp in klist :
                if str (kp) == str (kpath) :
                    return True
            return False



        klist = []
        clist = []
        self.calculate_spf (root)

        shortest_path = self.extract_spf_route (root, dest)
        if not shortest_path :
            print >> sys.stderr, "%d to %d route does not exist"  % \
                (root.id, dest.id)
            return
        kpath = KspfPath (shortest_path)

        klist.append (kpath)

        while len (klist) < k :

            #print "MOTO ", kpath
            #print "MOTO dev", kpath.deviation_links
            for n in range (len (kpath.path) - 1) :

                i = kpath.deviation_vertex

                # create_deviation_path set up kipath.deviation_vertex and
                # kipath.deviation_links
                kipath = self.create_deviation_path (i, kpath)
                #if kipath :
                    #print "kipath", kipath

                if (kipath
                    and not check_same_kpath (clist, kipath)
                    and not check_same_kpath (klist, kipath)):
                    clist.append (kipath)

                if not kpath.next_deviation_vertex () :
                    break

            kpath = self.find_min_kpath (clist)
            if not kpath :
                break

            if not check_same_kpath (klist, kpath) :
                klist.append (kpath)

        #print >> sys.stderr, "calculated k-shortestpaths "
        #print >> sys.stderr, '\n'.join (map (lambda x: str (x), klist))
        return klist

    def cleanup_for_kspf (self) :
        for link in self.list_link () :
            link.deviation_link = False
        self.cleanup_for_kspf_node_only ()
        return

    def cleanup_for_kspf_node_only (self) :
        for node in self.list_node () :
            node.deviation_node = False
        return

    def check_ecmped_vertex (self, vertex) :
        if len (vertex.spf_incoming) > 1 :
            return True
        return False

    def check_same_vertex_on_stacks (self, vertex) :

        incoming = vertex.spf_incoming

        hash = {}
        for v in incoming :
            for stack in v.spf_stacks :
                if hash.has_key (stack[len (stack) - 1].id) :
                    return True
                hash[stack[len (stack) - 1].id] = True

        return False

    def calculate_iplb_relay (self, dest_id) :
        """
        iplb relay point search.
        /* copy relay point stacks. */
        /* if incoming multiple incoming links exist, ECMPed vertex.
         * 1. if there is same vertex in top of multiple stacks,
              push incoming vertexes to each stacks.
         * 2. if stack of incoming vertex is null, push the incoming vertex.
         */

        iplb relay point is calculated recursively from destination vertex.
        function check_iplb_vertex (V)
        1. check incoming vretexes of V
        for Vi in incoming vertexes do
            if Vi is not checkd then
                check_iplb_vertex (Vi)

        duplicated = check_same_vertex_on_top_of_stacks ()

        if V has multiple incoming vertexes then
            for Vi in incoming vertexes do
                copy stacks of incoming vertexes to V
                if the stack is null or duplicated is true then
                    push Vi to stack
        """

        dest = self.find_node (dest_id)

        def check_iplb_vertex (v) :

            for incoming in v.spf_incoming :
                if not incoming.iplb_checked :
                    check_iplb_vertex (incoming)

            ecmped = self.check_ecmped_vertex (v)
            duplicated = self.check_same_vertex_on_stacks (v)

            for incoming in v.spf_incoming :
                # copy stacks
                for stack in incoming.spf_stacks :
                    copystack = copy.deepcopy (stack)

                    if ecmped and duplicated :
                        # term 1 is fullfilled. puth the incoming to stack
                        copystack.append (incoming)

                    v.spf_stacks.append (copystack)

                if ecmped and not incoming.spf_stacks :
                    # term 2 is fullfilled. push v to stacks
                    v.spf_stacks.append ([incoming])

            v.iplb_checked = True

            return

        check_iplb_vertex (dest)
        return


    def spf_dump (self, root) :

        for node in self.list_node () :
            if len (node.spf_nexthop) == 0 :
                continue

            nexthops = []
            for nexthop in node.spf_nexthop :
                link = self.find_link (root.id, nexthop.id)
                nexthops.append (link.address (nexthop.id))

            print ("ROUTE %d cost %d to %s/32 nexthop %s" %
                   (root.id, node.spf_cost, node.loaddr, ' '.join (nexthops)))

        return


    def iplb_dump (self, root, client) :

        if not self.iplb :
            return

        node = self.find_node (client)
        if not node.spf_stacks :
            return

        for stack in node.spf_stacks :
            relays = ' '.join (map (lambda x: x.loaddr, stack))
            print ("IPLB %d to %s/32 relays %s" %
                   (root.id, node.loaddr, relays))

        return


    def bench_random (self, client, flowdist, tool = "FLOWGEN") :

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
            print "%s %s %d %s -> %d %s" % (tool, flowdist, src.id, src.loaddr,
                                            dst.id, dst.loaddr)


def create_dag_topo_from_kspfs (kspfs) :

    topo = Topology ()

    # create node
    for kspf in kspfs :
        depth = 0
        for node in kspf.path :
            node_id = "%d %d" % (depth, node.id)
            if not topo.find_node (node_id) :
                nnode = Node (node_id)
                topo.add_node (nnode)
            depth += 1

    # create link. calculate_iplb_relay only check node.spf_incoming only.
    # Link is not considered.
    for kspf in kspfs :
        for n in range (len (kspf.path) - 1) :
            src_id = "%d %d" % (n, kspf.path[n].id)
            dst_id = "%d %d" % (n + 1, kspf.path[n + 1].id)
            src = topo.find_node (src_id)
            dst = topo.find_node (dst_id)

            if not dst in src.spf_outgoing :
                src.spf_outgoing.add (dst)

    return topo

def dump_kspf_topo_iplb (topo, root) :


    root_id = "%d %d" % (0, root)
    rootnode = topo.find_node (root_id)

    def dpfsearch (v, stack, root, is_multi) :
        #print v.id
        #time.sleep (1)
        if len (v.spf_outgoing) == 0 :
            # bottom
            if stack :
                relays = ' '.join (stack)
                print "IPLB %d to %s/32 relays %s" % (root, v.loaddr, relays)
            return

        if is_multi :
            stack.append (v.loaddr)

        for outgoing in v.spf_outgoing :
            if len (v.spf_outgoing) > 1 :
                dpfsearch (outgoing, copy.deepcopy (stack), root, True)
            else :
                dpfsearch (outgoing, copy.deepcopy (stack), root, False)

        return

    stack = []
    dpfsearch (rootnode, stack, root, False)
    return


def main (links, clients, options) :

    topo = Topology ()
    topo.read_links (links)

    if options.ecmp :
        topo.enable_ecmp ()

    if options.iplb :
        topo.enable_iplb ()

    topo.info_dump (clients)
    topo.node_dump ()
    topo.link_dump ()

    for root in topo.list_node () :

        # calculate routing table.
        topo.calculate_spf (root)
        if len (root.links.keys ()) == 1 :
            id = root.links.keys()[0]
            link = root.links[id]
            gateway = link.address (id)
            print "ROUTE %d cost 1 to default nexthop %s" % (root.id, gateway)
        else :
            topo.spf_dump (root)

        # calculate iplb routing table
        if options.iplb and root.id in clients :
            for client in clients :
                if client == root.id :
                    continue

                if options.k_shortestpath :
                    kspfs = topo.calculate_kspf (root, topo.find_node (client),
                                                 options.k_shortestpath)

                    ktopo = create_dag_topo_from_kspfs (kspfs)
                    dump_kspf_topo_iplb (ktopo, root.id)

                    topo.cleanup_for_kspf ()

                else :
                    topo.calculate_iplb_relay (client)
                    topo.iplb_dump (root, client)
                    topo.cleanup_for_iplb ()


    if options.tcp :
        topo.bench_random (clients, options.flowdist, "TCPGEN")
    else :
        topo.bench_random (clients, options.flowdist, "FLOWGEN")

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
        default = 0, dest = 'k_shortestpath',
        )

    parser.add_option (
        '-p', '--tcp', action = 'store_true', default = False,
        dest = 'tcp'
        )


    (options, args) = parser.parse_args ()


    if options.topology == 'fattree' :
        links = fattree
        clients = fattree_client
    if options.topology == 'clos' :
        links = clos
        clients = clos_client
    elif options.topology == 'bcube' :
        links = bcube
        clients = bcube_client
    elif options.topology == 'hyperx' :
        links = hyperx
        clients = hyperx_client
    elif options.topology == 'jellyfish' :
        links = jellyfish
        clients = jellyfish_client
    elif options.topology == 'square' :
        links = square
        clients = square_client
    elif options.topology == 'squaretwo' :
        links = squaretwo
        clients = squaretwo_client
    elif options.topology == 'kpath' :
        links = kpath
        clients = kpath_client
    else :
        print "invalid topology type"

    main (links, clients, options)

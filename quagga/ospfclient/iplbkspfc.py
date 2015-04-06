#!/usr/bin/env python

import sys
import copy
import time
import random
import operator
import commands
from optparse import OptionParser
from argparse import ArgumentParser


# 1.0.0.NodeID/32
loprefix = "1.0.0."

global linkbase
linkbase = 0

KNUM = 4
IP = "/sbin/ip"

SPF_STATE_NOVISIT = 0
SPF_STATE_CANDIDATE = 1
SPF_STATE_VISITED = 2



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
    def __init__ (self, id, loaddr = None, stubs = None) :
        self.id = id
        if isinstance (id, str) :
            [depth, node_id] = map (lambda x: int (x), id.split (' '))
            self.loaddr = "%s%d" % (loprefix, node_id)
        else :
            self.loaddr = "%s%d" % (loprefix, id)
        self.links = {} # neighbor_id : Link, neighbor_id : Link,

        if loaddr :
            self.loaddr = loaddr

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

        # iplbkspfc only
        if stubs :
            self.stubs = stubs
        else :
            self.sutbs = []

        return

    def __repr__(self):
        if isinstance (self.id, int) :
            return "<Node : '%d' '%s' >" % (self.id, self.loaddr)
        elif isinstance (self.id, str) :
            return "<Node : '%s' '%s' >" % (self.id, self.loaddr)
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

    def setloaddr (self, loaddr) :
        self.loaddr = loaddr
        return

    def setstubnetworks (self, stubs) :
        self.stubs = stubs
        return

class KspfPath () :
    def __init__ (self, path) :
        self.path = path
        self.destination = path[len (path) - 1]
        self.deviation_vertex = self.path[0]
        self.deviation_vertex_index = 0
        self.deviation_links = []

        return

    def __repr__(self):

        return "<KspfPath : '%s' >" % map (str, self.path)

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

    def read_kspfd_output (self, output) :

        routers = {} # loaddr : id
        links = [] # [ [src_id, dst_id] ]

        idcount = 1

        f = open (output, 'r') 
        for line in f :
            line = line.strip ()
            s = line.split (' ')
            if s[0] == "ROUTER" :
                # process ROUTER lins
                node = Node (idcount)
                node.setloaddr (s[1])
                node.setstubnetworks (s[3:])

                routers[s[1]] = idcount
                self.add_node (node)
                idcount += 1

            elif s[0] == "NETWORK" :

                src_id = routers[s[1]]
                dst_id = routers[s[2]]
                
                if (not self.find_node (src_id) or
                    not self.find_node (dst_id)) :
                    continue

                link = self.find_link (src_id, dst_id)
                if not link :
                    link = Link (src_id, dst_id)
                    self.add_link (link)

                    src_node = self.find_node (src_id)
                    src_node.add_link (link)

                    dst_node = self.find_node (dst_id)
                    dst_node.add_link (link)
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

        random.seed (BENCH_SEED)

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

    def bench_all_random (self, client, flowdist, tool = "FLOWGEN") :

        send_candidate = copy.deepcopy (client)
        recv_candidate = copy.deepcopy (client)
        conbinations = [] # [[src, dst], [src, dst], [src, dst]]

        random.seed (BENCH_SEED)

        while send_candidate :
            src = random.choice (send_candidate)
            dst = random.choice (recv_candidate)
            while src == dst :
                dst = random.choice (recv_candidate)
            send_candidate.remove (src)
            recv_candidate.remove (dst)

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
                nnode = Node (node_id, loaddr = node.loaddr,
                              stubs = node.stubs)
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


def dump_kspf_topo_iplb_kspfc (topo, root) :

    root_id = "%d %d" % (0, root)
    rootnode = topo.find_node (root_id)

    cmd_stack = []

    def dpfsearch (v, stack, root, is_multi) :
        #print v.id
        #time.sleep (1)
        if len (v.spf_outgoing) == 0 :
            # bottom
            if stack :
                for stub in v.stubs :
                    relays = ','.join (stack)
                    cmd_stack.append ("%s lb add prefix %s relay %s"
                                      % (IP, stub, relays))
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
    return cmd_stack


def main (output, ownaddr, knum) :

    cmd_stack = []

    topo = Topology ()
    topo.read_kspfd_output (output)

    # find root node
    root = None
    for node in topo.list_node () :
        if node.loaddr == ownaddr :
            #print >> sys.stderr, "root is %s" % node
            root = node
            break
    if not root :
        print "root node does not exist on LSDB"
        return
    

    # calculate iplb routing table
    for client in topo.list_node () :
        if client == root :
            continue

        kspfs = topo.calculate_kspf (root, client, knum)

        ktopo = create_dag_topo_from_kspfs (kspfs)
        cmd_stack += dump_kspf_topo_iplb_kspfc (ktopo, root.id)

        topo.cleanup_for_kspf ()

    print "\n".join (cmd_stack)

    print "flush all prefixes"
    commands.getoutput ("%s lb flush" % IP)

    print "exec above commands"
    for cmd in cmd_stack :
        commands.getoutput (cmd)

    return


if __name__ == '__main__' :

    # iplbkspfc.py [outputfile] [won addr]

    if len (sys.argv) < 3 :
        print "%s [outputfile] [own addr]" % sys.argv[0]
        sys.exit (1)

    output = sys.argv[1]
    ownaddr = sys.argv[2]

    main (output, ownaddr, KNUM)


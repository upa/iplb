#!/usr/bin/env python

import sys
import operator

# 1.0.0.NodeID/32
loprefix = "1.0.0."

global linkbase
linkbase = 0

SPF_STATE_NOVISIT = 0
SPF_STATE_CANDIDATE = 1
SPF_STATE_VISITED = 2

#links
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



class Link () :
    def __init__ (self, id1, id2) :
        global linkbase
        self.id1 = id1
        self.id2 = id2
        self.linkbase = linkbase
        self.id1_addr = self.id2addr (self.id1, self.linkbase)
        self.id2_addr = self.id2addr (self.id2, self.linkbase)
        linkbase += 1

        # spf calculation related
        self.spf_state = SPF_STATE_NOVISITED

        return

    def id2addr (self, id, linkbase) :
        # 2.X.X.(1|2)/24
        o2 = linkbase / 256
        o3 = linkbase - (o2) * 256
        return "2.%d.%d.%d/24" % (o2, o3, id)

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
        self.loaddr = "%s%d/32" % (loprefix, id)
        self.links = {} # neighbor_id : Link, neighbor_id : Link,

        # SPF calculation related
        self.spf_distance = -1
        self.spf_state = SPF_STATE_NOVIST
        self.spf_nexthop = None
        return

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
        

class Topology () :
    def __init__ (self) :
        self.nodes = {} # id: Node()
        self.links = {} # id1: id2: Link()
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
            for id2 in self.links[id].keys () :
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

    def cleanup_for_spf (self) :
        for node in self.list_node () :
            node->spf_cost = 1
            node->spf_state = SPF_STATE_NOVIST

        for link in self.list_link () :
            link->spf_state = SPF_STATE_NOVIST

    def calculate_spf (self, root) :

        candidate = []
        candidate_append (root)

        while len (candidate) > 0 :

            # select a vertex to be decided
            next = None
            distance = -1
            for v in candidate :
                if not next or distance < 0 :
                    next = v
                    distance = root->spf_cost
                else if next->spf_cost < distance :
                    next = v

            if not next :
                print "calculate_spf failed: no next vertex on candidates"
                sys.exit (1)
                return

            # process decided next vertex
            next->spf_state = SPF_STATE_VISITED
            candidate.remove (next)


            # add new candidates
            



def main () :

    topo = Topology ()
    topo.read_links (fattree)

    topo.dump ()

    return



main ()

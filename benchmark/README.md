
iplb evaluation on ns-3-dce
---------------------------

1. git clone https://github.com/upa/net-next-nuse.git
2. cd net-next-nuse
3. build net-next-nuse
  * enable CONFIG_IPLB and CONFIG_IP_ROUTE_MULTIPATH_HASHONLY.
  * make defconfig ARCH=lib OPT=no
  * make library ARCH=lib OPT=no
4. cd arch/lib/test && make testbin
5. cd arch/lib/test/buildtop/source/ns-3-dce
6. ln -s path-to/iplb/benchmark/dce-iplb-topologies.cc examples/
7. apply ns-3-dce-wscript.patch
8. generate topology info using dce-topo-gen.py
9. ./waf --run dce-iplb-topologies

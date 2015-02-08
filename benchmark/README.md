
iplb evaluation on ns-3-dce
---------------------------

1. git clone -b iplb https://github.com/upa/net-next-nuse.git
  * this branch contains iplb module and little change for multipath related codes to emulate commodity hardware routers.
2. cd net-next-nuse
3. build net-next-nuse
  * enable CONFIG_IPLB and CONFIG_IP_ROUTE_MULTIPATH_HASHONLY
  * make defconfig ARCH=lib OPT=no
  * make library ARCH=lib OPT=no
4. make -C arch/lib/test testbin
  * many packages are required by dce
5. cd arch/lib/test/buildtop/source/ns-3-dce
6. ln -s path-to/iplb/benchmark/dce-iplb-benchmark.cc examples/
7. add flowgen to dce binary.
  * git clone https://github.com/upa/flowgen.git
  * cd flowgen && make DCE=yes
  * cp flowgen path-to/net-next-nuse/arch/lib/test/buildtop/build/sbin/
8. apply ns-3-dce-wscript.patch
9. generate topology info using dce-topo-gen.py
  * ex) dce-topo-gen.py -t fattree --iplb --flowdist power > fattree.conf
10. ./waf --run "dce-iplb-benchmark --file=fatree.conf"


iplb evaluation on ns-3-dce
---------------------------

1. git clone https://github.com/upa/iplb.git

2. git clone -b iplb https://github.com/upa/net-next-nuse.git
  * this branch contains iplb module and little change for multipath related codes to emulate commodity hardware routers.

3. cd net-next-nuse

4. build net-next-nuse
  * enable CONFIG_IPLB and CONFIG_IP_ROUTE_MULTIPATH_HASHONLY for liblinux
  * make defconfig ARCH=lib OPT=no
  * make library ARCH=lib OPT=no

5. make -C arch/lib/test testbin
  * many packages are required by dce

6. cd arch/lib/test/buildtop/source/ns-3-dce

7. ln -s path-to/iplb/benchmark/dce-iplb-benchmark.cc examples/

8. apply iplb/benchmark/ns-3-dce-wscript.patch to wscript

9. add flowgen (traffic generator) to dce binary directory.
  * git clone https://github.com/upa/flowgen.git
  * cd flowgen && make DCE=yes
  * cp flowgen path-to/net-next-nuse/arch/lib/test/buildtop/build/sbin/

10. add iplb capable iproute2 package
  * cd iplb/iproute2-3.12.0
  * ./configure (requires libdb-dev, xtables-addons-source, flex and bison)
  * make CCOPTS+=-fpic CCOPTS+=-D_GNU_SOURCE CCOPTS+=-O0 CCOPTS+=-U_FORTIFY_SOURCE CCOPTS+=-g LDFLAGS=-pie LDFLAGS+=-rdynamic
  * cp ip/ip path-to/net-next-nuse/arch/lib/test/buildtop/build/sbin/

11. generate topology info using dce-topo-gen.py
  * ex) dce-topo-gen.py -t fattree --iplb --flowdist power > fattree.conf

12. ./waf --run "dce-iplb-benchmark --file=fatree.conf"



yum install -y kernel-devel
yum install -y elfutils-libelf-devel
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/kernel
make
make install

insmod ./pf_ring.ko min_num_slots=2000000

yum install -y bison flex

cd PF_RING/userland/lib
./configure && make
make install
cd ../libpcap
./configure && make
make install
## How to
The DPDK example implementation is based on MoonGen and hence it needs to be compiled first.
The measurements for the publication were created using the [combined example implementation](../../MoonGen/examples/dut-delay.lua),
which combines the traffic generation and capturing with the GTP processing.
The combined example needs to be run with the extra `--test-dev` argument
```
sudo MoonGen/build/MoonGen MoonGen/examples/dut-delay.lua <tx_port> <num_pkts> <pkt_rate> <pkt_size> <pre_cap_port> <post_cap_port> --infile /tmp/pre.pcap --outfile /tmp/post.pcap --test-dev <in_dut_port> <out_dut_port>
```
e.g.
```
sudo MoonGen/build/MoonGen MoonGen/examples/dut-delay.lua 4 1000 100 1280 3 2 --infile /tmp/in.1280.100.pcap --outfile /tmp/out.1280.100.pcap --test-dev
```
The [standalone example](dpdk-dut.lua), which can be run on a separated DUT, is executed in the following way:
```
sudo MoonGen/build/MoonGen MoonGen/examples/dpdk-dut.lua <in_port> <out_port> <pkt_size>
```
e.g.
```
sudo MoonGen/build/MoonGen MoonGen/examples/dpdk-dut.lua 1 0 128
```
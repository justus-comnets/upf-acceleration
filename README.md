[Comparison of UPF acceleration technologies
and their tail-latency for URLLC]()
---
This repository contains the source code used for measurements, data analysis, and plot generation for the paper [Comparison of UPF acceleration technologies
and their tail-latency for URLLC]().

## Content
* [MoonGen](MoonGen/) contains a **_copy_**  (not a fork, sorry) of the original [MoonGen Repository](https://github.com/emmericp/MoonGen) 
by Paul Emmerich ([Commit b11da03](https://github.com/emmericp/MoonGen/commit/b11da03004ab08e1c12fe3c2b51d6417553b9fbc))
with some modifications. TODO: Replace with fork.
* [plots](plots/) contains plot scripts for paper. Some plots need adaption of value ranges etc.
* [duts](duts/) contains our example implementations of GTP processing with P4 and DPDK.
  * [p4](duts/p4) contains P4 code and already compiled Bitfile.
  * [dpdk](duts/dpdk) contains standalone MoonGen script.
* [logs](logs/) contains measurement traces (during review only subset, because of limited storage).

## How to
### Measurement
The MoonGen measurement script is executed in the following way:
```
sudo MoonGen/build/MoonGen MoonGen/examples/dut-delay.lua <tx_port> <num_pkts> <pkt_rate> <pkt_size> <pre_cap_port> <post_cap_port> --infile /tmp/pre.pcap --outfile /tmp/post.pcap
```
e.g. with filled in parameters:
```
$ sudo ./MoonGen/build/MoonGen ./MoonGen/examples/dut-delay.lua 4 1000 100 1280 3 2 --infile /tmp/in.1280.100.pcap --outfile /tmp/out.1280.100.pcap
```

### PCAP processing

For processing the PCAPs multiple scripts are provided:
* [pcap_parser.py](pcap_parser.py) which implements the basic PCAP parsing
```
$ python3.8 pcap_parser.py --type owdelay --files /tmp/128.10000.core.pcap --show --save-pickle
```
* [process_pcaps.py](process_pcaps.py) processes multiple PCAPs at once using multiprocessing
```
$ python3.8 process_pcaps.py logs/dpdk/download logs/dpdk/download
```
other helper scripts such as:
* [filter.py](filter.py) to filter out any packets which are not related to the measurement.
* [merger_pcaps.py](merge_pcaps.py) to merge the ingress and egress capture files into a single one.

### Plot generation

Plots can be generated with [plot.py](plots/plot.py)
```
$ python3.8 plots/dut_delay.py --logdirs logs/xdp/download --core Nokia --plot-type rates --filter 128. --paper --show --save /tmp/xdp_rates.pdf
```


## How to
Please follow the [Workflow Steps](https://github.com/NetFPGA/P4-NetFPGA-public/wiki/Workflow-Overview#workflow-steps)
of the official [P4-NetFPGA-public repository](https://github.com/NetFPGA/P4-NetFPGA-public) to compile and flash the bitfile.
The compilation of the bitfile is explained at step 10., whereby the here provided [P4 file](GTP_en_decode.p4) needs to be placed in `$P4_PROJECT_DIR/src`.
Alternatively, our here provided [bitfile](GTP_en_decode.bit) can be directly flashed on the NetFPGA-SUME, as described in step 12.

### Setup GTP processing
Before the NetFPGA processes any packets, it needs to be configured.
For that, go to the `$P4_PROJECT_DIR/sw/CLI` directory and run the `P4_SWITCH_CLI.py` script.
Inside the CLI the following commands can be used enable the GTP encapsulation
```
table_cam_add_entry ipv4_encap gtpu_encap_v4 0b00000001 => 10.40.16.1 10.40.16.2 0b00000100
table_cam_add_entry ipv4_encap_udp gtpu_encap_udp_v4 0b00000001 => 10.40.16.1 10.40.16.2 0b00000100
```
which encapsulates all IPv4 packets into a GTP tunnel with source address `10.40.16.1` and destination address `10.40.16.2`,
whereby `0b00000001` specifies the ingress port and `0b00000100` the egress port.

The GTP decapsulation can be configured in a similar manner:
```
table_cam_add_entry ipv4_decap gtpu_decap_v4 0b00010000 => 0b01000000
table_cam_add_entry ipv4_decap_udp gtpu_decap_udp_v4 0b00010000 => 0b01000000
```
Here only the ingress and egress ports need to be specified.

#### Port and bitmask mapping 
`nf0` : `0b00000001`\
`nf1` : `0b00000100`\
`nf2` : `0b00010000`\
`nf3` : `0b01000000`


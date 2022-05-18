//
// Copyright (c) 2017 Stephen Ibanez
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
// as part of the DARPA MRC research programme.
//
// @NETFPGA_LICENSE_HEADER_START@
//
// Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
// license agreements.  See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.  NetFPGA licenses this
// file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
// "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at:
//
//   http://www.netfpga-cic.org
//
// Unless required by applicable law or agreed to in writing, Work distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations under the License.
//
// @NETFPGA_LICENSE_HEADER_END@
//


#include <core.p4>
#include <sume_switch.p4>

/*
 * Template P4 project for SimpleSumeSwitch 
 *
 */
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> udpPort_t;
#define TYPE_IPV4 0x0800

// standard Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// IPv4 header without options
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
//
header udp_t {
    udpPort_t   srcPort;
    udpPort_t   dstPort;
    bit<16>     length_udp;
    bit<16>     checksum;
}
//
header gtpu_t {
    bit<8>    flags;
    bit<8>    type;
    bit<16>   length;
    bit<32>   teid;
}

// List of all recognized headers
struct Parsed_packet {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    udp_t        gtpu_udp;
    gtpu_t       gtpu;
    ipv4_t       gtpu_ipv4;    
}


// user defined metadata: can be used to shared information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
    bit<8>  unused;
}

// digest data to be sent to CPU if desired. MUST be 256 bits!
struct digest_data_t {
    bit<256>  unused;
}

// Parser Implementation
@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in b, 
                 out Parsed_packet p, 
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {
    state start {
        b.extract(p.ethernet);
        user_metadata.unused = 0;
        digest_data.unused = 0;
        transition select(p.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: reject;
        } 
    }

    state parse_ipv4 {
        b.extract(p.ipv4);
        transition select(p.ipv4.protocol){
            17 : parse_udp;
            default: accept;
        }
    }
    state parse_udp{
        b.extract(p.udp);
        transition select(p.udp.dstPort){
            2152 : parse_gtpu;
            default : accept;
        }
    }
    state parse_gtpu{
        b.extract(p.gtpu);
        transition parse_gtpu_ipv4;
    }
    state parse_gtpu_ipv4{
        b.extract(p.gtpu_ipv4);
        transition select(p.gtpu_ipv4.protocol){
            17 : parse_gtpu_udp;
            default : accept;
        }
    }
    state parse_gtpu_udp{
        b.extract(p.gtpu_udp);
        transition accept;
    }

   
}

// match-action pipeline
control TopPipe(inout Parsed_packet p,
                inout user_metadata_t user_metadata, 
                inout digest_data_t digest_data, 
                inout sume_metadata_t sume_metadata) {

    action drop() {}

    action gtpu_encap_v4(ip4Addr_t srcAddr, ip4Addr_t dstAddr, port_t port) {
        p.udp.setValid();
        p.gtpu.setValid();
        p.gtpu_ipv4.setValid();
        p.gtpu_ipv4 = p.ipv4;
        // set ipv4(new)
        p.ipv4.totalLen = p.gtpu_ipv4.totalLen+8+8+20;
        p.ipv4.protocol = 17;
        p.ipv4.srcAddr = srcAddr;
        p.ipv4.dstAddr = dstAddr;
        // set udp
        p.udp.srcPort = 2152;
        p.udp.dstPort = 2152;
        p.udp.length_udp = p.ipv4.totalLen-20;
        // set gtup
        p.gtpu.flags = 0x30;
        p.gtpu.type  = 255;
        p.gtpu.length = p.udp.length_udp-16;
        p.gtpu.teid = 1;
        sume_metadata.dst_port = port;
    }

    action gtpu_encap_udp_v4(ip4Addr_t srcAddr, ip4Addr_t dstAddr, port_t port ) {
        p.gtpu_udp.setValid();
        p.gtpu.setValid();
        p.gtpu_ipv4.setValid();
        p.gtpu_ipv4 = p.ipv4;
        p.gtpu_udp = p.udp;
        // set ipv4(new)
        p.ipv4.totalLen = p.gtpu_ipv4.totalLen+8+8+20;
        p.ipv4.srcAddr = srcAddr;
        p.ipv4.dstAddr = dstAddr;
        // set udp
        p.udp.srcPort = 2152;
        p.udp.dstPort = 2152;
        p.udp.length_udp = p.ipv4.totalLen-20;
        // set gtup
        p.gtpu.flags = 0x30;
        p.gtpu.type  = 255;
        p.gtpu.length = p.udp.length_udp-16;
        p.gtpu.teid = 1;
        sume_metadata.dst_port = port;
    }

    action gtpu_decap_v4(port_t port) {
        sume_metadata.dst_port = port;
        p.ipv4 = p.gtpu_ipv4;
        p.udp.setInvalid();
        p.gtpu.setInvalid();
        p.gtpu_ipv4.setInvalid();
    }

    action gtpu_decap_udp_v4(port_t port) {
        sume_metadata.dst_port = port;
        p.ipv4 = p.gtpu_ipv4;
        p.udp = p.gtpu_udp;
        p.gtpu_udp.setInvalid();
        p.gtpu.setInvalid();
        p.gtpu_ipv4.setInvalid();
    }

    table ipv4_encap {
        key = {
            sume_metadata.src_port: exact;
        }
        actions = {
        gtpu_encap_v4;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table ipv4_encap_udp {
        key = {
            sume_metadata.src_port: exact;
        }
        actions = {
        gtpu_encap_udp_v4;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

     table ipv4_decap {
        key = {
            sume_metadata.src_port: exact;
        }
        actions = {
        gtpu_decap_v4;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table ipv4_decap_udp{
        key = {
            sume_metadata.src_port: exact;
        }
        actions = {
        gtpu_decap_udp_v4;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (p.ipv4.isValid() && !p.udp.isValid() && !p.gtpu.isValid()) {
            ipv4_encap.apply();
        }
        if (p.ipv4.isValid() && p.udp.isValid() && !p.gtpu.isValid()){
            ipv4_encap_udp.apply();
        }
        if (p.gtpu.isValid() && p.gtpu_udp.isValid()){
            ipv4_decap_udp.apply();
        }
        if (p.gtpu.isValid() && !p.gtpu_udp.isValid()){
            ipv4_decap.apply();
        }
    }

}

// Deparser Implementation
@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out b,
                    in Parsed_packet p,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data, 
                    inout sume_metadata_t sume_metadata) { 
    apply {
        b.emit(p.ethernet); 
        b.emit(p.ipv4);
        b.emit(p.udp);
        b.emit(p.gtpu);
        b.emit(p.gtpu_ipv4);
        b.emit(p.gtpu_udp);
    }
}

// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

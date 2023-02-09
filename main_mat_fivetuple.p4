#include <core.p4>
#include <xsa.p4>
#include "header_xsa.p4"

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType; 
}

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

header tcp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNo;
	bit<32> ackNo;
	bit<4>  dataOffset;
	bit<3>  res;
	bit<3>  ecn;
	bit<6>  ctrl;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

struct metadata_t {
	bit<1> axis_tdest;
	bit<32> axis_tid;
	bit<256> axis_tuser;
}

struct headers {
	ethernet_t   ethernet;
	ipv4_t       ipv4;
	tcp_t	 tcp;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
		out headers hdr,
		inout metadata_t meta,
		inout standard_metadata_t standard_metadata) {

	state start {
		transition parse_ethernet;
	}

	state parse_ethernet { 
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
0x0800: parse_ip;
			default: rejection;
		}
	}

	state parse_ip {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
0x6: parse_tcp;
			default: rejection;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}

	state rejection {
		//verify(false, error.ParserInvalidArgument);
		transition accept;
	}
}



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
		inout metadata_t meta,
		inout standard_metadata_t standard_metadata) {

	bit<16> table_key_sport;
    	bit<16> table_key_dport;
    	bool hit = false;

	action mark_to_drop() {
		standard_metadata.drop = 1;
	}

    	action insert_key(bit<32> id) {
		meta.axis_tuser = 224w0 ++ id;
    	}

    	table FiveTuple {
        	key = { hdr.ipv4.srcAddr      : exact;
                        hdr.ipv4.dstAddr      : exact;
	                hdr.ipv4.protocol : exact;
	                hdr.tcp.srcPort   : exact;
	                hdr.tcp.dstPort   : exact; }
	    actions        = { insert_key; 
                           mark_to_drop; }
	    size           = 16384;
	    default_action = mark_to_drop;
    	}
	apply {
		bool hitten = FiveTuple.apply().hit;
	}
}



/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr, inout metadata_t metadata, inout standard_metadata_t standard_metadata) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
	}
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/
	XilinxPipeline(
			MyParser(),
			MyIngress(),
			MyDeparser()
		      ) main;

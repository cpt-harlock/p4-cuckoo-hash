
#include <core.p4>
#include <xsa.p4>
#include "header_xsa.p4"

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

#define HASHER_PREFIX_0 0
#define HASHER_PREFIX_1 1
#define HASHER_PREFIX_2 2
#define HASHER_PREFIX_3 3

UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hasher_extern_0;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hasher_extern_1;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hasher_extern_2;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hasher_extern_3;
UserExtern<bit<PIBLT_INPUT_WIDTH>, bit<32>>(1) piblt_registers_extern;

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
	bit<1024> axis_tuser;
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
	action mark_to_drop() {
		standard_metadata.drop = 1;
	}

	apply {
		// for the moment key is the src ip
		// modifying it shouldn't break FPGA design
		bit<TABLES_KEY_INPUT_WIDTH> key = meta.axis_tuser[HASH_KEY_INPUT_WIDTH-1:0];
		bit<HASH_KEY_INPUT_WIDTH> input_hash_0 = meta.axis_tuser[HASH_KEY_INPUT_WIDTH-1:0];
		bit<HASH_KEY_INPUT_WIDTH> input_hash_1 = meta.axis_tuser[HASH_KEY_INPUT_WIDTH-1:0];
		bit<HASH_KEY_INPUT_WIDTH> input_hash_2 = meta.axis_tuser[HASH_KEY_INPUT_WIDTH-1:0];
		bit<HASH_KEY_INPUT_WIDTH> input_hash_3 = meta.axis_tuser[HASH_KEY_INPUT_WIDTH-1:0];
		bit<HASH_PREFIX_WIDTH> hash_prefix_0 = HASHER_PREFIX_0;
		bit<HASH_PREFIX_WIDTH> hash_prefix_1 = HASHER_PREFIX_1;
		bit<HASH_PREFIX_WIDTH> hash_prefix_2 = HASHER_PREFIX_2;
		bit<HASH_PREFIX_WIDTH> hash_prefix_3 = HASHER_PREFIX_3;
		bit<HASH_OUTPUT_WIDTH> output_hash_0;
		bit<HASH_OUTPUT_WIDTH> output_hash_1;
		bit<HASH_OUTPUT_WIDTH> output_hash_2;
		bit<HASH_OUTPUT_WIDTH> output_hash_3;

		hasher_extern_0.apply(hash_prefix_0 ++ input_hash_0, output_hash_0);
		hasher_extern_1.apply(hash_prefix_1 ++ input_hash_1, output_hash_1);
		hasher_extern_2.apply(hash_prefix_2 ++ input_hash_2, output_hash_2);
		hasher_extern_3.apply(hash_prefix_3 ++ input_hash_3, output_hash_3);

		bit<32> output_iblt;
		piblt_registers_extern.apply(output_hash_3 ++ output_hash_2 ++ output_hash_1 ++ output_hash_0 ++ key, output_iblt);

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

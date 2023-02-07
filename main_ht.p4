#include <core.p4>
#include <xsa.p4>
#include "header_xsa.p4"

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hasher_extern;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) hash_table_extern;

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
		bit<TABLES_KEY_INPUT_WIDTH> hash_table_key = 96w0 ++ hdr.ipv4.srcAddr;
		bit<TABLES_VALUE_INPUT_WIDTH> hash_table_value = 0;
		bit<TABLES_INDEX_INPUT_WIDTH> hash_table_index;
		bit<TABLES_INPUT_WIDTH> hash_table_input;
		bit<TABLES_OUTPUT_WIDTH> hash_table_output;

		bit<HASH_INPUT_WIDTH> hasher_input;
		bit<HASH_PREFIX_WIDTH> hasher_prefix = 8w0;
		bit<HASH_KEY_INPUT_WIDTH> hasher_key = 96w0 ++ hdr.ipv4.srcAddr;
		hasher_input = hasher_prefix ++ hasher_key;
		bit<HASH_OUTPUT_WIDTH> hasher_output;
		// compute hash
		hasher_extern.apply(hasher_input, hasher_output);
		
		// try inserting into hash table
		hash_table_index = hasher_output[31:0];
		hash_table_input = 2w0 ++ hash_table_index ++ hash_table_value ++ hash_table_key;
		hash_table_extern.apply(hash_table_input, hash_table_output);
		// using ip src address to contain output id
		meta.axis_tuser[TABLES_KEY_INPUT_WIDTH-1:0] = 96w0 ++ hash_table_output[31:0];
		// if key not found nor inserted
		if (hash_table_output[TABLES_OUTPUT_WIDTH-1:TABLES_OUTPUT_WIDTH-1] == 0) {
			mark_to_drop();
		}
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

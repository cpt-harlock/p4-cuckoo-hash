#include <core.p4>
#include <xsa.p4>
#include "header_xsa.p4"

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Parse ethernet or not
#define PARSE_ETHERNET 1

// one path of 512
#define CH_LENGTH 512
#define CH_LENGTH_BIT 32w512


// hash keys
#define CH_FIRST_HASH_KEY 8w0
#define CH_SECOND_HASH_KEY 8w7
#define CH_FIRST_HASH_REVERSE 0
#define CH_SECOND_HASH_REVERSE 1

UserExtern<bit<COUNTER_INPUT_SIZE>, bit<COUNTER_OUTPUT_SIZE>>(COUNTER_LATENCY) discarded_keys;
UserExtern<bit<FLAG_INPUT_SIZE>, bit<FLAG_OUTPUT_SIZE>>(FLAG_LATENCY) stop_flag;
UserExtern<bit<FLAG_INPUT_SIZE>, bit<FLAG_OUTPUT_SIZE>>(FLAG_LATENCY) recirculating_flag;
UserExtern<bit<COUNTER_INPUT_SIZE>, bit<COUNTER_OUTPUT_SIZE>>(COUNTER_LATENCY) total_packets;
UserExtern<bit<REGISTER_INPUT_SIZE>, bit<REGISTER_OUTPUT_SIZE>>(REGISTER_LATENCY) ch_first_level_first_table;
UserExtern<bit<REGISTER_INPUT_SIZE>, bit<REGISTER_OUTPUT_SIZE>>(REGISTER_LATENCY) ch_second_level_first_table;
UserExtern<bit<STASH_INPUT_SIZE>, bit<STASH_OUTPUT_SIZE>>(STASH_LATENCY) ch_first_stash;
UserExtern<bit<HASH_INPUT_SIZE>, bit<HASH_OUTPUT_SIZE>>(HASH_LATENCY) hash_first_level_first_table;
UserExtern<bit<HASH_INPUT_SIZE>, bit<HASH_OUTPUT_SIZE>>(HASH_LATENCY) hash_second_level_first_table;



header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType; // == 0x0 when recirculating packet
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
	bit<42> axis_tuser;
	bit<32> axis_tid;
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
		//transition parse_ip;
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
		bit<KEY_SIZE> packet_key;
		bit<FLAG_INPUT_SIZE> stop_flag_input;
		bit<COUNTER_OUTPUT_SIZE> total_packets_read;
		bit<FLAG_OUTPUT_SIZE> stop_flag_read;
		bit<FLAG_OUTPUT_SIZE> recirculating_flag_read;
		bit<COUNTER_OUTPUT_SIZE> hit_counter_read;
		bit<COUNTER_OUTPUT_SIZE> inserted_keys_read;
		bit<COUNTER_OUTPUT_SIZE> discarded_keys_read;
		bit<KEY_VALUE_SIZE> first_result;
		bit<KEY_VALUE_SIZE> second_result;
		bit<32> ch_first_level_first_table_index;
		bit<32> ch_second_level_first_table_index;
		bit<1> ch_first_level_first_table_hit;
		bit<1> ch_first_level_first_table_written;
		bit<1> ch_second_level_first_table_hit;
		bit<1> ch_second_level_first_table_written;
		bit<1> stash_hit;
		bit<1> stash_written;
		bit<1> stash_discarded;
		bit<32> stash_counter_read;
		bit<KEY_VALUE_SIZE> stash_output_value;

		if (standard_metadata.parser_error != error.NoError) {
			return;
		}

		total_packets.apply(COUNTER_INPUT_INCREMENT, total_packets_read);
		// assembling key
		if (meta.axis_tdest == 0) {
			packet_key = 64w0 ++ hdr.ipv4.srcAddr;
		} else {
			packet_key = 54w0 ++ meta.axis_tuser;
		}
		// try insert in first table or hit
		CUCKOO_READ_WRITE(10w0 ++ packet_key, CH_FIRST_HASH_KEY, ch_first_level_first_table, CH_LENGTH_BIT, first_result, ch_first_level_first_table_hit, ch_first_level_first_table_written, CH_FIRST_HASH_REVERSE, hash_first_level_first_table, meta.axis_tdest); 
		// output value is evicted from first ch or it's the original key if not evicted
		CUCKOO_READ_WRITE(first_result, CH_SECOND_HASH_KEY, ch_second_level_first_table, CH_LENGTH_BIT, second_result, ch_second_level_first_table_hit, ch_second_level_first_table_written, CH_SECOND_HASH_REVERSE, hash_second_level_first_table, meta.axis_tdest); 
		STASH_READ_WRITE(second_result, ch_first_stash, meta.axis_tdest, stash_output_value, stash_hit, stash_written, stash_discarded, stash_counter_read);
		bool stash_threshold;
		stash_threshold = stash_counter_read >= 4;
		// a try
		// nested if should work for variables
		bit<2> recirc_input = FLAG_INPUT_READ;
		if (meta.axis_tdest == 0) {
			if (stash_threshold)
				recirc_input = FLAG_INPUT_SET;
		}
		else {
			if (meta.axis_tid >= LOOP_LIMIT || stash_discarded == 1 ) {
				recirc_input = FLAG_INPUT_RESET;
			}
		}


		// now I can apply recirculating_flag outside if
		recirculating_flag.apply(recirc_input, recirculating_flag_read);
		// again, variables if should work
		if (meta.axis_tdest == 0) {
			if (recirculating_flag_read == 0 && stash_threshold) {
				meta.axis_tdest = 1;
				meta.axis_tid = 0;
			}	
		}
		else {
			// DEBUG: LOOP LIMIT TO 1
			mark_to_drop();
			//if (stash_discarded == 1) {
			//	// drop packet if recirculation was successfull
			//	mark_to_drop();
			//} 
		}

		// this part is common to both exec flows
		if (meta.axis_tid >= LOOP_LIMIT) {
			mark_to_drop();
		}
		// I can increase axis_tid without if, in case of normal packet is just unused
		meta.axis_tid = meta.axis_tid + 1;
		// again, this is common to both flows
		meta.axis_tuser = stash_output_value[41:0];
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

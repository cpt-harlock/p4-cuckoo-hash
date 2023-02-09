#include <core.p4>
#include <xsa.p4>
#include "header_xsa.p4"

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Parse ethernet or not
#define PARSE_ETHERNET 1

// hash keys
#define CH_DATAPATH_HASH_KEY 8w6
#define CH_FIRST_LEVEL_HASH_KEY 8w0
#define CH_SECOND_LEVEL_HASH_KEY 8w1
#define CH_THIRD_LEVEL_HASH_KEY 8w2
#define CH_FOURTH_LEVEL_HASH_KEY 8w3
// stash size, for triggering recirculation
#define STASH_SLOT_COUNT 16

UserExtern<bit<COUNTER_INPUT_SIZE>, bit<COUNTER_OUTPUT_SIZE>>(1) total_packets;

UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_datapath_selection;

UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_first_level_first_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_first_level_first_datapath;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_second_level_first_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_second_level_first_datapath;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_third_level_first_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_third_level_first_datapath;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_fourth_level_first_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_fourth_level_first_datapath;

UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_first_level_second_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_first_level_second_datapath;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_second_level_second_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_second_level_second_datapath;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_third_level_second_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_third_level_second_datapath;
UserExtern<bit<HASH_INPUT_WIDTH>, bit<HASH_OUTPUT_WIDTH>>(1) hash_fourth_level_second_datapath;
UserExtern<bit<TABLES_INPUT_WIDTH>, bit<TABLES_OUTPUT_WIDTH>>(1) ch_fourth_level_second_datapath;

UserExtern<bit<STASH_INPUT_WIDTH>, bit<STASH_OUTPUT_WIDTH>>(1) stash_first_datapath;
UserExtern<bit<STASH_INPUT_WIDTH>, bit<STASH_OUTPUT_WIDTH>>(1) stash_second_datapath;
UserExtern<bit<FLAG_INPUT_SIZE>, bit<FLAG_OUTPUT_SIZE>>(1) recirculating_flag;



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


		// hash datapath selection signals 
		bit<HASH_INPUT_WIDTH> hash_datapath_selection_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_datapath_selection_input_key;
		bit<HASH_PREFIX_WIDTH> hash_datapath_selection_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_datapath_selection_output;

		// first hash signals
		bit<HASH_INPUT_WIDTH> hash_first_level_first_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_first_level_first_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_first_level_first_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_first_level_first_datapath_output;

		// second hash signals
		bit<HASH_INPUT_WIDTH> hash_second_level_first_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_second_level_first_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_second_level_first_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_second_level_first_datapath_output;

		// third hash signals
		bit<HASH_INPUT_WIDTH> hash_third_level_first_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_third_level_first_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_third_level_first_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_third_level_first_datapath_output;

		// fourth hash signals
		bit<HASH_INPUT_WIDTH> hash_fourth_level_first_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_fourth_level_first_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_fourth_level_first_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_fourth_level_first_datapath_output;


		// first ch signals 
		bit<TABLES_KEY_INPUT_WIDTH> ch_first_level_first_datapath_input_key;
		bit<TABLES_INDEX_INPUT_WIDTH> ch_first_level_first_datapath_input_index;
		bit<TABLES_VALUE_INPUT_WIDTH> ch_first_level_first_datapath_input_value;
		bit<1> ch_first_level_first_datapath_input_ignore_input;
		bit<1> ch_first_level_first_datapath_input_evict;
		bit<TABLES_INPUT_WIDTH> ch_first_level_first_datapath_input;
		// output 
		bit<TABLES_OUTPUT_WIDTH> ch_first_level_first_datapath_output;

		// second ch signal
		bit<TABLES_INPUT_WIDTH> ch_second_level_first_datapath_input;
		bit<TABLES_OUTPUT_WIDTH> ch_second_level_first_datapath_output;

		// third ch signal
		bit<TABLES_INPUT_WIDTH> ch_third_level_first_datapath_input;
		bit<TABLES_OUTPUT_WIDTH> ch_third_level_first_datapath_output;

		// fourth ch signal
		bit<TABLES_INPUT_WIDTH> ch_fourth_level_first_datapath_input;
		bit<TABLES_OUTPUT_WIDTH> ch_fourth_level_first_datapath_output;

		// stash signals 
		bit<STASH_INPUT_WIDTH> stash_first_datapath_input;
		// output
		bit<STASH_OUTPUT_WIDTH> stash_first_datapath_output;
		bit<32> stash_first_datapath_output_counter;
		bit<1> stash_first_datapath_output_discarded;
		bit<1> stash_first_datapath_output_w_h;
		bit<TABLES_VALUE_INPUT_WIDTH> stash_first_datapath_output_value;
		bit<TABLES_KEY_INPUT_WIDTH> stash_first_datapath_output_key;

		/* second datapath */
		// first hash signals
		bit<HASH_INPUT_WIDTH> hash_first_level_second_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_first_level_second_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_first_level_second_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_first_level_second_datapath_output;

		// second hash signals
		bit<HASH_INPUT_WIDTH> hash_second_level_second_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_second_level_second_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_second_level_second_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_second_level_second_datapath_output;

		// third hash signals
		bit<HASH_INPUT_WIDTH> hash_third_level_second_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_third_level_second_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_third_level_second_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_third_level_second_datapath_output;

		// fourth hash signals
		bit<HASH_INPUT_WIDTH> hash_fourth_level_second_datapath_input;
		bit<HASH_KEY_INPUT_WIDTH> hash_fourth_level_second_datapath_input_key;
		bit<HASH_PREFIX_WIDTH> hash_fourth_level_second_datapath_input_prefix;
		bit<HASH_OUTPUT_WIDTH> hash_fourth_level_second_datapath_output;


		// first ch signals 
		bit<TABLES_KEY_INPUT_WIDTH> ch_first_level_second_datapath_input_key;
		bit<TABLES_INDEX_INPUT_WIDTH> ch_first_level_second_datapath_input_index;
		bit<TABLES_VALUE_INPUT_WIDTH> ch_first_level_second_datapath_input_value;
		bit<1> ch_first_level_second_datapath_input_ignore_input;
		bit<1> ch_first_level_second_datapath_input_evict;
		bit<TABLES_INPUT_WIDTH> ch_first_level_second_datapath_input;
		// output 
		bit<TABLES_OUTPUT_WIDTH> ch_first_level_second_datapath_output;

		// second ch signal
		bit<TABLES_INPUT_WIDTH> ch_second_level_second_datapath_input;
		bit<TABLES_OUTPUT_WIDTH> ch_second_level_second_datapath_output;

		// third ch signal
		bit<TABLES_INPUT_WIDTH> ch_third_level_second_datapath_input;
		bit<TABLES_OUTPUT_WIDTH> ch_third_level_second_datapath_output;

		// fourth ch signal
		bit<TABLES_INPUT_WIDTH> ch_fourth_level_second_datapath_input;
		bit<TABLES_OUTPUT_WIDTH> ch_fourth_level_second_datapath_output;

		// stash signals 
		bit<STASH_INPUT_WIDTH> stash_second_datapath_input;
		// output
		bit<STASH_OUTPUT_WIDTH> stash_second_datapath_output;
		bit<32> stash_second_datapath_output_counter;
		bit<1> stash_second_datapath_output_discarded;
		bit<1> stash_second_datapath_output_w_h;
		bit<TABLES_VALUE_INPUT_WIDTH> stash_second_datapath_output_value;
		bit<TABLES_KEY_INPUT_WIDTH> stash_second_datapath_output_key;

		if (standard_metadata.parser_error != error.NoError) {
			return;
		}

		
		bit<TABLES_KEY_INPUT_WIDTH> packet_key_1;
		bit<TABLES_VALUE_INPUT_WIDTH> packet_value_1;
		bit<TABLES_KEY_INPUT_WIDTH> packet_key_2;
		bit<TABLES_VALUE_INPUT_WIDTH> packet_value_2;
		bit<COUNTER_OUTPUT_SIZE> total_packets_read;
		bit<FLAG_OUTPUT_SIZE> recirculating_flag_read;

		// increase total count of packets
		total_packets.apply(COUNTER_INPUT_INCREMENT, total_packets_read);
		// first key is always in first metadata location
		packet_key_1 = meta.axis_tuser[TABLES_KEY_INPUT_WIDTH-1:0];
		packet_value_1 = meta.axis_tuser[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH)-1:TABLES_KEY_INPUT_WIDTH];
		// hash  for datapath selection
		hash_datapath_selection_input_key = packet_key_1;
		hash_datapath_selection_input_prefix = CH_DATAPATH_HASH_KEY;
		hash_datapath_selection_input = hash_datapath_selection_input_prefix ++ hash_datapath_selection_input_key;
		hash_datapath_selection.apply(hash_datapath_selection_input, hash_datapath_selection_output);
		bit<1> datapath = (hash_datapath_selection_output % 2)[0:0];

		// key for second datapath selection
		if (meta.axis_tdest == 1) {
			packet_key_2 = meta.axis_tuser[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + TABLES_KEY_INPUT_WIDTH)-1:(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH)];
			packet_value_2 = meta.axis_tuser[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH)-1:(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH + TABLES_KEY_INPUT_WIDTH)];
		} else {
			// get the only key
			packet_key_2 = meta.axis_tuser[TABLES_KEY_INPUT_WIDTH-1:0];
			packet_value_2 = meta.axis_tuser[(TABLES_KEY_INPUT_WIDTH + TABLES_VALUE_INPUT_WIDTH)-1:TABLES_KEY_INPUT_WIDTH];
		}


		// compute index for first table - first datapath
		hash_first_level_first_datapath_input_key = packet_key_1;
		hash_first_level_first_datapath_input_prefix = CH_FIRST_LEVEL_HASH_KEY;
		hash_first_level_first_datapath_input = hash_first_level_first_datapath_input_prefix ++ hash_first_level_first_datapath_input_key;
		hash_first_level_first_datapath.apply(hash_first_level_first_datapath_input, hash_first_level_first_datapath_output);

		// compute index for first table - second datapath
		hash_first_level_second_datapath_input_key = packet_key_2;
		hash_first_level_second_datapath_input_prefix = CH_FIRST_LEVEL_HASH_KEY;
		hash_first_level_second_datapath_input = hash_first_level_second_datapath_input_prefix ++ hash_first_level_second_datapath_input_key;
		hash_first_level_second_datapath.apply(hash_first_level_second_datapath_input, hash_first_level_second_datapath_output);

		// populate first ch input - first datapath
		ch_first_level_first_datapath_input_index = hash_first_level_first_datapath_output;
		ch_first_level_first_datapath_input_key = packet_key_1;
		ch_first_level_first_datapath_input_value = packet_value_1;
		// evict if recirculating
		ch_first_level_first_datapath_input_evict = meta.axis_tdest;
		// if recirculating, never ignore; if not, ignore when  datapath bit is 1 
		ch_first_level_first_datapath_input_ignore_input = (~meta.axis_tdest) & datapath;
		ch_first_level_first_datapath_input = ch_first_level_first_datapath_input_evict ++ ch_first_level_first_datapath_input_ignore_input ++ ch_first_level_first_datapath_input_index ++ ch_first_level_first_datapath_input_value ++ ch_first_level_first_datapath_input_key ;
		// access first ch
		ch_first_level_first_datapath.apply(ch_first_level_first_datapath_input, ch_first_level_first_datapath_output);


		// populate first ch input - second datapath
		ch_first_level_second_datapath_input_index = hash_first_level_second_datapath_output;
		ch_first_level_second_datapath_input_key = packet_key_2;
		ch_first_level_second_datapath_input_value = packet_value_2;
		// evict if recirculating
		ch_first_level_second_datapath_input_evict = meta.axis_tdest;
		// if recirculating, never ignore; if not, ignore when  datapath bit is 0 
		ch_first_level_second_datapath_input_ignore_input = (~meta.axis_tdest) & (~datapath);
		ch_first_level_second_datapath_input = ch_first_level_second_datapath_input_evict ++ ch_first_level_second_datapath_input_ignore_input ++ ch_first_level_second_datapath_input_index ++ ch_first_level_second_datapath_input_value ++ ch_first_level_second_datapath_input_key ;
		// access first ch
		ch_first_level_second_datapath.apply(ch_first_level_second_datapath_input, ch_first_level_second_datapath_output);

		// second table - first datapath 
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_HASH(ch_first_level_first_datapath_output, CH_SECOND_LEVEL_HASH_KEY, hash_second_level_first_datapath_input);
		hash_second_level_first_datapath.apply(hash_second_level_first_datapath_input, hash_second_level_first_datapath_output);
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_CUCKOO(ch_first_level_first_datapath_output, hash_second_level_first_datapath_output, meta.axis_tdest, ch_second_level_first_datapath_input);
		ch_second_level_first_datapath.apply(ch_second_level_first_datapath_input, ch_second_level_first_datapath_output);

		// second table - second datapath
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_HASH(ch_first_level_second_datapath_output, CH_SECOND_LEVEL_HASH_KEY, hash_second_level_second_datapath_input);
		hash_second_level_second_datapath.apply(hash_second_level_second_datapath_input, hash_second_level_second_datapath_output);
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_CUCKOO(ch_first_level_second_datapath_output, hash_second_level_second_datapath_output, meta.axis_tdest, ch_second_level_second_datapath_input);
		ch_second_level_second_datapath.apply(ch_second_level_second_datapath_input, ch_second_level_second_datapath_output);
		

		// third table - first datapath
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_HASH(ch_second_level_first_datapath_output, CH_THIRD_LEVEL_HASH_KEY, hash_third_level_first_datapath_input);
		hash_third_level_first_datapath.apply(hash_third_level_first_datapath_input, hash_third_level_first_datapath_output);
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_CUCKOO(ch_second_level_first_datapath_output, hash_third_level_first_datapath_output, meta.axis_tdest, ch_third_level_first_datapath_input);
		ch_third_level_first_datapath.apply(ch_third_level_first_datapath_input, ch_third_level_first_datapath_output);

		// third table - second datapath
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_HASH(ch_second_level_second_datapath_output, CH_THIRD_LEVEL_HASH_KEY, hash_third_level_second_datapath_input);
		hash_third_level_second_datapath.apply(hash_third_level_second_datapath_input, hash_third_level_second_datapath_output);
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_CUCKOO(ch_second_level_second_datapath_output, hash_third_level_second_datapath_output, meta.axis_tdest, ch_third_level_second_datapath_input);
		ch_third_level_second_datapath.apply(ch_third_level_second_datapath_input, ch_third_level_second_datapath_output);

		// fourth table - first datapath 
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_HASH(ch_third_level_first_datapath_output, CH_FOURTH_LEVEL_HASH_KEY, hash_fourth_level_first_datapath_input);
		hash_fourth_level_first_datapath.apply(hash_fourth_level_first_datapath_input, hash_fourth_level_first_datapath_output);
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_CUCKOO(ch_third_level_first_datapath_output, hash_fourth_level_first_datapath_output, meta.axis_tdest, ch_fourth_level_first_datapath_input);
		ch_fourth_level_first_datapath.apply(ch_fourth_level_first_datapath_input, ch_fourth_level_first_datapath_output);

		// fourth table - second datapath 
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_HASH(ch_third_level_second_datapath_output, CH_FOURTH_LEVEL_HASH_KEY, hash_fourth_level_second_datapath_input);
		hash_fourth_level_second_datapath.apply(hash_fourth_level_second_datapath_input, hash_fourth_level_second_datapath_output);
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_CUCKOO(ch_third_level_second_datapath_output, hash_fourth_level_second_datapath_output, meta.axis_tdest, ch_fourth_level_second_datapath_input);
		ch_fourth_level_second_datapath.apply(ch_fourth_level_second_datapath_input, ch_fourth_level_second_datapath_output);

		// stash - first datapath
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_STASH(ch_fourth_level_first_datapath_output, meta.axis_tdest, stash_first_datapath_input);
		stash_first_datapath.apply(stash_first_datapath_input, stash_first_datapath_output);
		STASH_PARSE_OUTPUT(stash_first_datapath_output, stash_first_datapath_output_key, stash_first_datapath_output_value, stash_first_datapath_output_counter, stash_first_datapath_output_discarded, stash_first_datapath_output_w_h);

		// stash - second datapath
		CUCKOO_PARSE_OUTPUT_BUILD_INPUT_NEXT_STASH(ch_fourth_level_second_datapath_output, meta.axis_tdest, stash_second_datapath_input);
		stash_second_datapath.apply(stash_second_datapath_input, stash_second_datapath_output);
		STASH_PARSE_OUTPUT(stash_second_datapath_output, stash_second_datapath_output_key, stash_second_datapath_output_value, stash_second_datapath_output_counter, stash_second_datapath_output_discarded, stash_second_datapath_output_w_h);

		bool stash_threshold;
		stash_threshold = stash_first_datapath_output_counter >= 1 && stash_second_datapath_output_counter >= 1;
		// a try
		// nested if should work for variables
		bit<2> recirc_input = FLAG_INPUT_READ;
		if (meta.axis_tdest == 0) {
			if (stash_threshold && stash_first_datapath_output_discarded == 0 && stash_second_datapath_output_discarded == 0 )
				recirc_input = FLAG_INPUT_SET;
		}
		else {
			if (meta.axis_tid >= LOOP_LIMIT || !stash_threshold ) {
				recirc_input = FLAG_INPUT_RESET;
			}
		}


		// now I can apply recirculating_flag outside if
		recirculating_flag.apply(recirc_input, recirculating_flag_read);
		// again, variables if should work
		if (meta.axis_tdest == 0) {
			if (recirculating_flag_read == 0 && stash_threshold && stash_first_datapath_output_discarded == 0 && stash_second_datapath_output_discarded == 0) {
				meta.axis_tdest = 1;
				meta.axis_tid = 0;
			}	
		}
		else {
			if (!stash_threshold) {
				// drop packet if recirculation was successfull
				mark_to_drop();
			} 
		}

		// this part is common to both exec flows
		// for normal pkts is never true
		if (meta.axis_tid >= LOOP_LIMIT) {
			mark_to_drop();
		}
		// I can increase axis_tid without if, in case of normal packet is just unused
		meta.axis_tid = meta.axis_tid + 1;
		// again, this is common to both flows
		meta.axis_tuser[TABLES_KEY_INPUT_WIDTH-1:0] = stash_first_datapath_output_key;
		meta.axis_tuser[(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH)-1:TABLES_KEY_INPUT_WIDTH] = stash_first_datapath_output_value;
		meta.axis_tuser[(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH+TABLES_KEY_INPUT_WIDTH)-1:(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH)] = stash_second_datapath_output_key;
		meta.axis_tuser[(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH+TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH)-1:(TABLES_KEY_INPUT_WIDTH+TABLES_VALUE_INPUT_WIDTH+TABLES_KEY_INPUT_WIDTH)] = stash_second_datapath_output_value;
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

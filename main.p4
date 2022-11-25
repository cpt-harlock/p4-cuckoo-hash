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

// ch tables
UserExtern<bit<REGISTER_INPUT_SIZE>, bit<REGISTER_OUTPUT_SIZE>>(REGISTER_LATENCY) ch_first_level_first_table;
UserExtern<bit<REGISTER_INPUT_SIZE>, bit<REGISTER_OUTPUT_SIZE>>(REGISTER_LATENCY) ch_second_level_first_table;
// ch stash
UserExtern<bit<STASH_INPUT_SIZE>, bit<STASH_OUTPUT_SIZE>>(STASH_LATENCY) ch_first_stash;
// hashers 
UserExtern<bit<HASH_INPUT_SIZE>, bit<HASH_OUTPUT_SIZE>>(HASH_LATENCY) hash_first_level_first_table;
UserExtern<bit<HASH_INPUT_SIZE>, bit<HASH_OUTPUT_SIZE>>(HASH_LATENCY) hash_second_level_first_table;
// counters + flag
UserExtern<bit<COUNTER_INPUT_SIZE>, bit<COUNTER_OUTPUT_SIZE>>(COUNTER_LATENCY) hit_counter;
UserExtern<bit<COUNTER_INPUT_SIZE>, bit<COUNTER_OUTPUT_SIZE>>(COUNTER_LATENCY) inserted_keys;
UserExtern<bit<COUNTER_INPUT_SIZE>, bit<COUNTER_OUTPUT_SIZE>>(COUNTER_LATENCY) discarded_keys;
UserExtern<bit<FLAG_INPUT_SIZE>, bit<FLAG_OUTPUT_SIZE>>(FLAG_LATENCY) stop_flag;
UserExtern<bit<FLAG_INPUT_SIZE>, bit<FLAG_OUTPUT_SIZE>>(FLAG_LATENCY) recirculating_flag;

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
	//recirculation flag
	bit<1> axis_tdest;
	//recirculation key_value
	bit<KEY_VALUE_SIZE> axis_tuser;
	//recirculation counter
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
#if PARSE_ETHERNET == 1
		transition parse_ethernet;
#else
		transition parse_ip;
#endif
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
	//compute CH indices
	apply {
		bit<KEY_SIZE> packet_key;
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
		bit<KEY_VALUE_SIZE> stash_output_value;

		bit<KEY_VALUE_SIZE> stash_first_result = 106w0;
		bit<KEY_VALUE_SIZE> stash_second_result = 106w0;
		bit<KEY_VALUE_SIZE> stash_third_result = 106w0;
		bit<KEY_VALUE_SIZE> stash_fourth_result = 106w0;
		bit<KEY_VALUE_SIZE> stash_fifth_result = 106w0;
		bit<KEY_VALUE_SIZE> stash_sixth_result = 106w0;
		bit<KEY_VALUE_SIZE> stash_seventh_result = 106w0;
		bit<KEY_VALUE_SIZE> stash_eighth_result = 106w0;
		bit<32> stash_count;
		bit<COUNTER_OUTPUT_SIZE> hit_counter_read;
		bit<COUNTER_OUTPUT_SIZE> total_packets_value;
		bit<FLAG_OUTPUT_SIZE> stop_flag_value;
		bit<FLAG_OUTPUT_SIZE> recirculating_flag_value;
		bit<32> stash_counter_read;

		if (standard_metadata.parser_error != error.NoError) {
			mark_to_drop();
			return;
		} 

		if (standard_metadata.parsed_bytes != 0) {
			stop_flag.apply(FLAG_INPUT_READ, stop_flag_value);
			if (stop_flag_value == 0) {
				// READING FLAG IN METADATA
				// if normal packet
				if (meta.axis_tdest == 0) {
					// assembling key
					packet_key = 64w0 ++ hdr.ipv4.srcAddr;
					// try insert in first table or hit
					CUCKOO_READ_WRITE(10w0 ++ packet_key, CH_FIRST_HASH_KEY, ch_first_level_first_table, CH_LENGTH_BIT, first_result, ch_first_level_first_table_hit, ch_first_level_first_table_written, CH_FIRST_HASH_REVERSE, hash_first_level_first_table); 
					// if finding the key in the first table, update the HIT counter
					if (ch_first_level_first_table_hit == 1) {
						hit_counter.apply(COUNTER_INPUT_INCREMENT, hit_counter_read);
					} else if (ch_first_level_first_table_written == 0) {
						// if written signal is low, try inserting in the second table
						CUCKOO_READ_WRITE(10w0 ++ packet_key, CH_SECOND_HASH_KEY, ch_second_level_first_table, CH_LENGTH_BIT, second_result, ch_second_level_first_table_hit, ch_second_level_first_table_written, CH_SECOND_HASH_REVERSE, hash_second_level_first_table); 
						// if hit in second table, update HIT counter 
						if (ch_second_level_first_table_hit == 1) {
							hit_counter.apply(COUNTER_INPUT_INCREMENT, hit_counter_read);
						} else if (ch_second_level_first_table_written == 0) {
							// try inserting into stash
							STASH_READ_WRITE(10w0 ++ packet_key, ch_first_stash, 1w0, stash_output_value, stash_hit, stash_written, stash_discarded, stash_counter_read);
							// stash hit, update HIT counter
							if (stash_hit == 1) {
								hit_counter.apply(COUNTER_INPUT_INCREMENT, hit_counter_read);
							} else if (stash_written == 1) {
								// stash written -> we inserted a new key
								inserted_keys.apply(COUNTER_INPUT_INCREMENT, hit_counter_read);
							} else if (stash_discarded == 1) {
								// discarded keys when can't be inserted into the stash
								discarded_keys.apply(COUNTER_INPUT_INCREMENT, hit_counter_read);
							}
							if (stash_counter_read >= STASH_RECIRCULATION_THRESHOLD) {
								recirculating_flag.apply(FLAG_INPUT_SET, recirculating_flag_value);
								// if not already recirculating
								if (recirculating_flag_value == 0) {
									meta.axis_tuser = stash_output_value;
									meta.axis_tdest = 1;
									meta.axis_tid = 0;
								}
							}

						} else {
							inserted_keys.apply(COUNTER_INPUT_INCREMENT, hit_counter_read);
						}
					} else {
						inserted_keys.apply(COUNTER_INPUT_INCREMENT, hit_counter_read);
					}
				} else {
					// RECIRCULATING PACKET 
					// increasing recirculation counter
					meta.axis_tid = meta.axis_tid + 1;
					if (meta.axis_tid > LOOP_LIMIT) {
						mark_to_drop();
						// reset recirculating value to allow new recirculations
						recirculating_flag.apply(FLAG_INPUT_RESET, recirculating_flag_value);
						//TODO: add statistics for recirculation
						// setting the stop flag
						bit<1> _placeholder_read;
						stop_flag.apply(FLAG_INPUT_SET, _placeholder_read);
						return;
					}
					bit<KEY_VALUE_SIZE> recirculating_value = meta.axis_tuser;
					//insert into first cuckoo
					CUCKOO_READ_WRITE_EVICT(recirculating_value, CH_FIRST_HASH_KEY, ch_first_level_first_table, CH_LENGTH_BIT, first_result, ch_first_level_first_table_hit, ch_first_level_first_table_written, CH_FIRST_HASH_REVERSE, hash_first_level_first_table); 
					//insert into second cuckoo
					CUCKOO_READ_WRITE_EVICT(10w0 ++ packet_key, CH_SECOND_HASH_KEY, ch_second_level_first_table, CH_LENGTH_BIT, second_result, ch_second_level_first_table_hit, ch_second_level_first_table_written, CH_SECOND_HASH_REVERSE, hash_second_level_first_table); 
					//insert into stash, evicting the oldest value (that just recirculated, being inserted in the ch first)
					STASH_READ_WRITE(10w0 ++ packet_key, ch_first_stash, 1w1, stash_output_value, stash_hit, stash_written, stash_discarded, stash_counter_read);
					// using discarded to signal freed slot in the stash 
					if (stash_discarded == 1) {
						// drop packet if recirculation was successfull
						//mark_to_drop();
						// shouldn't need to reset recirculate flag ...
						meta.axis_tdest = 0;
						// reset recirculating value to allow new recirculations
						recirculating_flag.apply(FLAG_INPUT_RESET, recirculating_flag_value);

					} else {
						// new recirculation key
						meta.axis_tuser = stash_output_value;
					}

				}
			}
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

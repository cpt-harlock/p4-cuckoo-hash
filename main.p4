#include <v1model.p4>
#include <core.p4>
#include "header.p4"

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Define constants for types of packets
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

//two path of 256
#define CH_LENGTH 256
#define CH_LENGTH_BIT 32w256

// hash keys
#define CH_FIRST_HASH_KEY 8w0
#define CH_SECOND_HASH_KEY 8w7
#define CH_FIRST_HASH_REVERSE 0
#define CH_SECOND_HASH_REVERSE 1
#define CH_DATAPATH_HASH_KEY 8w3
// 106 bits per register, first 96 bits for key and others for value 
// two levels of ch, 4 tables per level (4 parallel datapaths)
register<bit<BUCKET_SIZE>>(CH_LENGTH) ch_first_level_first_table;
register<bit<BUCKET_SIZE>>(CH_LENGTH) ch_first_level_second_table;
register<bit<BUCKET_SIZE>>(CH_LENGTH) ch_second_level_first_table;
register<bit<BUCKET_SIZE>>(CH_LENGTH) ch_second_level_second_table;
register<bit<KEY_VALUE_SIZE>>(STASH_LENGTH) ch_first_stash;
register<bit<KEY_VALUE_SIZE>>(STASH_LENGTH) ch_second_stash;
register<bit<32>>(1) ch_first_stash_counter;
register<bit<32>>(1) ch_second_stash_counter;

register<bit<32>>(1) hit_counter;
register<bit<96>>(1) last_key;
register<bit<32>>(1) recirculation_counter;
register<bit<32>>(1) succesfull_recirculation;
register<bit<32>>(1) unsuccesfull_recirculation;
register<bit<32>>(1) new_recirculation;
register<bit<32>>(1) recirculating;
register<bit<32>>(1) stop_flag;
register<bit<32>>(1) inserted_keys;
register<bit<32>>(1) discarded_keys;
register<bit<32>>(1) kicked_keys;
register<bit<32>>(1) debug;
register<bit<32>>(1) debug_1;
register<bit<32>>(1) debug_2;
register<bit<32>>(1) counter_reg;

#define RECIRCULATION_CONDITION ||
#define STASH_RECIRCULATE(flag) { \
	bit<32> recirculating_value; \
	bit<32> new_recirculation_value; \
	bit<32> succesfull_recirculation_value; \
	recirculating.read(recirculating_value, 0); \
	bit<32> ch_first_stash_counter_read;\
	bit<32> ch_second_stash_counter_read;\
	ch_first_stash_counter.read(ch_first_stash_counter_read, 0);\
	ch_second_stash_counter.read(ch_second_stash_counter_read, 0);\
	bool bool1 = ch_first_stash_counter_read >= STASH_RECIRCULATION_THRESHOLD; \ 
	bool bool2 = ch_second_stash_counter_read >= STASH_RECIRCULATION_THRESHOLD; \ 
	bool bool3 = ch_first_stash_counter_read >= STASH_LENGTH; \ 
	bool bool4 = ch_second_stash_counter_read >= STASH_LENGTH; \ 
	bool bool5 = bool1 && bool2; \
	bool bool6 = bool3 || bool4; \
	bool bool7 = bool5 || bool6; \
		if (flag == 1) { \
			if (recirculating_value == 0) { \
				if (bool7) {\
					resubmit_preserving_field_list(1);\
						recirculating.write(0, 1); \
						new_recirculation.read(new_recirculation_value, 0); \
						new_recirculation.write(0, new_recirculation_value + 1); \
				} else { \
					mark_to_drop(standard_metadata); \
				} \
			} else { \
				mark_to_drop(standard_metadata); \
			} \
		} else { \
			if (bool7) {\
				resubmit_preserving_field_list(1);\
			} else {\
				recirculating.write(0, 0); \
				succesfull_recirculation.read(succesfull_recirculation_value, 0); \
				succesfull_recirculation.write(0, succesfull_recirculation_value + 1); \
				mark_to_drop(standard_metadata); \
			}\
		}\
}


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

struct metadata {
	@field_list(1)
		bit<106> keyvalue;
	@field_list(1)
		bit<32> recirculation_counter;
}

struct headers {
	//ethernet_t   ethernet;
	ipv4_t       ipv4;
	tcp_t	 tcp;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
		out headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {

	state start {
		transition parse_ip;
		//transition parse_ethernet;
	}

	//state parse_ethernet { 
	//    	packet.extract(hdr.ethernet);
	//    	transition select(hdr.ethernet.etherType) {
	//    		0x0800: parse_ip;
	//    		default: rejection;
	//    	}
	//}

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
		verify(false, error.ParserInvalidArgument);
		transition accept;
	}
}


/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply {  }
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {

	//compute CH indices
	apply {
		bit<32> datapath_selection_index;
		bit<96> packet_key;
		bit<32> counter_result;
		bit<106> temp;
		bit<106> stash_evicted_1;
		bit<106> stash_evicted_2;
		bit<32> hit_counter_read;
		bit<32> inserted_keys_read;

		if (standard_metadata.parser_error != error.NoError) {
			mark_to_drop(standard_metadata);
			//return should work as well
			exit;
		} 


		bit<32> stop_flag_value;
		stop_flag.read(stop_flag_value, 0);
		if ( stop_flag_value == 0) { 
			if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_RESUBMIT) {
				bit<BUCKET_SIZE> first_result;
				bit<BUCKET_SIZE> second_result;
				bit<KEY_VALUE_SIZE> stash_first_result;
				bit<KEY_VALUE_SIZE> stash_second_result;
				bit<KEY_VALUE_SIZE> stash_third_result;
				bit<KEY_VALUE_SIZE> stash_fourth_result;
				bit<KEY_VALUE_SIZE> stash_fifth_result;
				bit<KEY_VALUE_SIZE> stash_sixth_result;
				bit<KEY_VALUE_SIZE> stash_seventh_result;
				bit<KEY_VALUE_SIZE> stash_eighth_result;
				inserted_keys.read(inserted_keys_read, 0);
				packet_key = 64w0 ++ hdr.ipv4.srcAddr;
				last_key.write(0, packet_key) ;
				counter_reg.read(counter_result, 0);
				counter_reg.write(0, counter_result+1);
				//computing datapath index
				hash(datapath_selection_index, HashAlgorithm.crc32, 32w0, { CH_DATAPATH_HASH_KEY, packet_key }, 32w2);
				if (datapath_selection_index == 0) {
					READ_FROM_CUCKOO_ALGO(10w0 ++ packet_key, CH_FIRST_HASH_KEY, ch_first_level_first_table, CH_LENGTH_BIT, first_result, CH_FIRST_HASH_REVERSE, crc16); 
					READ_FROM_CUCKOO_ALGO(10w0 ++ packet_key, CH_SECOND_HASH_KEY, ch_second_level_first_table, CH_LENGTH_BIT, second_result, CH_SECOND_HASH_REVERSE, crc32); 
					READ_FROM_STASH(ch_first_stash, stash_first_result, stash_second_result, stash_third_result, stash_fourth_result, stash_fifth_result, stash_sixth_result, stash_seventh_result, stash_eighth_result);
				} else {
					READ_FROM_CUCKOO_ALGO(10w0 ++ packet_key, CH_FIRST_HASH_KEY, ch_first_level_second_table, CH_LENGTH_BIT, first_result, CH_FIRST_HASH_REVERSE, crc16); 
					READ_FROM_CUCKOO_ALGO(10w0 ++ packet_key, CH_SECOND_HASH_KEY, ch_second_level_second_table, CH_LENGTH_BIT, second_result, CH_SECOND_HASH_REVERSE, crc32); 
					READ_FROM_STASH(ch_second_stash, stash_first_result, stash_second_result, stash_third_result, stash_fourth_result, stash_fifth_result, stash_sixth_result, stash_seventh_result, stash_eighth_result);
				}

				hit_counter.read(hit_counter_read, 0);
				bool find_in_first = false; 
				bool find_in_second = false; 
				bool first_bucket_free = false;
				bool second_bucket_free = false;
				FIND_KEY_IN_BUCKET(packet_key, first_result, find_in_first);
				FIND_KEY_IN_BUCKET(packet_key, second_result, find_in_second);
				IS_FREE_SLOT_IN_BUCKET(first_result, first_bucket_free);
				IS_FREE_SLOT_IN_BUCKET(second_result, second_bucket_free);

				if (find_in_first) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (find_in_second) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_first_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_second_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_third_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_fourth_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_fifth_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_sixth_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_seventh_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (stash_eighth_result[95:0] == packet_key) {
					hit_counter.write(0, hit_counter_read + 1);
				} else if (first_bucket_free) {
					inserted_keys.write(0, inserted_keys_read+1);
					if (datapath_selection_index == 0) {
						INSERT_INTO_CUCKOO_ALGO(10w0 ++ packet_key, CH_FIRST_HASH_KEY, ch_first_level_first_table, CH_LENGTH_BIT, temp, CH_FIRST_HASH_REVERSE, crc16);
					} else {
						INSERT_INTO_CUCKOO_ALGO(10w0 ++ packet_key, CH_FIRST_HASH_KEY, ch_first_level_second_table, CH_LENGTH_BIT, temp, CH_FIRST_HASH_REVERSE, crc16);
					}
					assert( temp == KEY_VALUE_SIZE_BIT);
				} else if (second_bucket_free) {
					inserted_keys.write(0, inserted_keys_read+1);
					if (datapath_selection_index == 0) {
						INSERT_INTO_CUCKOO_ALGO(10w0 ++ packet_key, CH_SECOND_HASH_KEY, ch_second_level_first_table, CH_LENGTH_BIT, temp, CH_SECOND_HASH_REVERSE, crc32);
					} else {
						INSERT_INTO_CUCKOO_ALGO(10w0 ++ packet_key, CH_SECOND_HASH_KEY, ch_second_level_second_table, CH_LENGTH_BIT, temp, CH_SECOND_HASH_REVERSE, crc32);
					}
					assert( temp == KEY_VALUE_SIZE_BIT);
				} 
				else {
					if (datapath_selection_index == 0) {
						INSERT_INTO_STASH(10w0 ++ packet_key, ch_first_stash, ch_first_stash_counter, 1);
					} else {
						INSERT_INTO_STASH(10w0 ++ packet_key, ch_second_stash, ch_second_stash_counter, 1);
					}
					bit<32> stop_flag_value;
					stop_flag.read(stop_flag_value, 0);
					// this macro depends on # of datapaths 
					if (stop_flag_value == 0) {
						STASH_RECIRCULATE(1);
					}
				} 
				// else just drop the key!
				// for the moment just drop the packet after CH operations
				mark_to_drop(standard_metadata);

			} else {
				//recirculation
				bit<32> recirculation_counter_value;
				bit<KEY_VALUE_SIZE> ch_first_stash_read;
				bit<KEY_VALUE_SIZE> ch_second_stash_read;
				bit<KEY_VALUE_SIZE> ch_first_level_first_table_read;
				bit<KEY_VALUE_SIZE> ch_first_level_second_table_read;
				bit<KEY_VALUE_SIZE> ch_second_level_first_table_read;
				bit<KEY_VALUE_SIZE> ch_second_level_second_table_read;
				recirculation_counter.read(recirculation_counter_value, 0);
				recirculation_counter.write(0, recirculation_counter_value + 1);
				//leave the recirculation counter
				if (meta.recirculation_counter == LOOP_LIMIT) {
					mark_to_drop(standard_metadata);
					bit<32> unsuccesfull_recirculation_value;
					unsuccesfull_recirculation.read(unsuccesfull_recirculation_value, 0);
					unsuccesfull_recirculation.write(0, unsuccesfull_recirculation_value + 1);
					recirculating.write(0,0);
					return;
				}
				meta.recirculation_counter = meta.recirculation_counter + 1;
				/* DEBUG ZONE */
				//ch_stash_counter.read(stash_counter_result, 0);
				//debug_2.write(0, 29w0 ++ stash_counter_result);
				/**************/

				//first mix -> FIFO
				STASH_MIX(ch_first_stash, ch_first_stash_counter);
				STASH_MIX(ch_second_stash, ch_second_stash_counter);
				//evict from stash
				EVICT_FROM_STASH(ch_first_stash, ch_first_stash_counter, ch_first_stash_read);
				EVICT_FROM_STASH(ch_second_stash, ch_second_stash_counter, ch_second_stash_read);

				//insert into first level cuckoo
				INSERT_INTO_CUCKOO_ALGO(ch_first_stash_read, CH_FIRST_HASH_KEY, ch_first_level_first_table, CH_LENGTH_BIT, ch_first_level_first_table_read, CH_FIRST_HASH_REVERSE, crc16);
				INSERT_INTO_CUCKOO_ALGO(ch_second_stash_read, CH_FIRST_HASH_KEY, ch_first_level_second_table, CH_LENGTH_BIT, ch_first_level_second_table_read, CH_FIRST_HASH_REVERSE, crc16);

				//insert into second level cuckoo
				INSERT_INTO_CUCKOO_ALGO(ch_first_level_first_table_read, CH_SECOND_HASH_KEY, ch_second_level_first_table, CH_LENGTH_BIT, ch_second_level_first_table_read, CH_SECOND_HASH_REVERSE, crc32);
				INSERT_INTO_CUCKOO_ALGO(ch_first_level_second_table_read, CH_SECOND_HASH_KEY, ch_second_level_second_table, CH_LENGTH_BIT, ch_second_level_second_table_read, CH_SECOND_HASH_REVERSE, crc32);

				//insert into stash
				INSERT_INTO_STASH(ch_second_level_first_table_read, ch_first_stash, ch_first_stash_counter, 0);
				INSERT_INTO_STASH(ch_second_level_second_table_read, ch_second_stash, ch_second_stash_counter, 0);

				STASH_RECIRCULATE(0);

			} 
		}
	}
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	apply { 

		//TODO: do switching for non-recirculating packets

	}
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply {
		update_checksum(
				hdr.ipv4.isValid(),
				{ hdr.ipv4.version,
				hdr.ipv4.ihl,
				hdr.ipv4.diffserv,
				hdr.ipv4.totalLen,
				hdr.ipv4.identification,
				hdr.ipv4.flags,
				hdr.ipv4.fragOffset,
				hdr.ipv4.ttl,
				hdr.ipv4.protocol,
				hdr.ipv4.srcAddr,
				hdr.ipv4.dstAddr },
				hdr.ipv4.hdrChecksum,
				HashAlgorithm.csum16);
	}
}


/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		/* TODO: add deparser logic */
	}
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

	V1Switch(
			MyParser(),
			MyVerifyChecksum(),
			MyIngress(),
			MyEgress(),
			MyComputeChecksum(),
			MyDeparser()
		) main;

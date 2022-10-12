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
#define LOOP_LIMIT 50

// four path of 64  
#define CH_LENGTH 128
#define CH_LENGTH_BIT 32w128

// 106 bits per register, first 96 bits for key and others for value 
// two levels of ch, 4 tables per level (4 parallel datapaths)
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_first_level_first_table;
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_first_level_second_table;
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_first_level_third_table;
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_first_level_fourth_table;
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_second_level_first_table;
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_second_level_second_table;
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_second_level_third_table;
register<bit<KEY_VALUE_SIZE>>(CH_LENGTH) ch_second_level_fourth_table;
register<bit<KEY_VALUE_SIZE>>(STASH_LENGTH) ch_first_stash;
register<bit<KEY_VALUE_SIZE>>(STASH_LENGTH) ch_second_stash;
register<bit<KEY_VALUE_SIZE>>(STASH_LENGTH) ch_third_stash;
register<bit<KEY_VALUE_SIZE>>(STASH_LENGTH) ch_fourth_stash;
register<bit<32>>(1) ch_first_stash_counter;
register<bit<32>>(1) ch_second_stash_counter;
register<bit<32>>(1) ch_third_stash_counter;
register<bit<32>>(1) ch_fourth_stash_counter;

register<bit<32>>(1) hit_counter;
register<bit<96>>(1) last_key;
register<bit<32>>(1) recirculation_counter;
register<bit<32>>(1) inserted_keys;
register<bit<32>>(1) discarded_keys;
register<bit<32>>(1) kicked_keys;
register<bit<32>>(1) debug;
register<bit<32>>(1) debug_1;
register<bit<32>>(1) debug_2;
register<bit<32>>(1) counter_reg;


#define STASH_RECIRCULATE { \
	bit<32> ch_first_stash_counter_read;\
	bit<32> ch_second_stash_counter_read;\
	bit<32> ch_third_stash_counter_read;\
	bit<32> ch_fourth_stash_counter_read;\
	ch_first_stash_counter.read(ch_first_stash_counter_read, 0);\
	ch_second_stash_counter.read(ch_second_stash_counter_read, 0);\
	ch_third_stash_counter.read(ch_third_stash_counter_read, 0);\
	ch_fourth_stash_counter.read(ch_fourth_stash_counter_read, 0);\
	bool bool1 = ch_first_stash_counter_read >= STASH_LENGTH/STASH_RECIRCULATION_LOAD_FACTOR;\
	bool bool2 = ch_second_stash_counter_read >= STASH_LENGTH/STASH_RECIRCULATION_LOAD_FACTOR;\
	bool bool3 = ch_third_stash_counter_read >= STASH_LENGTH/STASH_RECIRCULATION_LOAD_FACTOR;\
	bool bool4 = ch_fourth_stash_counter_read >= STASH_LENGTH/STASH_RECIRCULATION_LOAD_FACTOR;\
	if (bool1 && bool2 && bool3 && bool4) {\
		resubmit_preserving_field_list(1);\
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
		bit<2> odd_stash_counter_result;
		bit<2> even_stash_counter_result;
		bit<106> first_result;
		bit<106> second_result;
		bit<106> stash_first_result;
		bit<106> stash_second_result;
		bit<106> stash_third_result;
		bit<106> stash_fourth_result;
		bit<106> stash_fifth_result;
		bit<106> stash_sixth_result;
		bit<106> stash_seventh_result;
		bit<106> stash_eighth_result;
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


		if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_RESUBMIT) {
			inserted_keys.read(inserted_keys_read, 0);
			packet_key = 64w0 ++ hdr.ipv4.srcAddr;
			last_key.write(0, packet_key) ;
			counter_reg.read(counter_result, 0);
			counter_reg.write(0, counter_result+1);
			//computing datapath index
			hash(datapath_selection_index, HashAlgorithm.crc32, 32w0, { 3w4, packet_key }, 32w4);
			if (datapath_selection_index == 0) {
				READ_FROM_CUCKOO(packet_key, 1w0, ch_first_level_first_table, CH_LENGTH_BIT, first_result); 
				READ_FROM_CUCKOO(packet_key, 1w1, ch_second_level_first_table, CH_LENGTH_BIT, second_result); 
				READ_FROM_STASH(ch_first_stash, stash_first_result, stash_second_result, stash_third_result, stash_fourth_result, stash_fifth_result, stash_sixth_result, stash_seventh_result, stash_eighth_result);
			} else if (datapath_selection_index == 1) {
				READ_FROM_CUCKOO(packet_key, 1w0, ch_first_level_second_table, CH_LENGTH_BIT, first_result); 
				READ_FROM_CUCKOO(packet_key, 1w1, ch_second_level_second_table, CH_LENGTH_BIT, second_result); 
				READ_FROM_STASH(ch_second_stash, stash_first_result, stash_second_result, stash_third_result, stash_fourth_result, stash_fifth_result, stash_sixth_result, stash_seventh_result, stash_eighth_result);
			} else if (datapath_selection_index == 2) {
				READ_FROM_CUCKOO(packet_key, 1w0, ch_first_level_third_table, CH_LENGTH_BIT, first_result); 
				READ_FROM_CUCKOO(packet_key, 1w1, ch_second_level_third_table, CH_LENGTH_BIT, second_result); 
				READ_FROM_STASH(ch_third_stash, stash_first_result, stash_second_result, stash_third_result, stash_fourth_result, stash_fifth_result, stash_sixth_result, stash_seventh_result, stash_eighth_result);
			} else {
				READ_FROM_CUCKOO(packet_key, 1w0, ch_first_level_fourth_table, CH_LENGTH_BIT, first_result); 
				READ_FROM_CUCKOO(packet_key, 1w1, ch_second_level_fourth_table, CH_LENGTH_BIT, second_result); 
				READ_FROM_STASH(ch_fourth_stash, stash_first_result, stash_second_result, stash_third_result, stash_fourth_result, stash_fifth_result, stash_sixth_result, stash_seventh_result, stash_eighth_result);
			}

			hit_counter.read(hit_counter_read, 0);

			if (first_result[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (second_result[95:0] == packet_key) {
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
			} else if (first_result[95:0] == 96w0) {
				inserted_keys.write(0, inserted_keys_read+1);
				if (datapath_selection_index == 0) {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w0, ch_first_level_first_table, CH_LENGTH_BIT, temp);
				} else if (datapath_selection_index == 1) {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w0, ch_first_level_second_table, CH_LENGTH_BIT, temp);
				} else if (datapath_selection_index == 2) {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w0, ch_first_level_third_table, CH_LENGTH_BIT, temp);
				} else {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w0, ch_first_level_fourth_table, CH_LENGTH_BIT, temp);
				}
			} else if (second_result[95:0] == 96w0) {
				inserted_keys.write(0, inserted_keys_read+1);
				if (datapath_selection_index == 0) {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w1, ch_second_level_first_table, CH_LENGTH_BIT, temp);
				} else if (datapath_selection_index == 1) {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w1, ch_second_level_second_table, CH_LENGTH_BIT, temp);
				} else if (datapath_selection_index == 2) {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w1, ch_second_level_third_table, CH_LENGTH_BIT, temp);
				} else {
					INSERT_INTO_CUCKOO(10w0 ++ packet_key, 1w1, ch_second_level_fourth_table, CH_LENGTH_BIT, temp);
				}
			} 
			else {
				if (datapath_selection_index == 0) {
					INSERT_INTO_STASH(10w0 ++ packet_key, ch_first_stash, ch_first_stash_counter, 1);
				} else if (datapath_selection_index == 1) {
					INSERT_INTO_STASH(10w0 ++ packet_key, ch_second_stash, ch_second_stash_counter, 1);
				} else if (datapath_selection_index == 2) {
					INSERT_INTO_STASH(10w0 ++ packet_key, ch_third_stash, ch_third_stash_counter, 1);
				} else {
					INSERT_INTO_STASH(10w0 ++ packet_key, ch_fourth_stash, ch_fourth_stash_counter, 1);
				}
				// this macro depends on # of datapaths 
				STASH_RECIRCULATE;
			} 
			// else just drop the key!
			// for the moment just drop the packet after CH operations
			mark_to_drop(standard_metadata);

		} else {
			//recirculation
			bit<32> recirculation_counter_value;
			bit<KEY_VALUE_SIZE> ch_first_stash_read;
			bit<KEY_VALUE_SIZE> ch_second_stash_read;
			bit<KEY_VALUE_SIZE> ch_third_stash_read;
			bit<KEY_VALUE_SIZE> ch_fourth_stash_read;
			bit<KEY_VALUE_SIZE> ch_first_level_first_table_read;
			bit<KEY_VALUE_SIZE> ch_first_level_second_table_read;
			bit<KEY_VALUE_SIZE> ch_first_level_third_table_read;
			bit<KEY_VALUE_SIZE> ch_first_level_fourth_table_read;
			bit<KEY_VALUE_SIZE> ch_second_level_first_table_read;
			bit<KEY_VALUE_SIZE> ch_second_level_second_table_read;
			bit<KEY_VALUE_SIZE> ch_second_level_third_table_read;
			bit<KEY_VALUE_SIZE> ch_second_level_fourth_table_read;
			recirculation_counter.read(recirculation_counter_value, 0);
			recirculation_counter.write(0, recirculation_counter_value + 1);
			//leave the recirculation counter
			if (meta.recirculation_counter == LOOP_LIMIT) {
				mark_to_drop(standard_metadata);
				return;
			}
			meta.recirculation_counter = meta.recirculation_counter + 1;
			/* DEBUG ZONE */
			//ch_stash_counter.read(stash_counter_result, 0);
			//debug_2.writeS(0, 29w0 ++ stash_counter_result);
			/**************/

			//evict from stash
			EVICT_FROM_STASH(ch_first_stash, ch_first_stash_counter, ch_first_stash_read);
			EVICT_FROM_STASH(ch_second_stash, ch_second_stash_counter, ch_second_stash_read);
			EVICT_FROM_STASH(ch_third_stash, ch_third_stash_counter, ch_third_stash_read);
			EVICT_FROM_STASH(ch_fourth_stash, ch_fourth_stash_counter, ch_fourth_stash_read);

			//insert into first level cuckoo
			INSERT_INTO_CUCKOO(ch_first_stash_read, 1w0, ch_first_level_first_table, CH_LENGTH_BIT, ch_first_level_first_table_read);
			INSERT_INTO_CUCKOO(ch_second_stash_read, 1w0, ch_first_level_second_table, CH_LENGTH_BIT, ch_first_level_second_table_read);
			INSERT_INTO_CUCKOO(ch_third_stash_read, 1w0, ch_first_level_third_table, CH_LENGTH_BIT, ch_first_level_third_table_read);
			INSERT_INTO_CUCKOO(ch_fourth_stash_read, 1w0, ch_first_level_fourth_table, CH_LENGTH_BIT, ch_first_level_fourth_table_read);

			//insert into second level cuckoo
			INSERT_INTO_CUCKOO(ch_first_level_first_table_read, 1w1, ch_second_level_first_table, CH_LENGTH_BIT, ch_second_level_first_table_read);
			INSERT_INTO_CUCKOO(ch_first_level_second_table_read, 1w1, ch_second_level_second_table, CH_LENGTH_BIT, ch_second_level_second_table_read);
			INSERT_INTO_CUCKOO(ch_first_level_third_table_read, 1w1, ch_second_level_third_table, CH_LENGTH_BIT, ch_second_level_third_table_read);
			INSERT_INTO_CUCKOO(ch_first_level_fourth_table_read, 1w1, ch_second_level_fourth_table, CH_LENGTH_BIT, ch_second_level_fourth_table_read);

			//insert into stash
			INSERT_INTO_STASH(ch_second_level_first_table_read, ch_first_stash, ch_first_stash_counter, 0);
			INSERT_INTO_STASH(ch_second_level_second_table_read, ch_second_stash, ch_second_stash_counter, 0);
			INSERT_INTO_STASH(ch_second_level_third_table_read, ch_third_stash, ch_third_stash_counter, 0);
			INSERT_INTO_STASH(ch_second_level_fourth_table_read, ch_fourth_stash, ch_fourth_stash_counter, 0);
			STASH_RECIRCULATE
				
			//bit<106> debug_value;
			//bit<106> debug_1_value;
			//ch_stash.read(debug_value, 29w0 ++ (stash_counter_result - 1));
			//ch_stash.read(debug_1_value, 29w0 ++ (stash_counter_result - 2));
			//debug.write(0, debug_value[31:0]);
			//debug_1.write(0, debug_1_value[31:0]);
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

#include <v1model.p4>
#include <core.p4>

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


#define CH_LENGTH 512
#define CH_LENGTH_BIT 32w512
// macro for 512 total locations
#define INSERT_FIRST_CUCKOO(input, index, output) { \
	if (index[8:8] == 0 ) { \
		ch_first_row_even.read(output, 24w0 ++ index[7:0]); \
		ch_first_row_even.write(24w0 ++ index[7:0], input); \
	} else { \
		ch_first_row_odd.read(output, 24w0 ++ index[7:0]); \
		ch_first_row_odd.write(24w0 ++ index[7:0], input); \
	} \
}
#define INSERT_SECOND_CUCKOO(input, index, output) { \
	bit<32> temp_hash; \
	hash(temp_hash, HashAlgorithm.crc32, 32w0, { 0w0, input[95:0]}, CH_LENGTH_BIT); \
	if (temp_hash[8:8] == 0 ) { \
		ch_second_row_even.read(output, 24w0 ++ index[7:0]); \
		ch_second_row_even.write(24w0 ++ index[7:0], input); \
	} else { \
		ch_second_row_odd.read(output, 24w0 ++ index[7:0]); \
		ch_second_row_odd.write(24w0 ++ index[7:0], input); \
	} \
}

#define STASH_INSERT_ODD(input, increment) { \
	bit<2> stash_counter_read_value; \
	bit<32> discarded_read_value; \
	bit<32> kicked_read_value; \
	bit<32> inserted_keys_read_value; \
	ch_stash_counter_odd.read(stash_counter_read_value, 0); \
	inserted_keys.read(inserted_keys_read_value, 0); \
	if (stash_counter_read_value < 2 && input[95:0] != 96w0) { \
		ch_stash_odd.write(30w0 ++ stash_counter_read_value, input); \
		stash_counter_read_value = stash_counter_read_value + 1; \
		if (increment == 1) { \
			inserted_keys.write(0, inserted_keys_read_value + 1); \
		} \
	} \
	else if (stash_counter_read_value >=2 && input[95:0] != 96w0) { \
		if (increment  == 1) { \
			discarded_keys.read(discarded_read_value, 0); \
			discarded_keys.write(0, discarded_read_value + 1); \
		} \
		else { \
			kicked_keys.read(kicked_read_value, 0); \
			kicked_keys.write(0, kicked_read_value + 1); \
		} \
	} \
	ch_stash_counter_odd.write(0, stash_counter_read_value); \
}

#define STASH_INSERT_EVEN(input, increment) { \
	bit<2> stash_counter_read_value; \
	bit<32> discarded_read_value; \
	bit<32> kicked_read_value; \
	bit<32> inserted_keys_read_value; \
	ch_stash_counter_even.read(stash_counter_read_value, 0); \
	inserted_keys.read(inserted_keys_read_value, 0); \
	if (stash_counter_read_value < 2 && input[95:0] != 96w0) { \
		ch_stash_even.write(30w0 ++ stash_counter_read_value, input); \
		stash_counter_read_value = stash_counter_read_value + 1; \
		if (increment == 1) { \
			inserted_keys.write(0, inserted_keys_read_value + 1); \
		} \
	} \
	else if (stash_counter_read_value >=2 && input[95:0] != 96w0) { \
		if (increment  == 1) { \
			discarded_keys.read(discarded_read_value, 0); \
			discarded_keys.write(0, discarded_read_value + 1); \
		} \
		else { \
			kicked_keys.read(kicked_read_value, 0); \
			kicked_keys.write(0, kicked_read_value + 1); \
		} \
	} \
	ch_stash_counter_even.write(0, stash_counter_read_value); \
}

#define STASH_INSERT(input_1, input_2, increment) { \
	bit<32> hash_1; \
	bit<32> hash_2; \
	hash(hash_1, HashAlgorithm.crc32, 32w0, { 0w0, (input_1)[95:0]}, 32w512); \
	hash(hash_2, HashAlgorithm.crc32, 32w0, { 0w0, (input_2)[95:0]}, 32w512); \
	if (hash_1[8:8] == 1w0) { \
		STASH_INSERT_EVEN((input_1), increment) \
	} else { \
		STASH_INSERT_ODD((input_1), increment) \
	} \
	if (hash_2[8:8] == 1w0) { \
		STASH_INSERT_EVEN((input_2), increment) \
	} else { \
		STASH_INSERT_ODD((input_2), increment) \
	} \
}


//TODO
//#define STASH_MIX_3 { \
//	bit<106> temp_stash_0; \
//	bit<106> temp_1; \
//	ch_stash.read(temp_stash_0, 0);	 \
//	ch_stash.read(temp_1, 1);	 \
//	ch_stash.write(0, temp_1);	 \
//	ch_stash.read(temp_1, 2);	 \
//	ch_stash.write(1, temp_1);	 \
//	ch_stash.write(2, temp_stash_0);	 \
//}
//TODO	
//#define STASH_MIX_4 { \
//	bit<106> temp_stash_0; \
//	bit<106> temp_1; \
//	ch_stash.read(temp_stash_0, 0);	 \
//	ch_stash.read(temp_1, 1);	 \
//	ch_stash.write(0, temp_1);	 \
//	ch_stash.read(temp_1, 2);	 \
//	ch_stash.write(1, temp_1);	 \
//	ch_stash.read(temp_1, 3);	 \
//	ch_stash.write(2, temp_1);	 \
//	ch_stash.write(3, temp_stash_0);	 \
//}
//#define STASH_MIX { \
//	bit<3> stash_counter_read_value; \
//	ch_stash_counter.read(stash_counter_read_value, 0); \
//	if (stash_counter_read_value == 3) { \
//		STASH_MIX_3 \
//	} \
//	if (stash_counter_read_value == 4) { \
//		STASH_MIX_4 \
//	} \
//}

// zeroing input variables 
#define STASH_READ(output_1, output_2) { \
	bit<2> odd_stash_counter_read_value; \
	bit<2> even_stash_counter_read_value; \
	output_1 = 0; \
	output_2 = 0; \
	ch_stash_counter_odd.read(odd_stash_counter_read_value, 0); \
	ch_stash_counter_even.read(even_stash_counter_read_value, 0); \
	if (odd_stash_counter_read_value > 0 && even_stash_counter_read_value > 0) { \
		ch_stash_odd.read(output_1, 30w0 ++ (odd_stash_counter_read_value - 1)); \
		ch_stash_even.read(output_2, 30w0 ++ (even_stash_counter_read_value - 1)); \
		ch_stash_odd.write(30w0 ++ (odd_stash_counter_read_value - 1), 0); \
		ch_stash_even.write(30w0 ++ (even_stash_counter_read_value - 1), 0); \
		ch_stash_counter_odd.write(0, odd_stash_counter_read_value - 1); \
		ch_stash_counter_even.write(0, even_stash_counter_read_value - 1); \
	} \
	else { \
		return; \
	} \
}

#define STASH_RECIRCULATE { \
	bit<2> odd_stash_counter_read_value; \
	bit<2> even_stash_counter_read_value; \
	ch_stash_counter_odd.read(odd_stash_counter_read_value, 0); \
	ch_stash_counter_even.read(even_stash_counter_read_value, 0); \
	if (odd_stash_counter_read_value > 0 && even_stash_counter_read_value > 0 ) { \
			resubmit_preserving_field_list(1); \
	} \
}
	

// 106 bits per register, first 96 bits for key and others for value 
register<bit<106>>(CH_LENGTH/2) ch_first_row_odd;
register<bit<106>>(CH_LENGTH/2) ch_first_row_even;
register<bit<106>>(CH_LENGTH/2) ch_second_row_odd;
register<bit<106>>(CH_LENGTH/2) ch_second_row_even;
register<bit<106>>(2) ch_stash_odd;
register<bit<106>>(2) ch_stash_even;
register<bit<2>>(1) ch_stash_counter_odd;
register<bit<2>>(1) ch_stash_counter_even;
register<bit<10>>(1) counter_reg;
register<bit<32>>(1) hit_counter;
register<bit<96>>(1) last_key;
register<bit<32>>(1) recirculation_counter;
register<bit<32>>(1) inserted_keys;
register<bit<32>>(1) discarded_keys;
register<bit<32>>(1) kicked_keys;
register<bit<32>>(1) debug;
register<bit<32>>(1) debug_1;
register<bit<32>>(1) debug_2;

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
		bit<32> first_index;
		bit<32> second_index;
		bit<96> packet_key;
		bit<10> counter_result;
		bit<2> odd_stash_counter_result;
		bit<2> even_stash_counter_result;
		bit<106> first_result;
		bit<106> second_result;
		bit<106> stash_result_0;
		bit<106> stash_result_1;
		bit<106> temp;
		bit<106> stash_evicted_1;
		bit<106> stash_evicted_2;
		bit<32> hit_counter_read;
		bit<32> inserted_keys_read;

		ch_stash_counter_odd.read(odd_stash_counter_result, 0);
		ch_stash_counter_even.read(even_stash_counter_result, 0);

		if (standard_metadata.parser_error != error.NoError) {
			mark_to_drop(standard_metadata);
			//return should work as well
			exit;
		}
		if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_RESUBMIT) {
			//packet_key = hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.srcPort ++ hdr.tcp.dstPort;
			//HACK
			packet_key = 64w0 ++ hdr.ipv4.srcAddr;
			counter_reg.read(counter_result, 0);
			counter_reg.write(0, counter_result+1);
		} else {
			packet_key = meta.keyvalue[95:0];
			counter_result = meta.keyvalue[105:96];
		}

		last_key.write(0, packet_key) ;
		inserted_keys.read(inserted_keys_read, 0);

		if (standard_metadata.instance_type != PKT_INSTANCE_TYPE_RESUBMIT) {
			hash(first_index, HashAlgorithm.crc32, 32w0, { 0w0, packet_key }, CH_LENGTH_BIT);
			hash(second_index, HashAlgorithm.crc32, 32w0, { 1w0, packet_key }, CH_LENGTH_BIT);
			//debug.write(0, first_index);

			if (first_index[8:8]==0) {
				ch_first_row_even.read(first_result, 24w0 ++ first_index[7:0]);
				ch_second_row_even.read(second_result, 24w0 ++ second_index[7:0]);
				ch_stash_odd.read(stash_result_0, 0);
				ch_stash_odd.read(stash_result_1, 1);
			}
			else {
				ch_first_row_odd.read(first_result, 24w0 ++ first_index[7:0]);
				ch_second_row_odd.read(second_result, 24w0 ++ second_index[7:0]);
				ch_stash_even.read(stash_result_0, 0);
				ch_stash_even.read(stash_result_1, 1);
			}
			hit_counter.read(hit_counter_read, 0);
			if (first_result[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (second_result[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (stash_result_0[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (stash_result_1[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (first_result[95:0] == 96w0) {
				if (first_index[8:8]==0) {
					ch_first_row_even.write(24w0 ++ first_index[7:0], 10w0 ++ packet_key);
				}
				else {
					ch_first_row_odd.write(24w0 ++ first_index[7:0], 10w0 ++ packet_key);
				}	
				inserted_keys.write(0, inserted_keys_read+1);
			} else if (second_result[95:0] == 96w0) {
				if (first_index[8:8]==0) {
					ch_second_row_even.write(24w0 ++ second_index[7:0], 10w0 ++ packet_key);
				}
				else {
					ch_second_row_odd.write(24w0 ++ second_index[7:0], 10w0 ++ packet_key);
				}	
				inserted_keys.write(0, inserted_keys_read+1);
			} 
			else if (odd_stash_counter_result < 2 || even_stash_counter_result < 2) {
				STASH_INSERT(10w0 ++ packet_key, 106w0, 1)
				STASH_RECIRCULATE
			} 
			else {
				bit<32> discarded_keys_read;
				discarded_keys.read(discarded_keys_read, 0);
				discarded_keys.write(0, discarded_keys_read + 1);
			}
			// else just drop the key!
			// for the moment just drop the packet after CH operations
			mark_to_drop(standard_metadata);

		} else {
			//recirculation
			bit<32> recirculation_counter_value;
			// hash of evicted keys
			bit<32> evicted_1_hash_first;
			bit<32> evicted_1_hash_second;
			bit<32> evicted_2_hash_first;
			bit<32> evicted_2_hash_second;
			// values read from the ch
			bit<106> evicted_1_ch_first;
			bit<106> evicted_2_ch_first;
			bit<106> evicted_1_ch_second;
			bit<106> evicted_2_ch_second;
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
			//debug_2.write(0, 29w0 ++ stash_counter_result);
			/**************/
			STASH_READ(stash_evicted_1, stash_evicted_2)
			//compute two hash per key
			hash(evicted_1_hash_first, HashAlgorithm.crc32, 32w0, { 0w0, stash_evicted_1[95:0]}, CH_LENGTH_BIT);
			hash(evicted_2_hash_first, HashAlgorithm.crc32, 32w0, { 0w0, stash_evicted_2[95:0]}, CH_LENGTH_BIT);

			//access two different memories
			INSERT_FIRST_CUCKOO(stash_evicted_1, evicted_1_hash_first, evicted_1_ch_first)
			INSERT_FIRST_CUCKOO(stash_evicted_2, evicted_2_hash_first, evicted_2_ch_first)

			hash(evicted_1_hash_second, HashAlgorithm.crc32, 32w0, { 1w0, evicted_1_ch_first[95:0]}, CH_LENGTH_BIT);
			hash(evicted_2_hash_second, HashAlgorithm.crc32, 32w0, { 1w0, evicted_2_ch_first[95:0]}, CH_LENGTH_BIT);

			INSERT_SECOND_CUCKOO(evicted_1_ch_first, evicted_1_hash_second, evicted_1_ch_second);
			INSERT_SECOND_CUCKOO(evicted_2_ch_first, evicted_2_hash_second, evicted_2_ch_second);

			STASH_INSERT(evicted_1_ch_second, evicted_2_ch_second, 0)
			//STASH_MIX
			// recirculate trying to free the stash
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

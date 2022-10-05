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
#define LOOP_LIMIT 200


#define CH_LENGTH 512
#define CH_LENGTH_BIT 32w512
// 106 bits per register, first 96 bits for key and others for value 
//register<bit<106>>(CH_LENGTH) ch_first_row;

register<bit<106>>(CH_LENGTH/2) ch_first_row_odd;
register<bit<106>>(CH_LENGTH/2) ch_first_row_even;
//register<bit<106>>(CH_LENGTH/2) ch_first_row_00;

//register<bit<32>>(CH_LENGTH) ch_first_row_KL;
//register<bit<32>>(CH_LENGTH) ch_first_row_KM;
//register<bit<32>>(CH_LENGTH) ch_first_row_KH;
//register<bit<10>>(CH_LENGTH) ch_first_row_V;

//register<bit<106>>(CH_LENGTH) ch_second_row;
register<bit<106>>(CH_LENGTH/2) ch_second_row_odd;
register<bit<106>>(CH_LENGTH/2) ch_second_row_even;
register<bit<106>>(4) ch_stash;
register<bit<3>>(1) ch_stash_counter;
register<bit<10>>(1) counter_reg;
register<bit<32>>(1) hit_counter;
register<bit<96>>(1) last_key;
register<bit<32>>(1) recirculation_counter;
register<bit<32>>(1) inserted_keys;
register<bit<32>>(1) discarded_keys;
register<bit<32>>(1) debug;
register<bit<32>>(1) debug_1;

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
		bit<3> stash_counter_result;
		bit<106> first_result;
		bit<106> second_result;
		bit<106> stash_result_0;
		bit<106> stash_result_1;
		bit<106> stash_result_2;
		bit<106> stash_result_3;
		bit<106> temp;
		bit<106> stash_evicted_1;
		bit<106> stash_evicted_2;
		bit<32> hit_counter_read;
		bit<32> inserted_keys_read;

		ch_stash_counter.read(stash_counter_result, 0);

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
			hash(second_index, HashAlgorithm.crc32, 32w0, { 24w0, packet_key }, CH_LENGTH_BIT);
			//debug.write(0, first_index);

			if (first_index[8:8]==0) {
				ch_first_row_even.read(first_result, 24w0 ++ first_index[7:0]);
			}
			else {
				ch_first_row_odd.read(first_result, 24w0 ++ first_index[7:0]);
			}
			if (second_index[8:8]==0) {
				ch_second_row_even.read(second_result, 24w0 ++ second_index[7:0]);
			}
			else {
				ch_second_row_odd.read(second_result, 24w0 ++ second_index[7:0]);
			}
			ch_stash.read(stash_result_0, 0);
			ch_stash.read(stash_result_1, 1);
			ch_stash.read(stash_result_2, 2);
			ch_stash.read(stash_result_3, 3);
			hit_counter.read(hit_counter_read, 0);
			if (first_result[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (second_result[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (stash_result_0[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (stash_result_1[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (stash_result_2[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (stash_result_3[95:0] == packet_key) {
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
				if (second_index[8:8]==0) {
					ch_second_row_even.write(24w0 ++ second_index[7:0], 10w0 ++ packet_key);
				}
				else {
					ch_second_row_odd.write(24w0 ++ second_index[7:0], 10w0 ++ packet_key);
				}	
				inserted_keys.write(0, inserted_keys_read+1);
			} 
			else if (stash_counter_result < 4) {
				// stash treated as a stack
				ch_stash.write(29w0 ++ stash_counter_result, 10w0 ++ packet_key);
				ch_stash_counter.write(0, stash_counter_result + 1);
				inserted_keys.write(0, inserted_keys_read+1);
				if (stash_counter_result + 1 ==  4) {
					resubmit_preserving_field_list(1);
				}
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
			//evict 2 keys from the stash
			ch_stash_counter.read(stash_counter_result, 0);
			ch_stash.read(stash_evicted_1, 29w0 ++  (stash_counter_result - 1));
			ch_stash.read(stash_evicted_2, 29w0 ++  (stash_counter_result - 2));
			ch_stash_counter.write(0, stash_counter_result - 2);
			//compute two hash per key
			hash(evicted_1_hash_first, HashAlgorithm.crc32, 32w0, { 0w0, stash_evicted_1[95:0]}, CH_LENGTH_BIT);
			hash(evicted_2_hash_first, HashAlgorithm.crc32, 32w0, { 0w0, stash_evicted_2[95:0]}, CH_LENGTH_BIT);

			//access two different memories
			if (evicted_1_hash_first[8:8] != evicted_2_hash_first[8:8] ) {
				//insert stash elements into ch 1 and evict corresponding values
				if (evicted_1_hash_first[8:8] == 0 ) {
					ch_first_row_even.read(evicted_1_ch_first, 24w0 ++ evicted_1_hash_first[7:0]);
					ch_first_row_even.write(24w0 ++ evicted_1_hash_first[7:0], stash_evicted_1);
				} else {
					ch_first_row_odd.read(evicted_1_ch_first, 24w0 ++ evicted_1_hash_first[7:0]);
					ch_first_row_odd.write(24w0 ++ evicted_1_hash_first[7:0], stash_evicted_1);
				}
				if (evicted_2_hash_first[8:8] == 0 ) {
					ch_first_row_even.read(evicted_2_ch_first, 24w0 ++ evicted_2_hash_first[7:0]);
					ch_first_row_even.write(24w0 ++ evicted_2_hash_first[7:0], stash_evicted_2);
				} else {
					ch_first_row_odd.read(evicted_2_ch_first, 24w0 ++ evicted_2_hash_first[7:0]);
					ch_first_row_odd.write(24w0 ++ evicted_2_hash_first[7:0], stash_evicted_2);
				}
			} 
			// else insert only first key
			else {
				if (evicted_1_hash_first[8:8] == 0 ) {
					ch_first_row_even.read(evicted_1_ch_first, 24w0 ++ evicted_1_hash_first[7:0]);
					ch_first_row_even.write(24w0 ++ evicted_1_hash_first[7:0], stash_evicted_1);
				} else {
					ch_first_row_odd.read(evicted_1_ch_first, 24w0 ++ evicted_1_hash_first[7:0] );
					ch_first_row_odd.write(24w0 ++ evicted_1_hash_first[7:0], stash_evicted_1);
				}
				// second key evicted from stash become the second key evicted from ch first, for code coherence
				evicted_2_ch_first = stash_evicted_2;
			}


			//now, we need to check what we read from ch_first
			// both keys extracted from first ch are != 0
			if (evicted_1_ch_first[95:0] != 0 && evicted_2_ch_first[95:0] != 0) {
				// need to try inserting both in second ch 
				hash(evicted_1_hash_second, HashAlgorithm.crc32, 32w0, { 24w0, evicted_1_ch_first[95:0]}, CH_LENGTH_BIT);
				hash(evicted_2_hash_second, HashAlgorithm.crc32, 32w0, { 24w0, evicted_2_ch_first[95:0]}, CH_LENGTH_BIT);
				// access to different halves -> both inserted 	
				// if we can access two different locations ... 
				if (evicted_1_hash_second[8:8] != evicted_2_hash_second[8:8]) {
					// substitute values
					if (evicted_1_hash_second[8:8] == 0) {
						ch_second_row_even.read(evicted_1_ch_second, 24w0 ++ evicted_1_hash_second[7:0]);
						ch_second_row_even.write(24w0 ++ evicted_1_hash_second[7:0], evicted_1_ch_first);
					} else {
						ch_second_row_odd.read(evicted_1_ch_second, 24w0 ++ evicted_1_hash_second[7:0]);
						ch_second_row_odd.write(24w0 ++ evicted_1_hash_second[7:0], evicted_1_ch_first);
					}
					if (evicted_2_hash_second[8:8] == 0) {
						ch_second_row_even.read(evicted_2_ch_second, 24w0 ++ evicted_2_hash_second[7:0]);
						ch_second_row_even.write(24w0 ++ evicted_2_hash_second[7:0], evicted_2_ch_first);
					} else {
						ch_second_row_odd.read(evicted_2_ch_second, 24w0 ++ evicted_2_hash_second[7:0]);
						ch_second_row_odd.write(24w0 ++ evicted_2_hash_second[7:0], evicted_2_ch_first);
					}
					// save the eviction into the stash	
					ch_stash_counter.read(stash_counter_result, 0);
					// if read values are != 0, update stash counter
					if ( evicted_1_ch_second[95:0] != 0 ) {
						ch_stash.write(29w0 ++ stash_counter_result, evicted_1_ch_second);
						stash_counter_result = stash_counter_result + 1;
					}
					if ( evicted_2_ch_second[95:0] != 0 ) {
						ch_stash.write(29w0 ++ stash_counter_result, evicted_2_ch_second);
						stash_counter_result = stash_counter_result + 1;
					}
					ch_stash_counter.write(0, stash_counter_result);
				} 
				// else only access location for first key and save the other into the stash
				else {
					// insert only the first key
					if (evicted_1_hash_second[8:8] == 0) {
						ch_second_row_even.read(evicted_1_ch_second, 24w0 ++ evicted_1_hash_second[7:0]);
						ch_second_row_even.write(24w0 ++ evicted_1_hash_second[7:0], evicted_1_ch_first);
					} else {
						ch_second_row_odd.read(evicted_1_ch_second, 24w0 ++ evicted_1_hash_second[7:0]);
						ch_second_row_odd.write(24w0 ++ evicted_1_hash_second[7:0], evicted_1_ch_first);
					}
					ch_stash_counter.read(stash_counter_result, 0);
					if ( evicted_1_ch_second[95:0] != 0 ) {
						ch_stash.write(29w0 ++ stash_counter_result, evicted_1_ch_second);
						stash_counter_result = stash_counter_result + 1;
					}
					//save into the stash the second key read from first ch
					if ( evicted_2_ch_first[95:0] != 0 ) {
						ch_stash.write(29w0 ++ stash_counter_result, evicted_2_ch_first);
						stash_counter_result = stash_counter_result + 1;
					}
					ch_stash_counter.write(0, stash_counter_result);
				}
			} 
			// only first  evicted key from ch 1 is different from 0
			else if (evicted_1_ch_first[95:0] != 0) {
				// only check first value
				hash(evicted_1_hash_second, HashAlgorithm.crc32, 32w0, { 24w0, evicted_1_ch_first[95:0]}, CH_LENGTH_BIT);
				if (evicted_1_hash_second[8:8] == 0) {
					ch_second_row_even.read(evicted_1_ch_second, 24w0 ++ evicted_1_hash_second[7:0]);
					ch_second_row_even.write(24w0 ++ evicted_1_hash_second[7:0], evicted_1_ch_first);
				} else {
					ch_second_row_odd.read(evicted_1_ch_second, 24w0 ++ evicted_1_hash_second[7:0]);
					ch_second_row_odd.write(24w0 ++ evicted_1_hash_second[7:0], evicted_1_ch_first);
				}
				ch_stash_counter.read(stash_counter_result, 0);
				if ( evicted_1_ch_second[95:0] != 0 ) {
					ch_stash.write(29w0 ++ stash_counter_result, evicted_1_ch_second);
					stash_counter_result = stash_counter_result + 1;
				}
				ch_stash_counter.write(0, stash_counter_result);
			} else if (evicted_2_ch_first[95:0] != 0) {
				hash(evicted_2_hash_second, HashAlgorithm.crc32, 32w0, { 24w0, evicted_2_ch_first[95:0]}, CH_LENGTH_BIT);
				if (evicted_2_hash_second[8:8] == 0) {
					ch_second_row_even.read(evicted_2_ch_second, 24w0 ++ evicted_2_hash_second[7:0]);
					ch_second_row_even.write(24w0 ++ evicted_2_hash_second[7:0], evicted_2_ch_first);
				} else {
					ch_second_row_odd.read(evicted_2_ch_second, 24w0 ++ evicted_2_hash_second[7:0]);
					ch_second_row_odd.write(24w0 ++ evicted_2_hash_second[7:0], evicted_2_ch_first);
				}
				ch_stash_counter.read(stash_counter_result, 0);
				if ( evicted_2_ch_second[95:0] != 0 ) {
					ch_stash.write(29w0 ++ stash_counter_result, evicted_2_ch_second);
					stash_counter_result = stash_counter_result + 1;
				}
				ch_stash_counter.write(0, stash_counter_result);
			} else {
				// greetings, both insertions worked on first ch!
			}
			// recirculate trying to free the stash
			ch_stash_counter.read(stash_counter_result, 0);
			if (stash_counter_result == 4) {
				//mix stash
				bit<106> temp_stash_0;
				bit<106> temp_1;

				ch_stash.read(temp_stash_0, 0);	

				ch_stash.read(temp_1, 1);	
				ch_stash.write(0, temp_1);	

				ch_stash.read(temp_1, 2);	
				ch_stash.write(1, temp_1);	

				ch_stash.read(temp_1, 3);	
				ch_stash.write(2, temp_1);	
	
				ch_stash.write(3, temp_stash_0);

				resubmit_preserving_field_list(1);
			}
			bit<106> debug_value;
			bit<106> debug_1_value;
			ch_stash.read(debug_value, 29w0 ++ (stash_counter_result - 1));
			ch_stash.read(debug_1_value, 29w0 ++ (stash_counter_result - 2));
			debug.write(0, debug_value[31:0]);
			debug_1.write(0, debug_1_value[31:0]);
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

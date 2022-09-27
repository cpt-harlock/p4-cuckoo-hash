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


#define CH_LENGTH 512
#define CH_LENGTH_BIT 16w512
// 106 bits per register, first 96 bits for key and others for value 
register<bit<106>>(CH_LENGTH) ch_first_row;
register<bit<106>>(CH_LENGTH) ch_second_row;
register<bit<10>>(1) counter_reg;
register<bit<32>>(1) hit_counter;
register<bit<96>>(1) last_key;
register<bit<32>>(1) recirculation_counter;
register<bit<32>>(1) inserted_keys;

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
	bit<3> recirculation_counter;
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
		bit<106> first_result;
		bit<106> second_result;
		bit<106> temp;
		bit<32> hit_counter_read;
		bit<32> inserted_keys_read;


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
			hash(first_index, HashAlgorithm.crc32, 32w0, { 0w0, packet_key }, 32w512);
			hash(second_index, HashAlgorithm.crc32, 32w0, { 1w0, packet_key }, 32w512);
			ch_first_row.read(first_result, first_index);
			ch_second_row.read(second_result, second_index);
			hit_counter.read(hit_counter_read, 0);
			if (first_result[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (second_result[95:0] == packet_key) {
				hit_counter.write(0, hit_counter_read + 1);
			} else if (first_result[95:0] == 96w0) {
				//HACK
				//ch_first_row.write(first_index, counter_result ++ packet_key);
				ch_first_row.write(first_index, 10w0 ++ packet_key);
				inserted_keys.write(0, inserted_keys_read+1);
			} else if (second_result[95:0] == 96w0) {
				//HACK
				//ch_second_row.write(second_index, counter_result ++ packet_key);
				ch_second_row.write(second_index, 10w0 ++ packet_key);
				inserted_keys.write(0, inserted_keys_read+1);
			} else {
				//TODO: discover usage of session id	
				//sending a packet duplicate to egress for switching
				//clone_preserving_field_list(CloneType.I2E, 32w500, 1);
				//meta.keyvalue = counter_result ++ packet_key;
				meta.keyvalue = 10w0 ++ packet_key;
				resubmit_preserving_field_list(1);
			}
			// for the moment just drop the packet after CH operations
			mark_to_drop(standard_metadata);

		} else {
			//recirculation
			bit<32> recirculation_counter_value;
			recirculation_counter.read(recirculation_counter_value, 0);
			recirculation_counter.write(0, recirculation_counter_value + 1);
			meta.recirculation_counter = meta.recirculation_counter + 1;
			if (meta.recirculation_counter == 7) {
				mark_to_drop(standard_metadata);
				return;
			}
			hash(first_index, HashAlgorithm.crc32, 32w0, { 0w0, packet_key }, 32w512);
			ch_first_row.read(first_result, first_index);
			temp = first_result;
			//ch_first_row.write(first_index, counter_result ++ packet_key);
			ch_first_row.write(first_index, 10w0 ++ packet_key);
			if (temp[95:0] != 96w0) {
				hash(second_index, HashAlgorithm.crc32, 32w0, { 1w0, temp[95:0]}, 32w512);
				ch_second_row.read(second_result, second_index);
				ch_second_row.write(second_index, temp);
				//just for coherence :)
				temp = second_result;
				if (temp[95:0] != 96w0) {
					meta.keyvalue = temp;
					resubmit_preserving_field_list(1);
				} else {
					inserted_keys.write(0, inserted_keys_read+1);
				}
				mark_to_drop(standard_metadata);
			} else {
				inserted_keys.write(0, inserted_keys_read+1);
				mark_to_drop(standard_metadata);	
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

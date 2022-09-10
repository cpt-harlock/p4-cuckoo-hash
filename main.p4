#include <v1model.p4>
#include <core.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


#define CH_LENGTH 512
#define CH_LENGTH_BIT 16w512
// 106 bits per register, first 96 bits for key and others for value 
register<bit<106>>(CH_LENGTH) ch_first_row;
register<bit<106>>(CH_LENGTH) ch_second_row;
register<bit<10>>(1) counter_reg;

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

struct metadata {
    /* empty */
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
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet { 
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			0x0800: parse_ip;
			default: reject;
		}
    }

	state parse_ip {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			0x6: parse_tcp;
			default: reject;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
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
    //action drop() {
    //    mark_to_drop(standard_metadata);
    //}

    //action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    //    /* TODO: fill out code in action body */
    //}

    //table ipv4_lpm {
    //    key = {
    //        hdr.ipv4.dstAddr: lpm;
    //    }
    //    actions = {
    //        ipv4_forward;
    //        drop;
    //        NoAction;
    //    }
    //    size = 1024;
    //    default_action = NoAction();
    //}

    //apply {
    //    /* TODO: fix ingress control logic
    //     *  - ipv4_lpm should be applied only when IPv4 header is valid
    //     */
    //    ipv4_lpm.apply();
    //}

	//compute CH indices
    apply {
	bit<32> first_index;
	bit<32> second_index;
	bit<96> packet_key = hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr ++ hdr.tcp.srcPort ++ hdr.tcp.dstPort;
	hash(first_index, HashAlgorithm.crc16, 16w0, { 0w0, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort }, 16w512);
	hash(second_index, HashAlgorithm.crc16, 16w0, { 1w0, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort }, 16w512);
	bit<106> first_result;
	bit<106> second_result;
	bit<10> counter_result;
	ch_first_row.read(first_result, first_index);
	ch_second_row.read(second_result, second_index);
	if (first_result[95:0] == packet_key) {
		//do nothing
	} else if (second_result[95:0] == packet_key) {
		//do nothing
	} else if (first_result[95:0] == 96w0) {
		counter_reg.read(counter_result, 0);
		ch_first_row.write(first_index, counter_result ++ packet_key);
		counter_reg.write(0, counter_result+1);
	} else if (second_result[95:0] == 96w0) {
		counter_reg.read(counter_result, 0);
		ch_second_row.write(second_index, counter_result ++ packet_key);
		counter_reg.write(0, counter_result+1);
	} 
	// TODO: implement recirculation!

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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

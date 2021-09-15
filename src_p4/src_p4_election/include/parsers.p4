/*************************************************************************
*********************** P A R S E R  *******************************
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
        transition select(hdr.ethernet.ethertype){
            TYPE_EXP: parse_distrib_algo;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition parse_data_payload;
    }


    state parse_distrib_algo {
        packet.extract(hdr.sync_header);
        transition select(hdr.sync_header.message_type){
            NORMAL_PKT: parse_distrib_msg;
            default: accept;
        }
    }

    state parse_distrib_msg{
        packet.extract(hdr.msg);
        transition accept;
    }
    state parse_data_payload{
        packet.extract(hdr.data_payload);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.CPU);
        packet.emit(hdr.sync_header);
        packet.emit(hdr.msg);
    }
}

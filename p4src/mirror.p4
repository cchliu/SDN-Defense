#include "includes/headers.p4"
#include "includes/parser.p4"

#define HASH_BIT_WIDTH 10
#define HASH_TABLE_SIZE 1024

header_type custom_metadata_t {
    fields {
        K_val: 16;
        protocol: 8;
        hash_val: 16;
        count_val: 16;
    }
}
metadata custom_metadata_t custom_metadata;

// Define the field list to compute hash on
// Use the 5-tuple of 
// (src ip, dst ip, src port, dst port, ip protocol)
field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation flow_hash {
    input {
        hash_fields;
    }
    algorithm: csum16;
    output_width: HASH_BIT_WIDTH;
}

// Define registers to store the counts
register flow_pkt_counter {
    width: 16;
    instance_count: HASH_TABLE_SIZE;
}

action _no_op() {
    no_op();
}

// Update counter on each TCP packet
action add_flow_pkt_counter() {
    modify_field_with_hash_based_offset(custom_metadata.hash_val, 0, flow_hash, HASH_TABLE_SIZE);
    register_read(custom_metadata.count_val, flow_pkt_counter, custom_metadata.hash_val);
    add_to_field(custom_metadata.count_val, 1);
    register_write(flow_pkt_counter, custom_metadata.hash_val, custom_metadata.count_val);
}

// Clear counter when receiving SYN packet
// or SYN-ACK packet
action clear_flow_pkt_counter() {
    modify_field_with_hash_based_offset(custom_metadata.hash_val, 0, flow_hash, HASH_TABLE_SIZE);
    register_write(flow_pkt_counter, custom_metadata.hash_val, 0);
}

table clear_pkt_counter {
    reads {
        tcp.ctrl: exact;
    }
    actions {
        clear_flow_pkt_counter;
        _no_op;
    }
    size: 5;
}
    
table update_pkt_counter {
    actions {
        add_flow_pkt_counter;
    }
    size: 5;
}


// Define table select_tcp               
action label_tcp() {
    modify_field(custom_metadata.protocol, 6);
}

table select_tcp {
    reads {
        tcp: valid;
    }
    actions {
        _no_op;
        label_tcp;
    }
}

// Load K parameter from runtime flow rules
action set_K(k_input) {
    modify_field(custom_metadata.K_val, k_input);
}

table load_K {
    actions { set_K; }
    size: 5;
}

// Define table mirror_select
field_list i2e_mirror_info {
    standard_metadata;
}

// Mirror packets
action mirror() {
    clone_ingress_pkt_to_egress(100, i2e_mirror_info);
}

table mirror_select {
    actions { mirror; }
    size: 5;
}

// Define table forward
action set_nhop(port) {
    modify_field(standard_metadata.egress_spec, port);
}

table forward {
    actions {set_nhop;}
    size: 5;
}


control ingress {
    apply(load_K);
    apply(select_tcp);
    if(custom_metadata.protocol == 6){
        apply(clear_pkt_counter);
        apply(update_pkt_counter);
        if(custom_metadata.count_val <= custom_metadata.K_val) {
            apply(mirror_select);
        }
    }
    apply(forward);
} 
        
control egress {
}    

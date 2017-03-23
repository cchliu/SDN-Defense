#include "includes/headers.p4"
#include "includes/parser.p4"

action _drop() {
    drop();
}

action set_nhop(port) {
    modify_field(standard_metadata.egress_spec, port);
}

table forward {
    actions {
        set_nhop;
    }
    size: 5;
}

control ingress {
    apply(forward);
}

control egress {
}
    

//
// Created by kohuz on 13.10.22.
//

#pragma once
#include <tuple>
#define NF_VERSION 5
tuple<in_addr_t, in_addr_t, int, int, int, int> ipv4_packet(const u_char *packet, int *total_length);
packet assemble_packet(flow flow_record, int sequence);
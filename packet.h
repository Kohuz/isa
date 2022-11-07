#pragma once
#include <tuple>
#define NF_VERSION 5
#define __FAVOR_BSD
tuple<in_addr_t, in_addr_t, int, int, int, int> ipv4_packet(const u_char *packet, int *total_length, int *fin, int *flags);
packet assemble_packet(flow flow_record, int sequence);
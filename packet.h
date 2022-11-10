#pragma once
#include <tuple>
#define NF_VERSION 5
#define __FAVOR_BSD

/**
 * @brief Extracts information from a packet into a tuple for the unique key in map
 *
 * @return tuple<in_addr_t, in_addr_t, int, int, int, int>
 */
tuple<in_addr_t, in_addr_t, int, int, int, int> ipv4_packet(const u_char *packet, int *total_length, int *fin, int *flags);

/**
 * @brief Creates a packet according to cisco documentation from the flow record structure
 *
 * @return packet
 */
packet assemble_packet(flow flow_record, int sequence);
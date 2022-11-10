#pragma once
#define __FAVOR_BSD
#include <stdint.h>
#include <time.h>

#include <tuple>
#include "structures.h"

using namespace std;

/**
 * @brief Represents headers and record based on the cisco documentation:
 * https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
 *
 */
struct netflow5_header
{
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
};

struct netflow5_record
{
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctects;
    uint32_t First;
    uint32_t Last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
};

struct packet
{
    netflow5_header header;
    netflow5_record payload;
};

/**
 * @brief Represents one flow in the map structure
 *
 */
struct flow
{
    in_addr_t s_addr;
    in_addr_t d_addr;
    uint16_t s_port;
    uint16_t d_port;
    uint8_t protocol;
    uint32_t dOctets;
    uint32_t dPkts;
    uint8_t tos;
    uint32_t time_sec;
    uint32_t time_nsec;
    int flags;
    bool tcp_flag;
    uint32_t last_packet;
    uint32_t first_packet;
    long last_usec;
    long first_usec;
};

// Key to identify flows
typedef tuple<in_addr_t, in_addr_t, int, int, int, int>
    tuple_key;

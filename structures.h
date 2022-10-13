#pragma once

#include <stdint.h>
#include <time.h>


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
// https://github.com/aabc/ipt-netflow/blob/master/ipt_NETFLOW.h
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
    uint64_t time_sec;
    bool tcp_flags;
    time_t last_packet;
    time_t first_packet;
};


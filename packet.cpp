#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <netinet/in.h>

#include <iostream>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "map_struct.h"
#include "structures.h"
#include "packet.h"

#define __FAVOR_BSD
#define SIZE_ETHERNET 14
#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17

tuple<in_addr_t, in_addr_t, int, int, int, int> ipv4_packet(const u_char *packet, int *length, int *fin, int *flags)
{
    const struct ip *ip;
    ip = (struct ip *)(packet + SIZE_ETHERNET);
    if (ip->ip_v != 4)
    {
        fprintf(stderr, "Invalid version in the ip header");
        exit(EXIT_FAILURE);
    }
    // print_ipv4(ip);

    auto src_ip = ip->ip_src.s_addr;
    auto dst_ip = ip->ip_dst.s_addr;
    int tos = ip->ip_tos;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;

    int size_ip = ip->ip_hl * 4;
    *length = *length - size_ip;
    if (ip->ip_p == ICMP_PROTOCOL)
    {
        protocol = ICMP_PROTOCOL;
    }
    else if (ip->ip_p == TCP_PROTOCOL)
    {
        const struct tcphdr *tcp; /* The TCP header */
        tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + size_ip);
        *flags = tcp->th_flags;
        //printf("tcp flags %x\n", tcp->th_flags);
        if (tcp->th_flags & TH_FIN)
        {
            *fin = 1;
        }
        if (tcp->th_flags & TH_SYN)
        {

        }
        if (tcp->th_flags & TH_RST)
        {
            *fin = 1;
        }
        if (tcp->th_flags & TH_PUSH)
        {
        }
        if (tcp->th_flags & TH_ACK)
        {

        }




        protocol = TCP_PROTOCOL;
        src_port = ntohs(tcp->th_sport);
        dst_port = ntohs(tcp->th_dport);
    }
    else if (ip->ip_p == UDP_PROTOCOL)
    {
        const struct udphdr *udp; /* The TCP header */
        udp = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);
        protocol = UDP_PROTOCOL;
        src_port = ntohs(udp->uh_sport);
        dst_port = ntohs(udp->uh_dport);
    }

    return make_tuple(ntohl(src_ip), ntohl(dst_ip), protocol, src_port, dst_port, tos);
}

packet assemble_packet(flow flow_record, int sequence)
{
    netflow5_header header;
    header.version = htons(NF_VERSION);
    header.count = htons(1);
    header.flow_sequence = htonl(sequence);
    header.SysUptime = htonl(flow_record.time_sec);
    header.unix_secs = htonl(flow_record.time_sec);
    header.unix_nsecs = htonl(flow_record.time_nsec);
    header.engine_id = 0;
    header.engine_type = 0;
    header.sampling_interval = htons(0);

    netflow5_record record;
    record.srcaddr = htonl(flow_record.s_addr);
    record.dstaddr = htonl(flow_record.d_addr);
    record.nexthop = 0;
    record.input = 0;
    record.output = 0;
    record.dPkts = htonl(flow_record.dPkts);
    record.dOctects = htonl(flow_record.dOctets);
    record.First = htonl(flow_record.first_packet);
    record.Last = htonl(flow_record.last_packet);
    // printf("first: %d\n", flow_record.first_packet - flow_record.time_sec);
    // printf("last: %d\n", flow_record.last_packet - flow_record.time_sec);
    // printf("sysuptime: %d\n", flow_record.time_sec);
    record.srcport = htons(flow_record.s_port);
    record.dstport = htons(flow_record.d_port);
    record.pad1 = 0;
    record.tcp_flags = 1;
    record.prot = flow_record.protocol;
    record.tos = flow_record.tos;
    record.src_as = 0;
    record.dst_as = 0;
    record.src_mask = 0;
    record.dst_mask = 0;
    record.pad2 = 0;

    packet pkt;
    pkt.header = header;
    pkt.payload = record;

    return pkt;
}

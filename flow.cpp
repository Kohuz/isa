#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <iostream>
#include <unordered_map>

using namespace std;

#define SIZE_ETHERNET 14
#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define IPV4_ETHER 2048
#define ARP_ETHER 2054

typedef struct Packet Packet;
struct Packet
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t src_mask;
    uint32_t dst_mask;
    uint32_t src_port;
    uint32_t dst_port;
    uint8_t *protocol;
    uint16_t ToS;
};
// https://github.com/aabc/ipt-netflow/blob/master/ipt_NETFLOW.h
struct netflow5_record
{
    uint32_t s_addr;
    uint32_t d_addr;
    uint32_t nexthop;
    uint16_t i_ifc;
    uint16_t o_ifc;
    uint32_t nr_packets;
    uint32_t nr_octets;
    uint32_t first_ms;
    uint32_t last_ms;
    uint16_t s_port;
    uint16_t d_port;
    uint8_t reserved;
    uint8_t tcp_flags;
    uint8_t protocol;
    uint8_t tos;
    uint16_t s_as;
    uint16_t d_as;
    uint8_t s_mask;
    uint8_t d_mask;
    uint16_t padding;
} __attribute__((packed));
// struct Netflow_row
// {
//     Packet packet;
//     uint16_t flags;
//     uint32_t number_of_packets;
//     uint32_t number_of_bytes;
//     // TODO: time type
//     uint64_t first;
//     uint64_t last;
//     uint32_t next_hop;
//     uint32_t input_interface;
//     uint32_t output_interface;
//     uint8_t srcAS;
//     uint8_t dstAS;
//     uint16_t active;
//     uint16_t idle;
//     bool tcp_flags;
// };

// src and dst addresses, protocol, ports, tos
typedef tuple<int, int, int, int, int, int> tuple_key;
// https://stackoverflow.com/questions/11408934/using-a-stdtuple-as-key-for-stdunordered-map
struct key_hash : public unary_function<tuple_key, size_t>
{
    size_t operator()(const tuple_key &k) const
    {
        return ((get<0>(k) ^ get<1>(k) + get<2>(k) ^ get<3>(k) - get<4>(k) ^ get<5>(k)) % 20) << 2;
    }
};

struct key_equal : public binary_function<tuple_key, tuple_key, bool>
{
    bool operator()(const tuple_key &v0, const tuple_key &v1) const
    {
        return (
            get<0>(v0) == get<0>(v1) &&
            get<1>(v0) == get<1>(v1) &&
            get<2>(v0) == get<2>(v1) &&
            get<3>(v0) == get<3>(v1) &&
            get<4>(v0) == get<4>(v1) &&
            get<5>(v0) == get<5>(v1));
    }
};

typedef unordered_map<tuple_key, netflow5_record, key_hash, key_equal> map_t;
string get_ip(struct in_addr address)
{
    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(address), addr, INET_ADDRSTRLEN);
    printf("addr %s\n", addr);
}

tuple<uint32_t, uint32_t, int, int, int, int> ipv4_packet(const u_char *packet, int total_length)
{
    const struct ip *ip;
    ip = (struct ip *)(packet + SIZE_ETHERNET);
    if (ip->ip_v != 4)
    {
        fprintf(stderr, "Invalid version in the ip header");
        exit(EXIT_FAILURE);
    }
    // print_ipv4(ip);

    auto src_ip = ip->ip_src;
    auto dst_ip = ip->ip_dst;
    int tos = ip->ip_tos;
    int src_port = 0;
    int dst_port = 0;
    int protocol = 0;

    int size_ip = ip->ip_hl * 4;

    if (ip->ip_p == ICMP_PROTOCOL)
    {
        protocol = ICMP_PROTOCOL;
    }
    else if (ip->ip_p == TCP_PROTOCOL)
    {
        const struct tcphdr *tcp; /* The TCP header */
        tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + size_ip);
        protocol = TCP_PROTOCOL;
        src_port = htons(tcp->th_sport);
        dst_port = htons(tcp->th_dport);
    }
    else if (ip->ip_p == UDP_PROTOCOL)
    {
        const struct udphdr *udp; /* The TCP header */
        udp = (struct udphdr *)(packet + SIZE_ETHERNET + size_ip);
        protocol = UDP_PROTOCOL;
        src_port = htons(udp->uh_sport);
        dst_port = htons(udp->uh_dport);
    }
    printf("here addr: %d", src_ip.s_addr);
    return make_tuple(src_ip.s_addr, dst_ip.s_addr, protocol, src_port, dst_port, tos);
}
int main(int argc, char *argv[])
{
    string usage = "./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n";
    if (argc > 7)
    {
        cerr << usage;
        return EXIT_FAILURE;
    }

    int opt;
    char *file = NULL;
    int active_timeout = 60;
    int inactive_timeout = 10;

    /***************************************************************************************
     *    Title:  Optional arguments with getopt_long(3)
     *    Author: Lars Erik Wik
     *    Date: August 13, 2021
     *    Availability: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
     *
     ***************************************************************************************/
    // The argument parsing was inspired by the mentioned above

    const struct option options[] =
        {

            {"file", optional_argument, 0, 'f'},

            {NULL, 0, 0, '\0'}};

    while ((opt = getopt_long(argc, argv, "f::", options, NULL)) != -1)
    {
        printf("%d\n", opt);
        switch (opt)
        {

        case 'f': // option with optional argument
            if (optarg == NULL)
            {
                printf("default");
            }
            else
            {

                file = optarg;
                printf("%s\n", optarg);
            }
            break;

        default:
            cerr << usage;
            return EXIT_FAILURE;
        }
    }
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const uint8_t *packet;

    // map_t m;

    // data d;
    // d.x = "test data";
    // m[make_tuple("d", "df", 2, 3, 4, 8)] = d;

    // auto itr = m.find(make_tuple("d", "df", 2, 3, 4, 9));
    // if (m.end() != itr)
    // {
    //     cout << "x: " << itr->second.x;
    // }
    // else
    // {
    //     cout << "not found";
    // }

    if (!file)
    {
        // TODO: ARGUMENTS
        handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL)
        {
            printf("Could not open file %s: %s\n", argv[1], errbuf);
            exit(-1);
        }
    }
    else
    {
        // handle = pcap_fopen_offline(stdin, errbuf);
        handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL)
        {
            printf("Could not open file %s: %s\n", argv[1], errbuf);
            exit(-1);
        }
    }
    while (packet = pcap_next(handle, &header))
    {

        printf("got one packet\n");
        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header *)(packet);
        int length = header.caplen;
        printf("length: %d bytes\n", length);
        printf("time: %ld\n", header.ts.tv_sec);
        tuple<int, int, int, int, int, int> tpl;
        if (htons(ethernet->ether_type) == IPV4_ETHER)
        {
            tpl = ipv4_packet(packet, length);
        }

        netflow5_record record;
        record.s_addr = get<0>(tpl);
        record.d_addr = get<1>(tpl);
        record.protocol = get<2>(tpl);
        record.s_port = get<3>(tpl);
        record.d_port = get<4>(tpl);
        record.tos = get<5>(tpl);
        printf("record: \n");
        printf("s_addr %d\n", get<0>(tpl));
        printf("d_addr %d\n", get<1>(tpl));
        printf("%d\n", record.protocol);
        printf("sport %d\n", record.s_port);
        printf("dport %d\n", record.d_port);
        printf("%d\n", record.tos);
        printf("\n\n");
    }
}
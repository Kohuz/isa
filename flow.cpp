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
#include <tuple>
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
    in_addr_t s_addr;
    in_addr_t d_addr;
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
    bool tcp_flags;
    uint8_t protocol;
    uint8_t tos;
    uint16_t s_as;
    uint16_t d_as;
    uint8_t s_mask;
    uint8_t d_mask;
    uint16_t padding;
} __attribute__((packed));

struct flow
{
    in_addr_t s_addr;
    in_addr_t d_addr;
    uint16_t s_port;
    uint16_t d_port;
    uint8_t protocol;
    // TODO:
    timeval Last;
    uint32_t dOctets;
    uint32_t dPkts;
    uint8_t tos;
    bool tcp_flags;
    time_t last_packet;
    time_t first_packet;
};

// src and dst addresses, protocol, ports, tos
typedef tuple<in_addr_t, in_addr_t, int, int, int, int>
    tuple_key;
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

typedef unordered_map<tuple_key, flow, key_hash, key_equal> map_t;
int check_number(char *number)
{
    char *fail_ptr = NULL;
    string err_msg = "-n argument has to be a positive integer\n";
    int num = strtol(number, &fail_ptr, 10);

    if (*fail_ptr)
    {
        cout << err_msg;
        exit(EXIT_FAILURE);
    }

    if (num < 1)
    {
        cout << err_msg;
        exit(EXIT_FAILURE);
    }
    return num;
}

tuple<in_addr_t, in_addr_t, int, int, int, int> ipv4_packet(const u_char *packet, int total_length)
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
    int src_port = 0;
    int dst_port = 0;
    int protocol = 0;

    int size_ip = ip->ip_hl * 4;

    if (ip->ip_p == ICMP_PROTOCOL)
    {
        printf("here");
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

    return make_tuple(src_ip, dst_ip, protocol, src_port, dst_port, tos);
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
    string collector_ip = "127.0.0.1:2055";
    int active_timeout = 60;
    int inactive_timeout = 10;
    int limit = 1024;

    /***************************************************************************************
     *    Title:  Optional arguments with getopt_long(3)
     *    Author: Lars Erik Wik
     *    Date: August 13, 2021
     *    Availability: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
     *
     ***************************************************************************************/
    // The argument parsing was inspired by the mentioned above

    int option;

    while ((option = getopt(argc, argv, "f:c:a:i:m:")) != -1)
    {
        switch (option)
        {

        case 'f':
            file = optarg;
            break;
        case 'c':
            collector_ip = optarg;
            break;
        case 'a':
            active_timeout = check_number(optarg);
            break;
        case 'i':
            inactive_timeout = check_number(optarg);
            break;
        case 'm':
            limit = check_number(optarg);
            break;

        default:
            cout << usage;
            exit(EXIT_FAILURE);
        }
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const uint8_t *packet;

    map_t flows;

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
        handle = pcap_open_offline("-", errbuf);
        if (handle == NULL)
        {
            printf("Could not open file %s: %s\n", argv[1], errbuf);
            exit(-1);
        }
    }
    else
    {
        // handle = pcap_fopen_offline(stdin, errbuf);
        handle = pcap_open_offline(file, errbuf);
        if (handle == NULL)
        {
            printf("Could not open file %s: %s\n", argv[1], errbuf);
            exit(-1);
        }
    }
    int exported_flows = 0;
    while (packet = pcap_next(handle, &header))
    {

        printf("got one packet\n");
        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header *)(packet);
        int length = header.caplen;
        printf("length: %d bytes\n", length);
        auto my_time = header.ts.tv_sec;
        printf("time: %ld\n", my_time);
        tuple<in_addr_t, in_addr_t, int, int, int, int> tpl;
        if (htons(ethernet->ether_type) == IPV4_ETHER)
        {
            tpl = ipv4_packet(packet, length);
        }

        flow record;
        record.s_addr = get<0>(tpl);
        record.d_addr = get<1>(tpl);
        record.protocol = get<2>(tpl);
        record.s_port = get<3>(tpl);
        record.d_port = get<4>(tpl);
        record.tos = get<5>(tpl);
        // printf("record: \n");
        // cout << "src ip: " << get<0>(tpl) << '\n';
        // cout << "dst ip: " << get<1>(tpl) << '\n';

        // printf("%d\n", record.protocol);
        // printf("sport %d\n", record.s_port);
        // printf("dport %d\n", record.d_port);
        // printf("%d\n", record.tos);
        // printf("\n\n");
        printf("protocol: %d\n", record.protocol);
        auto comp_tuple = make_tuple(record.s_addr, record.d_addr, record.protocol, record.s_port, record.d_port, record.tos);
        auto found = flows.find(comp_tuple);
        cout << "=============\n";
        printf(" %ul\n", get<0>(comp_tuple));
        printf(" %ul\n", get<1>(comp_tuple));
        printf(" %d\n", get<2>(comp_tuple));
        printf(" %d\n", get<3>(comp_tuple));
        printf(" %d\n", get<4>(comp_tuple));
        printf(" %d\n", get<5>(comp_tuple));

        cout << "Time diffs\n";
        cout << "=================\n";
        for (auto const flow : flows)
        {

            auto time_diff = difftime(my_time, flow.second.last_packet);
            cout << "times: " << my_time << " " << flow.second.last_packet << "\n";
            cout << flow.second.s_port << "\n";
            cout << flow.second.protocol << "\n";
            cout << time_diff << " inactive time diff\n";
            auto to_erase = flow.second;
            auto tuple_erase = make_tuple(to_erase.s_addr, to_erase.d_addr,
                                          to_erase.protocol, to_erase.s_port, to_erase.d_port, to_erase.tos);
            cout << "SIZE: "
                 << flows.size() << "\n";
            if (time_diff > inactive_timeout)
            {
                cout << "EXPORTING INACTIVE\n\n";

                flows.erase(tuple_erase);
                continue;
            }

            time_diff = difftime(my_time, flow.second.first_packet);
            cout << time_diff << " active time diff\n";
            if (time_diff > active_timeout)
            {
                cout << "EXPORTING ACTIVE\n\n";
                flows.erase(tuple_erase);

                continue;
            }
        }
        cout << "=================\n";

        if (flows.end() != found)
        {

            flows[comp_tuple].dPkts++;
            flows[comp_tuple].last_packet = header.ts.tv_sec;
            cout << "dpkts: " << flows[comp_tuple].dPkts << '\n';
            cout << flows[comp_tuple].last_packet << "last packet\n";
            cout << "added\n";
        }
        else
        {
            flows[comp_tuple] = record;
            flows[comp_tuple].first_packet = header.ts.tv_sec;
            flows[comp_tuple].last_packet = header.ts.tv_sec;
            cout << flows[comp_tuple].first_packet << "first packet\n";
            cout << flows[comp_tuple].last_packet << "last packet\n";
            cout << "created\n";
        }
        cout << "=============\n";
    }
    cout << "size: " << flows.size();
}
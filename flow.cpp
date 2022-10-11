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
#include <errno.h>
#include <iostream>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <sstream>

using namespace std;

#define SIZE_ETHERNET 14
#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define IPV4_ETHER 2048
#define ARP_ETHER 2054
#define NF_VERSION 5

typedef struct netflow5_header netflow5_header;
typedef struct netflow5_record netflow5_record;
struct netflow5_header
{
    uint8_t version;
    uint16_t count;
    uint32_t SysUptim;
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

void print_flows(map_t flows)
{
    for (auto const flow : flows)
    {
        cout << "Src IP " << flow.second.s_addr << "\n";
        cout << "Dst IP " << flow.second.d_addr << "\n";
        cout << "Src Port " << flow.second.s_port << "\n";
        cout << "Dst Port " << flow.second.d_port << "\n";
        printf("tos %d \n", flow.second.tos);
        cout << "dPakets " << flow.second.dPkts << "\n";
        printf("protocol %d \n", flow.second.protocol);
        cout << "dOctets " << flow.second.dOctets << "\n";
        cout << "========================\n";
    }
}

packet assemble_packet(flow flow_record, int sequence)
{
    netflow5_header header;
    header.version = 5;
    header.count = 1;
    header.flow_sequence = sequence;
    header.unix_nsecs = 0;
    header.unix_secs = 0;
    header.engine_id =0;
    header.engine_type = 0;
    header.sampling_interval = 0;

    netflow5_record  record;
    record.srcaddr = flow_record.s_addr;
    record.dstaddr = flow_record.d_addr;
    record.nexthop = 0;
    record.input = 0;
    record.output = 0;
    record.dPkts = flow_record.dPkts;
    record.dOctects = flow_record.dOctets;
    record.First = flow_record.first_packet;
    record.srcport = flow_record.s_port;
    record.dstport = flow_record.d_port;
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
// from isa prednaska
void export_packet(flow flow, string collector_ip, string port)
{
    // TODO: check port is a number
    int sock;
    struct sockaddr_in server, from;
    struct hostent *servent;
    int len = collector_ip.length();
    char buffer[1024];

    // declaring character array
    char collector[len + 1];

    // copying the contents of the
    // string to char array
    strcpy(collector, collector_ip.c_str());
    if ((servent = gethostbyname(collector)) == NULL)
    { // check the first parameter
        cerr << collector << "\n";
        cerr << "gethostbyname() failed\n";
        exit(1);
    }


    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr, servent->h_addr, servent->h_length);

    server.sin_port = htons(stoi(port)); // server port (network byte order)
    server.sin_family = AF_INET;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    { // create a client socket
        cerr << "gethostbyname() failed\n";
        exit(1);
    }

//TODO: sequence number
    packet pkt = assemble_packet(flow, 1);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1){
        printf("eerno: %s\n", strerror(errno));
        exit(1);
            }
    printf("* Server socket created\n");
    int i = send(sock,&pkt,sizeof(pkt),0);
    if(i == -1) {
        printf("ret value: %d\n", i);
        printf("eerno: %s\n", strerror(errno));
        exit(1);
    }

    // assemble_packet()
    //  if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == -1)
    //  {
    //      cerr << (1, "connect() failed");
    //      exit(1);
    //  }
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
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;

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

    vector<string> split_ip;
    string segment;
    stringstream strstream(collector_ip);
    // TODO: HANDLE BAD INPUT
    while (getline(strstream, segment, ':'))
    {
        split_ip.push_back(segment);
    }
    string coll_ip = split_ip[0];
    string port = split_ip[1];
    pcap_t *
            handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const uint8_t *packet;

    map_t flows;

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

        // Create flow record
        flow record;
        record.s_addr = get<0>(tpl);
        record.d_addr = get<1>(tpl);
        record.protocol = get<2>(tpl);
        record.s_port = get<3>(tpl);
        record.d_port = get<4>(tpl);
        record.tos = get<5>(tpl);

        // Try to find it in captured flows
        auto comp_tuple = make_tuple(record.s_addr, record.d_addr, record.protocol, record.s_port, record.d_port, record.tos);
        auto found = flows.find(comp_tuple);

        vector<tuple<in_addr_t, in_addr_t, int, int, int, int> > to_delete;
        for (auto flow = flows.begin(); flow != flows.end(); flow++)
        {
            printf("exported flows: %d\n\n", exported_flows);

            auto time_diff = difftime(my_time, flow->second.last_packet);

            auto to_erase = flow->second;
            auto tuple_erase = make_tuple(to_erase.s_addr, to_erase.d_addr,
                                          to_erase.protocol, to_erase.s_port, to_erase.d_port, to_erase.tos);
            cout << "SIZE: "
                 << flows.size() << "\n";

            if (time_diff > inactive_timeout)
            {
                cout << "EXPORTING INACTIVE\n\n";
                export_packet(flows[tuple_erase], coll_ip, port);
                to_delete.push_back(tuple_erase);
                exported_flows++;
                continue;
            }

            time_diff = difftime(my_time, flow->second.first_packet);
            if (time_diff > active_timeout)
            {
                cout << "EXPORTING ACTIVE\n\n";
                export_packet(flows[tuple_erase], coll_ip, port);
                to_delete.push_back(tuple_erase);
                exported_flows++;

                continue;
            }
        }
        for (auto const& item: to_delete){
            flows.erase(item);
        }

        if (flows.end() != found)
        {

            flows[comp_tuple].dPkts++;
            flows[comp_tuple].dOctets += header.caplen;
            flows[comp_tuple].last_packet = header.ts.tv_sec;

            cout << "added\n";
        }
        else
        {
            flows[comp_tuple] = record;
            flows[comp_tuple].first_packet = header.ts.tv_sec;
            flows[comp_tuple].last_packet = header.ts.tv_sec;
            flows[comp_tuple].dPkts = 1;
            flows[comp_tuple].dOctets = header.caplen;

            cout << "created\n";
        }
    }
    // print_flows(flows);
    cout << "size: " << flows.size();
}
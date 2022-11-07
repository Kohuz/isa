#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <iostream>
#include <tuple>
#include <map>
#include <vector>
#include <bits/stdc++.h>
#include "structures.h"
#include "packet.h"
#include "export.h"
#include "helpers.h"
#define __FAVOR_BSD

#define IPV4_ETHER 2048

using namespace std;
typedef struct netflow5_header netflow5_header;
typedef struct netflow5_record netflow5_record;

int main(int argc, char *argv[])
{
    string usage = "./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n";
    if (argc > 10)
    {
        cerr << usage;
        return EXIT_FAILURE;
    }

    char *file = NULL;
    string collector_ip = "127.0.0.1:2055";
    int active_timeout = 60;
    int inactive_timeout = 10;
    int limit = 1024;

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

    string coll_ip;
    string port;
    stringstream strstream(collector_ip);
    if (collector_ip.find(':') == string::npos)
    {
        coll_ip = collector_ip;
        port = "2055";
    }
    else
    {
        while (getline(strstream, segment, ':'))
        {
            split_ip.push_back(segment);
        }
        coll_ip = split_ip[0];
        port = split_ip[1];
        check_port(port);
    }
    // TODO: HANDLE BAD INPUT

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const uint8_t *packet;

    map<tuple_key , flow> flows;
    //map_t flows;

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

    struct bpf_program compiled_filter;
    if (pcap_compile(handle, &compiled_filter, "tcp or udp or icmp", 0, 0) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", "tcp or udp or icmp", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &compiled_filter) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", "tcp or udp or icmp", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    int exported_flows = 1;

    while (packet = pcap_next(handle, &header))
    {
        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header *)(packet);
        int length;
        int fin = 0;
        uint32_t my_time = header.ts.tv_sec;
        uint32_t my_time_nsec = header.ts.tv_usec * 1000;
        auto time_for_timeout = header.ts.tv_sec * 1000000 + header.ts.tv_usec;
        int flags = 0;

        tuple<in_addr_t, in_addr_t, int, int, int, int> tpl;

        if (htons(ethernet->ether_type) == IPV4_ETHER)
        {
            tpl = ipv4_packet(packet, &length, &fin, &flags);
        }

        // Create flow record
        flow record;
        record.s_addr = get<0>(tpl);
        record.d_addr = get<1>(tpl);
        record.protocol = get<2>(tpl);
        record.s_port = get<3>(tpl);
        record.d_port = get<4>(tpl);
        record.tos = get<5>(tpl);
        record.tcp_flag = fin;
        fin = 0;

        // Try to find it in captured flows
        auto comp_tuple = make_tuple(record.s_addr, record.d_addr, record.protocol, record.s_port, record.d_port, record.tos);
        if (record.tcp_flag == 1)
        {
            auto fin_found = flows.find(comp_tuple);
            if (flows.end() != fin_found)
            {

                flows[comp_tuple].dPkts++;
                flows[comp_tuple].dOctets += header.caplen - 14;
                flows[comp_tuple].last_packet = my_time;
                flows[comp_tuple].last_usec = time_for_timeout;
                flows[comp_tuple].flags = flows[comp_tuple].flags | flags;
                export_packet(flows[comp_tuple], coll_ip, port, exported_flows);

                flows.erase(fin_found);
                exported_flows++;
            }

            else
            {
                record.dPkts = 1;
                record.time_sec = my_time;
                record.flags = flags;
                record.time_nsec = my_time_nsec;
                record.first_packet = my_time;
                record.last_packet = my_time;
                record.dOctets = header.caplen - 14;
                export_packet(record, coll_ip, port, exported_flows);
            }
        }

        vector<tuple<in_addr_t, in_addr_t, int, int, int, int>> to_delete;
        vector<flow> to_sort;

        for (auto flow = flows.begin(); flow != flows.end(); flow++)
        {

            auto inactive_time_diff = time_for_timeout - flow->second.last_usec;
            auto active_time_diff = time_for_timeout - flow->second.first_usec;
            auto to_erase = flow->second;
            auto tuple_erase = make_tuple(to_erase.s_addr, to_erase.d_addr,
                                          to_erase.protocol, to_erase.s_port, to_erase.d_port, to_erase.tos);


            if (inactive_time_diff > inactive_timeout * 1000000)
            {
                to_sort.push_back(flows[tuple_erase]);
                to_delete.push_back(tuple_erase);
                exported_flows++;
            }

            else if (active_time_diff > active_timeout * 1000000)
            {
                to_sort.push_back(flows[tuple_erase]);
                to_delete.push_back(tuple_erase);
                exported_flows++;
            }
        }

        sort(to_sort.begin(), to_sort.end(), compareFlows);
        for (auto flow : to_sort)
        {
            export_packet(flow, coll_ip, port, exported_flows);
            cout << "EXPORTING timers\n";
        }

        for (auto const &item : to_delete)
        {
            flows.erase(item);
        }
        // cout << flows.size() << "\n";
        if (record.tcp_flag == 1)
        {
            continue;
        }
        auto found = flows.find(comp_tuple);
        if (flows.end() == found && flows.size() == limit)
        {
            auto latest = find_latest(flows);
            cout << "export memory\n";
            export_packet(flows[latest], coll_ip, port, exported_flows);
            flows.erase(latest);
        }
        if (flows.end() != found)
        {

            flows[comp_tuple].dPkts++;
            flows[comp_tuple].dOctets += header.caplen - 14;
            flows[comp_tuple].last_packet = my_time;
            flows[comp_tuple].last_usec = time_for_timeout;
            flows[comp_tuple].flags = flows[comp_tuple].flags | flags;
        }
        else
        {

            flows[comp_tuple] = record;
            flows[comp_tuple].first_packet = my_time;
            flows[comp_tuple].last_packet = my_time;
            flows[comp_tuple].last_usec = time_for_timeout;
            flows[comp_tuple].first_usec = time_for_timeout;
            flows[comp_tuple].dPkts = 1;
            flows[comp_tuple].time_sec = my_time;
            flows[comp_tuple].flags = flags;
            flows[comp_tuple].time_nsec = my_time_nsec;

            flows[comp_tuple].dOctets = header.caplen - 14;

            // cout << "created\n";
        }
    }
    vector<flow> to_sort;
    for (auto flow = flows.begin(); flow != flows.end(); flow++)
    {
        to_sort.push_back(flow->second);
    }
    sort(to_sort.begin(), to_sort.end(), compareFlows);
    for (auto flow : to_sort)
    {
        export_packet(flow, coll_ip, port, exported_flows);
        exported_flows++;
        cout << "EXPORTING AFTER END\n";
    }
}
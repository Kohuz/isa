#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <pcap/pcap.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <errno.h>
#include <iostream>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <sstream>
#include "structures.h"
#include "map_struct.h"
#include "packet.h"
#include "export.h"

#define IPV4_ETHER 2048

using namespace std;
typedef struct netflow5_header netflow5_header;
typedef struct netflow5_record netflow5_record;

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

tuple<in_addr_t, in_addr_t, int, int, int, int> find_latest(map_t flows)
{
    auto latest = flows.begin();

    for (auto flow = flows.begin(); flow != flows.end(); flow++)
    {
        if (flow->second.last_packet > latest->second.last_packet)
        {
            latest = flow;
        }
    }
    auto to_return = latest->second;
    return make_tuple(to_return.s_addr, to_return.d_addr,
                      to_return.protocol, to_return.s_port, to_return.d_port, to_return.tos);
}

int main(int argc, char *argv[])
{
    string usage = "./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n";
    if (argc > 7)
    {
        cerr << usage;
        return EXIT_FAILURE;
    }

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
    pcap_t *handle;
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

    int exported_flows = 1;
    int boot_time;
    int i = 0;
    while (packet = pcap_next(handle, &header))
    {
        if (i == 0)
        {
            boot_time = header.ts.tv_sec * 1000;
            printf("THIS IS BOOT TIME %d\n", boot_time);
            i++;
        }

        const struct ether_header *ethernet; /* The ethernet header */
        ethernet = (struct ether_header *)(packet);
        int length = header.caplen;
        int fin = 0;
        uint32_t my_time = header.ts.tv_sec;
        uint32_t my_time_nsec = header.ts.tv_usec * 1000;
        auto time_for_timeout = header.ts.tv_sec;

        tuple<in_addr_t, in_addr_t, int, int, int, int> tpl;

        if (htons(ethernet->ether_type) == IPV4_ETHER)
        {
            tpl = ipv4_packet(packet, &length, &fin);
        }

        // Create flow record
        flow record;
        record.s_addr = get<0>(tpl);
        record.d_addr = get<1>(tpl);
        record.protocol = get<2>(tpl);
        record.s_port = get<3>(tpl);
        record.d_port = get<4>(tpl);
        record.tos = get<5>(tpl);
        record.tcp_flags = fin;
        fin = 0;

        // Try to find it in captured flows
        auto comp_tuple = make_tuple(record.s_addr, record.d_addr, record.protocol, record.s_port, record.d_port, record.tos);
        auto found = flows.find(comp_tuple);

        vector<tuple<in_addr_t, in_addr_t, int, int, int, int>> to_delete;
        for (auto flow = flows.begin(); flow != flows.end(); flow++)
        {

            auto inactive_time_diff = my_time - flow->second.last_packet;
            auto active_time_diff = my_time - flow->second.first_packet;
            // cout << "boot time " << my_time - flow->second.last_packet << "\n";
            auto to_erase = flow->second;
            auto tuple_erase = make_tuple(to_erase.s_addr, to_erase.d_addr,
                                          to_erase.protocol, to_erase.s_port, to_erase.d_port, to_erase.tos);

            if (flows[tuple_erase].tcp_flags == 1)
            {
                cout << "EXPORTING fin\n\n";
                export_packet(flows[tuple_erase], coll_ip, port, exported_flows);
                to_delete.push_back(tuple_erase);
                exported_flows++;
                continue;
            }
            else if (inactive_time_diff > inactive_timeout)
            {
                cout << "EXPORTING INACTIVE\n\n";
                export_packet(flows[tuple_erase], coll_ip, port, exported_flows);
                to_delete.push_back(tuple_erase);
                exported_flows++;
            }

            else if (active_time_diff > active_timeout)
            {
                cout << "EXPORTING ACTIVE\n\n";
                export_packet(flows[tuple_erase], coll_ip, port, exported_flows);
                to_delete.push_back(tuple_erase);
                exported_flows++;
            }
        }
        for (auto const &item : to_delete)
        {
            flows.erase(item);
        }
        cout << flows.size() << "\n";

        if (flows.end() != found)
        {

            flows[comp_tuple].dPkts++;
            flows[comp_tuple].dOctets += header.caplen - 14;
            flows[comp_tuple].last_packet = my_time;
            // cout << flows[comp_tuple].last_packet << "\n";
            //  flows[comp_tuple].time_sec = (my_time - start_time);

            cout << "added\n";
        }
        else
        {
            if (flows.size() == limit)
            {
                auto latest = find_latest(flows);
            }
            flows[comp_tuple] = record;
            flows[comp_tuple].first_packet = my_time;
            flows[comp_tuple].last_packet = my_time;
            flows[comp_tuple].dPkts = 1;
            flows[comp_tuple].time_sec = my_time;
            flows[comp_tuple].time_nsec = my_time_nsec;

            flows[comp_tuple].dOctets = header.caplen - 14;

            cout << "created\n";
        }
    }
    for (auto flow = flows.begin(); flow != flows.end(); flow++)
    {
        auto to_export = flow->second;
        auto tuple_export = make_tuple(to_export.s_addr, to_export.d_addr,
                                       to_export.protocol, to_export.s_port, to_export.d_port, to_export.tos);
        export_packet(flows[tuple_export], coll_ip, port, exported_flows);
        exported_flows++;
        cout << "EXPORTING AFTER END\n";
    }
}
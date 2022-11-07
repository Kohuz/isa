#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <iostream>
#include <tuple>
#include <map>
#include <bits/stdc++.h>
#include "structures.h"
#include "helpers.h"

int check_number(const char *number)
{
    char *fail_ptr = NULL;
    string err_msg = "Port argument has to be a positive integer\n";
    int num = strtol(number, &fail_ptr, 10);

    if (*fail_ptr)
    {
        cerr << err_msg;
        exit(EXIT_FAILURE);
    }

    if (num < 1)
    {
        cerr << err_msg;
        exit(EXIT_FAILURE);
    }
    return num;
}
void check_port(string port)
{
    const char *cstr = port.c_str();
    int prt_num = check_number(cstr);
    if (prt_num <= 1023 || prt_num > 65535)
    {
        cerr << "Not a valid port number\n";
        exit(EXIT_FAILURE);
    }
}

tuple<in_addr_t, in_addr_t, int, int, int, int> find_latest(map<tuple_key , flow> flows)
{
    auto latest = flows.begin();

    for (auto flow = flows.begin(); flow != flows.end(); flow++)
    {
        if (flow->second.first_usec < latest->second.first_usec)
        {
            latest = flow;
        }
    }
    auto to_return = latest->second;
    return make_tuple(to_return.s_addr, to_return.d_addr,
                      to_return.protocol, to_return.s_port, to_return.d_port, to_return.tos);
}

bool compareFlows(flow f1, flow f2)
{
    return (f1.first_usec < f2.first_usec);
}

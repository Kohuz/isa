#pragma once

int check_number(const char *number);
void check_port(string port);
tuple<in_addr_t, in_addr_t, int, int, int, int> find_latest(map<tuple_key , flow> flows);
bool compareFlows(flow f1, flow f2);


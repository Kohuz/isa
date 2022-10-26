//
// Created by kohuz on 13.10.22.
//

#pragma  once


#include <tuple>
#include <unordered_map>
#include "structures.h"
#define __FAVOR_BSD

using namespace std;

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


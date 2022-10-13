
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


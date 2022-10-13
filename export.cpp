#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>
#include <iostream>
#include <string>
#include <tuple>
#include <chrono>

#include "map_struct.h"
#include "structures.h"
#include "packet.h"
#include "export.h"

using namespace std;
using namespace std::chrono;
// from isa prednaska
void export_packet(flow flow, string collector_ip, string port, int sequence)
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

    // TODO: sequence number
    packet pkt = assemble_packet(flow, sequence);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        printf("eerno: %s\n", strerror(errno));
        exit(1);
    }

    pkt.header.unix_secs = ntohl(time(NULL));
    pkt.header.unix_nsecs = ntohl(time_point_cast<nanoseconds>(system_clock::now()).time_since_epoch().count());
    int i = send(sock, &pkt, sizeof(pkt), 0);
    if (i == -1)
    {
        printf("ret value: %d\n", i);
        printf("eerno: %s\n", strerror(errno));
        exit(1);
    }

}

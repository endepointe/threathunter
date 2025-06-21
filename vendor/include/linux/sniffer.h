#ifndef SNIFFER_H 
#define SNIFFER_H

// Resources:
// TCPIP Tut https://datatracker.ietf.org/doc/rfc1180/ 


#include "utils.h"
#include <pcap.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

struct EthernetHeader {
    uint8_t dest_eth_addr[ETH_ALEN];
    uint8_t src_eth_addr[ETH_ALEN];
    uint16_t eth_type;
};

struct IpHeader {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl;
    unsigned int version;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version;
    unsigned int ihl;
#else 
# error "fix endianess in bits/endian.h"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};


int bpf_filter_and_listen(const std::string&);

#endif

#ifndef SILO_H 
#define SILO_H

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
#include "data_collector.h"

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

class Silo {
 public:
    Silo() : filter_exp_("tcp and port 80"), 
                bucket_of_ips_(std::make_shared<std::unordered_set<std::string>>()) {}
    Silo(const std::string& exp) : filter_exp_(exp), 
                bucket_of_ips_(std::make_shared<std::unordered_set<std::string>>()) {}
    ~Silo() {}
    int filter_and_listen();
    int filter_and_listen(const std::string&);
    bool bucket_contains(const std::string&);
    //DataCollector* data_collector_;

 private:
    static void _handle_packets(u_char*, const struct pcap_pkthdr*, const u_char*);
    void _add_ip(const std::string&);
    std::string filter_exp_;
    std::shared_ptr<std::unordered_set<std::string>> bucket_of_ips_;
    std::mutex mutex_;
};

int bpf_filter_and_listen(const std::string&);

#endif

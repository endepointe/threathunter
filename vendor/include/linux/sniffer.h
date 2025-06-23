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

class Sniffer {
 public:
    Sniffer() : filter_exp_("tcp and port 80") {}
    Sniffer(const std::string& exp) : filter_exp_(exp) {}
    ~Sniffer() {
        //if (eth_header_) delete eth_header_;
        //if (ip_header_) delete ip_header_;
        //if (alldevs_) {pcap_freealldevs(alldevs_);}
        //if (handle_) {pcap_close(handle_);}
        //if (bpf_filter_) {pcap_freecode(&bpf_filter_);}
    }
    std::string get_exp();
    int filter_and_listen();
    int filter_and_listen(const std::string&);
 private:
    static void _handle_packets(u_char*, const struct pcap_pkthdr*, const u_char*);
    std::string filter_exp_;
    //EthernetHeader* eth_header_ = nullptr; // TODO: make this a shared_ptr
    //IpHeader* ip_header_ = nullptr; // TODO: read about reinterpret_cast<T>
    //pcap_if_t* alldevs_ = nullptr;
    //pcap_t* handle_ = nullptr;
    //struct bpf_program bpf_filter_;
};

int bpf_filter_and_listen(const std::string&);

#endif

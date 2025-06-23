
// TODO:
//  create a logging function that moves stdout and stderr 
//  messages to status.log and error.log.
#include "sniffer.h"

std::string Sniffer::get_exp() 
{
    return filter_exp_;
}

void Sniffer::_handle_packets(u_char* user, 
        const struct pcap_pkthdr* h, 
        const u_char* packet) 
{
    EthernetHeader* eth_header_ = new EthernetHeader;
    const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);

    // The character 'e' has a numeric equivalent based on its ASCII value.
    // The sizeof operator returns an integer, not a character like 'e'.
    // If you meant to convert the character 'e' to its numeric ASCII value:
    std::cout << "Value of ehs: " << std::dec << sizeof(EthernetHeader) << std::endl;
    if (sizeof(EthernetHeader) > 14) {
        std::cerr << "Ethernet may have a VLAN tag. Handle this condition" << std::endl;
        return;
    }

    if (h->len < sizeof(EthernetHeader)) {
        std::cerr << "The packet is too small to contain an ethernet header. its something else\n";
        delete eth_header_;
        return;
    }

    std::memcpy(eth_header_->dest_eth_addr, packet, sizeof(eth_header_->dest_eth_addr));
    ///////testing whether its faster to read memory. probably is...
    std::cout << "\n\tETHERHOST WO new struct assign: " << std::endl;
    for (int i = 0; i < (int)sizeof(eth_header->ether_dhost); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->ether_dhost[i];
        if (i < sizeof(eth_header->ether_dhost) - 1) {
            std::cout << ":";
        }
    }
    std::cout << "\n\tEND ETHERHOST WO new struct assign: " << std::endl;
    ////////////
    std::memcpy(eth_header_->src_eth_addr, 
            (void*)(packet + sizeof(eth_header_->dest_eth_addr)), 
            sizeof(eth_header_->src_eth_addr));
    std::memcpy(&eth_header_->eth_type,
            (void*)(packet + sizeof(eth_header_->dest_eth_addr) + sizeof(eth_header_->src_eth_addr)),
            sizeof(eth_header_->eth_type));

    std::cout << "Ethernet destination address: ";
    for (int i = 0; i < (int)sizeof(eth_header_->dest_eth_addr); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header_->dest_eth_addr[i];
        if (i < sizeof(eth_header_->dest_eth_addr) - 1) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout << "Ethernet source address: ";
    for (int i = 0; i < (int)sizeof(eth_header_->src_eth_addr); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header_->src_eth_addr[i];
        if (i < sizeof(eth_header_->src_eth_addr) - 1) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    uint16_t eth_type_network_order = eth_header_->eth_type;
    uint16_t eth_type_host_order = ntohs(eth_type_network_order);

    // what else would I need this for?
    //std::stringstream ss;
    //ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << eth_type_host_order;
    //std::string eth_type_hex = ss.str();

    switch (eth_type_host_order) {
        case ETHERTYPE_IP: {
            std::cout << "Ethernet type is IPv4" << std::endl;

            // TODO: set eth header length instead of 14
            const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(packet + 14); 
            uint32_t ip_header_len_bytes = iph->ihl * 4;
            if (h->len < 14 + ip_header_len_bytes) {
                std::cerr << "Error: Packet too short for the IP header length ("
                    << (ip_header_len_bytes) + 14 << ") specified in the header." << std::endl;
                delete eth_header_;
                return;
            }
            uint16_t tot_len = ntohs(iph->tot_len);
            struct in_addr src_addr;
            src_addr.s_addr = iph->saddr;
            struct in_addr dst_addr;
            dst_addr.s_addr = iph->daddr;           
            // NOTE: inet_ntoa is not thread-safe. Consider inet_ntop for new code.
            std::cout << "IP src address: " <<  inet_ntoa(src_addr) << std::endl;
            std::cout << "IP dest address: " << inet_ntoa(dst_addr) << std::endl;
            std::cout << "IP header total length: " << tot_len << std::endl;
            std::cout << "Version: " << iph->version << std::endl;
            std::cout << "Id:" << ntohs(iph->id) << std::endl;
            uint32_t frag_off_flags = ntohs(iph->frag_off);
            std::cout << "Fragment offset:" << (uint32_t)((frag_off_flags & 0x1FFF)*8) << std::endl; 
            uint32_t flags = (frag_off_flags >> 13) & 0x07;
            std::cout << "Flags: 0x" << std::hex << flags << std::dec;
            if (flags & 0x04) std::cout << " (DF - Don't Fragment)";
            if (flags & 0x02) std::cout << " (MF - More Fragments)";
            // This flag is technically reserved and must be 0 in IPv4
            if (flags & 0x01) std::cout << " (Reserved - must be 0)"; 
            std::cout << std::endl;
            std::cout << "TTL:" << static_cast<int>(iph->ttl) << std::endl;
            uint32_t protocol = static_cast<int>(iph->protocol); 
            std::cout << "Protocol:" << protocol << std::endl;
            switch(protocol) {
                case IPPROTO_ICMP: std::cout << " (ICMP)"; break;
                case IPPROTO_TCP: std::cout << " (TCP)"; break;
                case IPPROTO_UDP: std::cout << " (UDP)"; break;
                // handle other protocols found in netinet/in.h
                default: break;
            }
            std::cout << std::endl;
            std::cout << "Checksum:" << std::hex << ntohs(iph->check) << std::dec << std::endl;

            std::cout << "---------------------------" << std::endl;
            
            const unsigned char* payload_data = packet + 14 + ip_header_len_bytes;
            size_t payload_len = tot_len - ip_header_len_bytes;
            std::cout << "PROCESSPAYLOADPROCESSPAYLOAD: Length = "
                << std::hex << payload_len<<std::dec << std::endl;
            break;
        }

        case ETHERTYPE_IPV6:
            std::cout << "Ethernet type is IPv6" << std::endl;
            break;
        case ETHERTYPE_ARP:
            std::cout << "Ethernet type is ARP" << std::endl;
            break;
        case ETHERTYPE_REVARP:
            std::cout << "Ethernet type is Reverse ARP" << std::endl;
            break;
        case ETHERTYPE_LOOPBACK:
            std::cout << "Ethernet type is loopback" << std::endl;
            break;
        default:
            std::cout << "check ethernet protocol id in /usr/include/net/ethernet.h\n";
            break;
    }
    std::cout << "<proto> packet captured, length: " << h->len << "\n";

    delete eth_header_;

}

int Sniffer::filter_and_listen()
{
    std::cout << "Sniffer using: " << get_exp() << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs_;

    if (pcap_findalldevs(&alldevs_, errbuf) == -1) {
        std::cerr << "unable to find devices..."<< errbuf << "\n";
        return -1;
    }

    if (!alldevs_) {
        std::cerr << "no devices available\n";
        return -2;
    }
    
    const std::string dev(alldevs_->name);
    
    pcap_t* handle_;

    handle_ = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "unable to open device: " << errbuf << "\n";
        return -3;
    }

    // look in dlt.h in pcap
    int data_link_type = DLT_NULL;
    switch (const int value = pcap_datalink(handle_)) {
        case DLT_NULL:
            break;
        case DLT_EN10MB:
            data_link_type = value;
            break;
        case 2:
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
            break;
        default:
            // TODO: log this for future patching
            std::cout << "Non-Ethernet 10MB header type found. Type: " 
                << value << ". Find definition in pcap/dlt.h\n";
            ////////////////////////////////////////////////////////////////////////
            break;
    }

    std::cout << "Datalink header type: " << data_link_type << std::endl;

    std::cout << "Using device: " << dev << " with filter: "<< filter_exp_<< std::endl;

    struct bpf_program bpf_filter_;
    // TODO: sanitize filter exp and error handle
    if (pcap_compile(handle_, &bpf_filter_, filter_exp_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        ////////////////////////////////////////////////
        std::cerr << "bad filter: " << pcap_geterr(handle_) << "\n";
        return -4;
    }

    if (pcap_setfilter(handle_, &bpf_filter_) == -1) {
        std::cerr << "could not set filter: " << pcap_geterr(handle_) << "\n";
        return -5;       
    }

    // TODO: this is blocking. must be done while CONDITIONS are true or 
    // handle packet data in callback.
    pcap_loop(handle_, 0, Sniffer::_handle_packets, reinterpret_cast<u_char*>(this));
    ////////////////////////////////////////////////

    pcap_freecode(&bpf_filter_);
    pcap_close(handle_);
    pcap_freealldevs(alldevs_);

    return 0;
}

int Sniffer::filter_and_listen(const std::string& filter_exp)
{
    std::cout << "Sniffer using: " << filter_exp << std::endl;
    return 1;
}

/// previous impl wihtout class
/* 
void
_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) 
{    
    // TODO: 
    // - break ethernet, ip, tcp header parsing sections into functions
    // - send parsed data to server for threat analysis.

    EthernetHeader* eth_header = new EthernetHeader;

    if (h->len < sizeof(EthernetHeader)) {
        std::cerr << "The packet is too small to contain an ethernet header. its something else\n";
        delete eth_header;
        return;
    }

    std::memcpy(eth_header->dest_eth_addr, packet, sizeof(eth_header->dest_eth_addr));
    std::memcpy(eth_header->src_eth_addr, 
            (void*)(packet + sizeof(eth_header->dest_eth_addr)), 
            sizeof(eth_header->src_eth_addr));
    std::memcpy(&eth_header->eth_type,
            (void*)(packet + sizeof(eth_header->dest_eth_addr) + sizeof(eth_header->src_eth_addr)),
            sizeof(eth_header->eth_type));

    std::cout << "Ethernet destination address: ";
    for (int i = 0; i < (int)sizeof(eth_header->dest_eth_addr); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->dest_eth_addr[i];
        if (i < sizeof(eth_header->dest_eth_addr) - 1) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout << "Ethernet source address: ";
    for (int i = 0; i < (int)sizeof(eth_header->src_eth_addr); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->src_eth_addr[i];
        if (i < sizeof(eth_header->src_eth_addr) - 1) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    uint16_t eth_type_network_order = eth_header->eth_type;
    uint16_t eth_type_host_order = ntohs(eth_type_network_order);

    switch (eth_type_host_order) {
        case ETHERTYPE_IP: {
            std::cout << "Ethernet type is IPv4" << std::endl;

            const u_char* ip_header_start = packet + sizeof(EthernetHeader);

            if (h->len < sizeof(EthernetHeader) + sizeof(IpHeader)) {
                std::cerr << "Packet too short to contain full IP header\n";
                delete eth_header;
                break;
            }

            IpHeader* ip_header = reinterpret_cast<IpHeader*>(const_cast<u_char*>(ip_header_start));

            uint16_t total_length = ntohs(ip_header->tot_len);
            uint16_t identification = ntohs(ip_header->id);
            uint16_t flags_fragment_offset = ntohs(ip_header->frag_off);
            uint8_t ttl = ntohs(ip_header->ttl);
            uint16_t header_checksum = ntohs(ip_header->check);
            uint32_t source_address = ntohl(ip_header->saddr);
            uint32_t dest_address = ntohl(ip_header->daddr);

            std::cout << "IP Version: " << (unsigned int)ip_header->version << std::endl;
            std::cout << "IP Header Length: " << (unsigned int)ip_header->ihl * 4 << " bytes" << std::endl;
            std::cout << "Total Length: " << total_length << std::endl;
            std::cout << "Protocol: " << (uint8_t)ip_header->protocol << std::endl;
            std::cout << "Checksum: " << (uint16_t)ntohl(ip_header->check) << std::endl;
            std::cout << "TTL: " << (uint8_t)(ip_header->ttl) << std::endl;


            std::stringstream source_address_ss;
            source_address_ss << ((source_address >> 24) & 0xFF) << "."
                << ((source_address >> 16) & 0xFF) << "."
                << ((source_address >> 8) & 0xFF) << "."
                << (source_address & 0xFF);

            std::stringstream dest_address_ss;
            dest_address_ss << ((dest_address >> 24) & 0xFF) << "."
                << ((dest_address >> 16) & 0xFF) << "."
                << ((dest_address >> 8) & 0xFF) << "."
                << (dest_address & 0xFF);

            std::cout << "Source Address: " << source_address_ss.str() << std::endl;
            std::cout << "Destination Address: " << dest_address_ss.str() << std::endl;
            break;
        }

        case ETHERTYPE_IPV6:
            std::cout << "Ethernet type is IPv6" << std::endl;
            break;
        case ETHERTYPE_ARP:
            std::cout << "Ethernet type is ARP" << std::endl;
            break;
        case ETHERTYPE_REVARP:
            std::cout << "Ethernet type is Reverse ARP" << std::endl;
            break;
        case ETHERTYPE_LOOPBACK:
            std::cout << "Ethernet type is loopback" << std::endl;
            break;
        default:
            std::cout << "check ethernet protocol id in /usr/include/net/ethernet.h\n";
            break;
    }

    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << eth_type_host_order;
    std::string eth_type_hex = ss.str();

    std::cout << "<proto> packet captured, length: " << h->len << "\n";

    delete eth_header;
}

int
bpf_filter_and_listen(const std::string& filter_exp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "unable to find devices..."<< errbuf << "\n";
        return -1;
    }

    if (!alldevs) {
        std::cerr << "no devices available\n";
        return -2;
    }
    
    const std::string dev(alldevs->name);

    pcap_t *handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "unable to open device: " << errbuf << "\n";
        return -3;
    }

    // look in dlt.h in pcap
    int data_link_type = DLT_NULL;
    switch (const int value = pcap_datalink(handle)) {
        case DLT_NULL:
            break;
        case DLT_EN10MB:
            data_link_type = value;
            break;
        case 2:
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
            break;
        default:
            // TODO: log this for future patching
            std::cout << "Non-Ethernet 10MB header type found. Type: " 
                << value << ". Find definition in pcap/dlt.h\n";
            ////////////////////////////////////////////////////////////////////////
            break;
    }

    std::cout << "Datalink header type: " << data_link_type << std::endl;

    std::cout << "Using device: " << dev << " with filter: "<< filter_exp<< std::endl;

    struct bpf_program filter;

    // TODO: sanitize filter exp and error handle
    if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        ////////////////////////////////////////////////
        std::cerr << "bad filter: " << pcap_geterr(handle) << "\n";
        return -4;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "could not set filter: " << pcap_geterr(handle) << "\n";
        return -5;       
    }

    // TODO: this is blocking. must be done while CONDITIONS are true.
    pcap_loop(handle, 0, _packet_handler, nullptr);
    ////////////////////////////////////////////////

    pcap_freecode(&filter);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
*/


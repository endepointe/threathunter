
// TODO:
//  create a logging function that moves stdout and stderr 
//  messages to status.log and error.log.
#include "sniffer.h"
#include "pcap.h"

void
_packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) 
{
    std::cout << "<proto> packet captured, length: " << h->len << "\n";
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

    std::cout << "Using device: " << dev << " with filter: "<< filter_exp<< std::endl;

    struct bpf_program filter;

    // TODO: sanitize filter exp and error handle
    if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "bad filter: " << pcap_geterr(handle) << "\n";
        return -4;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "could not set filter: " << pcap_geterr(handle) << "\n";
        return -5;       
    }

    pcap_loop(handle, 10, _packet_handler, nullptr);

    pcap_freecode(&filter);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}

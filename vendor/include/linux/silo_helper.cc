
// TODO:
//  create a logging function that moves stdout and stderr 
//  messages to status.log and error.log.
#include "silo_helper.h"



int Silo::filter_and_listen(const std::string& filter_exp)
{

    std::cout << "Silo using: " << filter_exp_ << std::endl;
    return 1;
}

void Silo::_add_ip(const std::string& ip) 
{
    std::lock_guard<std::mutex> lock(mutex_);
    bucket_of_ips_->insert(ip);
}

bool Silo::bucket_contains(const std::string& ip) 
{
    std::lock_guard<std::mutex> lock(mutex_);
    return bucket_of_ips_->count(ip) > 0;
}


void Silo::_handle_packets(u_char* user, 
        const struct pcap_pkthdr* h, 
        const u_char* packet) 
{
    Silo* this_silo_ptr = reinterpret_cast<Silo*>(user);
    std::cout << "A self silo filter is: " << this_silo_ptr->filter_exp_ << std::endl;

    std::thread t1( [&this_silo_ptr] () {
        this_silo_ptr->_add_ip("ipaddressadded");
    });    

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


            std::thread t2( [&this_silo_ptr] () {
                this_silo_ptr->_add_ip("anotheripaddressadded");
            });

            t1.join();
            t2.join();
            std::cout << "Final Bucket of IPs contains: " 
                << this_silo_ptr->bucket_contains("ipaddressadded") << std::endl;
            std::cout << "Bucket of IPs contains: " << this_silo_ptr->bucket_contains("anotheripaddressadded") << std::endl;
            static DataCollector data_collector;
            data_collector.process_packet(packet, h);
            //this_silo_ptr->data_collector_->process_packet(packet, h);

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

int Silo::filter_and_listen()
{
    std::cout << "Silo using: " << filter_exp_ << std::endl;

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
    pcap_loop(handle_, 0, Silo::_handle_packets, reinterpret_cast<u_char*>(this));
    ////////////////////////////////////////////////

    pcap_freecode(&bpf_filter_);
    pcap_close(handle_);
    pcap_freealldevs(alldevs_);

    return 0;
}
/*
Plan:

1.  Outline the general idea of passing data to a gRPC async connection within the thread handler.
2.  Provide a simplified example showing how the `thread_handler` can be modified to interact with a hypothetical `GrpcClient` for asynchronous communication.
3.  Explain the importance of managing the gRPC client's lifetime and thread safety aspects, even in this simplified example.

```cpp
// C++
#include <iostream>
#include <string>
#include <thread>
#include <memory>

// Placeholder for gRPC client-related classes/functions
class GrpcClient {
public:
  GrpcClient() {
    std::cout << "GrpcClient created." << std::endl;
  }
  ~GrpcClient() {
    std::cout << "GrpcClient destroyed." << std::endl;
  }

  void send_data_async(const std::string& data) {
    // Simulate asynchronous send
    std::cout << "Sending data asynchronously: " << data << std::endl;
  }
};

class MyClass {
private:
  int data;
  std::string message;
  std::unique_ptr<GrpcClient> grpc_client; // Manage the client's lifetime

  void thread_handler() {
    std::cout << "Thread started, initial data: " << data << std::endl;
    data += 10;
    message = "Updated in thread";
    std::cout << "Thread finished, updated data: " << data << ", message: " << message << std::endl;

    // Use the gRPC client to send data asynchronously
    grpc_client->send_data_async(message);
  }

public:
  MyClass(int initial_data) : data(initial_data), message("Initial message"), grpc_client(std::make_unique<GrpcClient>()) {}

  void run_in_thread() {
    std::thread t(&MyClass::thread_handler, this);
    t.join();
    std::cout << "Data after thread: " << data << ", message: " << message << std::endl;
  }

  static void static_run_in_thread(MyClass& obj) {
      std::thread t(&MyClass::thread_handler, &obj);
      t.join();
      std::cout << "Static: Data after thread: " << obj.data << ", message: " << obj.message << std::endl;
  }
};

int main() {
  MyClass obj(5);
  obj.run_in_thread();

  MyClass obj2(15);
  MyClass::static_run_in_thread(obj2);
  return 0;
}
```

Next steps: We can discuss error handling, gRPC client setup, and more sophisticated thread management (e.g., using a thread pool) if needed.

// class idea
1.  **Define Data Structures:** Create basic structures for network and system data.
2.  **gRPC Client Integration:**  Incorporate a gRPC client for sending data asynchronously. This will be a simplified client for demonstration purposes.
3.  **Non-Blocking Data Collection:** Use non-blocking techniques for network (pcap) and system data collection.  For system data, this might involve reading from files or using `sysctl` in a non-blocking manner.
4.  **Asynchronous gRPC Calls:**  Implement asynchronous gRPC calls to avoid blocking the data collection threads.
5.  **Thread Safety:** Ensure thread safety when accessing shared resources.
6.  **Integration with `Silo` Class:** Adapt the new class to work with your existing `Silo` class, specifically within the `_handle_packets` method.
7.  **Error Handling:** Add basic error handling for gRPC calls and data collection.

```cpp
// C++
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <random>
#include <grpcpp/grpcpp.h>

// Include necessary headers for network and system data
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/sysinfo.h>

// Placeholder for gRPC service definition
namespace example {
class DataService final {
 public:
  virtual ~DataService() {}
  virtual ::grpc::Status SendData(::grpc::ServerContext* context, const ::example::DataRequest* request, ::example::DataReply* response) = 0;
};
struct DataRequest final{
  std::string message;
};

struct DataReply final{
  std::string message;
};
}  // namespace example

// Data structures for network and system data
struct NetworkData {
    std::string src_ip;
    std::string dest_ip;
    uint16_t protocol;
    size_t packet_size;
};

struct SystemData {
    double cpu_usage;
    size_t memory_usage;
    size_t disk_usage;
};

class GrpcClient {
public:
    GrpcClient() {
        std::cout << "GrpcClient created." << std::endl;
    }
    ~GrpcClient() {
        std::cout << "GrpcClient destroyed." << std::endl;
    }

    void send_data_async(const std::string& data) {
        // Simulate asynchronous send
        std::cout << "Sending data asynchronously: " << data << std::endl;
        // TODO: Implement actual asynchronous gRPC call here
        std::thread t([data]() {
            // Simulate network latency
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::cout << "gRPC send completed for: " << data << std::endl;
        });
        t.detach(); // Detach the thread to allow it to run independently
    }
};

class DataCollector {
private:
    std::unique_ptr<GrpcClient> grpc_client_;
    std::mutex mutex_;

public:
    DataCollector() : grpc_client_(std::make_unique<GrpcClient>()) {}

    ~DataCollector() = default;

    void collect_and_send(const NetworkData& network_data, const SystemData& system_data) {
        std::string combined_data = package_data(network_data, system_data);
        grpc_client_->send_data_async(combined_data);
    }

private:
    std::string package_data(const NetworkData& network_data, const SystemData& system_data) {
        // Package the data into a string or protobuf message
        std::stringstream ss;
        ss << "Network Data: src_ip=" << network_data.src_ip
           << ", dest_ip=" << network_data.dest_ip
           << ", protocol=" << network_data.protocol
           << ", packet_size=" << network_data.packet_size
           << " | System Data: cpu_usage=" << system_data.cpu_usage
           << ", memory_usage=" << system_data.memory_usage
           << ", disk_usage=" << system_data.disk_usage;
        return ss.str();
    }

    // Example function to get system data
    SystemData get_system_data() {
        SystemData data;
        struct sysinfo sys_info;
        if (sysinfo(&sys_info) == 0) {
            data.cpu_usage = get_random_number();
            data.memory_usage = sys_info.totalram - sys_info.freeram;
            data.disk_usage = get_random_number();
        } else {
            std::cerr << "Error getting system info" << std::endl;
        }
        return data;
    }

    double get_random_number() {
      static std::random_device rd;
      static std::mt19937 gen(rd());
      static std::uniform_real_distribution<> dis(0, 100);
      return dis(gen);
    }
public:
    void process_packet(const u_char* packet, const struct pcap_pkthdr* h) {
        NetworkData network_data;
        // Populate network_data from the packet
        network_data.packet_size = h->len;
        network_data.src_ip = "127.0.0.1"; // Example
        network_data.dest_ip = "127.0.0.1"; // Example
        network_data.protocol = 6;           // Example: TCP

        SystemData system_data = get_system_data();
        collect_and_send(network_data, system_data);
    }
};

#include "silo.h"

void Silo::_handle_packets(u_char* user,
    const struct pcap_pkthdr* h,
    const u_char* packet) {
    Silo* this_silo_ptr = reinterpret_cast<Silo*>(user);

    // process packet data
    EthernetHeader* eth_header_ = new EthernetHeader;
    const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);

    std::cout << "Value of ehs: " << std::dec << sizeof(EthernetHeader) << std::endl;
    if (sizeof(EthernetHeader) > 14) {
        std::cerr << "Ethernet may have a VLAN tag. Handle this condition" << std::endl;
        delete eth_header_;
        return;
    }

    if (h->len < sizeof(EthernetHeader)) {
        std::cerr << "The packet is too small to contain an ethernet header. its something else\n";
        delete eth_header_;
        return;
    }

    std::memcpy(eth_header_->dest_eth_addr, packet, sizeof(eth_header_->dest_eth_addr));
    std::cout << "\n\tETHERHOST WO new struct assign: " << std::endl;
    for (int i = 0; i < (int)sizeof(eth_header->ether_dhost); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->ether_dhost[i];
        if (i < sizeof(eth_header->ether_dhost) - 1) {
            std::cout << ":";
        }
    }
    std::cout << "\n\tEND ETHERHOST WO new struct assign: " << std::endl;
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

    switch (eth_type_host_order) {
    case ETHERTYPE_IP: {
        std::cout << "Ethernet type is IPv4" << std::endl;

        const struct iphdr* iph = reinterpret_cast<const struct iphdr*>(packet + 14);
        uint32_t ip_header_len_bytes = iph->ihl * 4;
        if (h->len < 14 + ip_header_len_bytes) {
            std::cerr << "Error: Packet too short for the IP header length ("
                << (ip_header_len_bytes)+14 << ") specified in the header." << std::endl;
            delete eth_header_;
            return;
        }
        uint16_t tot_len = ntohs(iph->tot_len);
        struct in_addr src_addr;
        src_addr.s_addr = iph->saddr;
        struct in_addr dst_addr;
        dst_addr.s_addr = iph->daddr;
        std::cout << "IP src address: " << inet_ntoa(src_addr) << std::endl;
        std::cout << "IP dest address: " << inet_ntoa(dst_addr) << std::endl;
        std::cout << "IP header total length: " << tot_len << std::endl;
        std::cout << "Version: " << iph->version << std::endl;
        std::cout << "Id:" << ntohs(iph->id) << std::endl;
        uint32_t frag_off_flags = ntohs(iph->frag_off);
        std::cout << "Fragment offset:" << (uint32_t)((frag_off_flags & 0x1FFF) * 8) << std::endl;
        uint32_t flags = (frag_off_flags >> 13) & 0x07;
        std::cout << "Flags: 0x" << std::hex << flags << std::dec;
        if (flags & 0x04) std::cout << " (DF - Don't Fragment)";
        if (flags & 0x02) std::cout << " (MF - More Fragments)";
        if (flags & 0x01) std::cout << " (Reserved - must be 0)";
        std::cout << std::endl;
        std::cout << "TTL:" << static_cast<int>(iph->ttl) << std::endl;
        uint32_t protocol = static_cast<int>(iph->protocol);
        std::cout << "Protocol:" << protocol << std::endl;
        switch (protocol) {
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
            << std::hex << payload_len << std::dec << std::endl;

        // Instantiate DataCollector here
        static DataCollector data_collector; // Static to avoid re-instantiation
        data_collector.process_packet(packet, h);

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
*/

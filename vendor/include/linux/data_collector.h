#ifndef DATA_COLLECTOR_H
#define DATA_COLLECTOR_H

#include "utils.h"

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

class DataCollector 
{
 private:
    std::string grpc_client_; 
    //std::unique_ptr<GrpcClient> grpc_client_;
    std::mutex mutex_;

 public:
    DataCollector() : grpc_client_("todo: instaniate a std::unique_ptr<GrpcClientType> grpc_client_") {}
    ~DataCollector() = default;

    void process_packet(const u_char* packet, const struct pcap_pkthdr* h) 
    {
        NetworkData network_data;
        // Populate network_data from the packet
        network_data.packet_size = h->len;
        network_data.src_ip = "127.0.0.1"; // Example
        network_data.dest_ip = "127.0.0.1"; // Example
        network_data.protocol = 6;           // Example: TCP

        SystemData system_data = _get_system_data();
        //collect_and_send("network data", "system data");
        collect_and_send(network_data, system_data);
    }
    void collect_and_send(const NetworkData& network_data, const SystemData& system_data) {
        std::string combined_data = _package_data(network_data, system_data);
        std::cout << "TODO: send network and system data to the Hub" << std::endl;
        std::cout << "\tcontent of combined data: "<< combined_data << std::endl;
        //grpc_client_->send_data_async(combined_data);
    }

 private:
    std::string _package_data(const NetworkData& network_data, const SystemData& system_data) 
    {
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

    SystemData _get_system_data() {
        SystemData data;
        struct sysinfo sys_info;
        if (sysinfo(&sys_info) == 0) {
            data.cpu_usage = _get_random_number();
            data.memory_usage = sys_info.totalram - sys_info.freeram;
            data.disk_usage = _get_random_number();
        } else {
            std::cerr << "Error getting system info" << std::endl;
        }
        return data;
    }

    double _get_random_number() {
      static std::random_device rd;
      static std::mt19937 gen(rd());
      static std::uniform_real_distribution<> dis(0, 100);
      return dis(gen);
    }
};

#endif

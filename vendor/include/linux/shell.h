#include "utils.h"

// No need to include the header file: linux_monitor.h.
// The data structures were made available in client.cc

std::atomic<bool> collecting(false);
std::mutex data_mutex;

std::vector<ProcessInfo> collected_processes;
std::vector<ConnectionInfo> collected_connections;

using grpc::ClientContext;
using grpc::Status;
using grpc::Channel;
using threathunter::ThreatHunter;
using threathunter::SnapshotRequest;
using threathunter::ScanResult;

std::string test(){
    return "hello from shell";
}

void background_collector() 
{
    while (collecting)
    {
        std::lock_guard<std::mutex> lock(data_mutex);
        collected_processes = get_processes();
        collected_connections = get_connections("tcp");
        auto udp = get_connections("udp");
        collected_connections.insert(collected_connections.end(), udp.begin(), udp.end());
        std::this_thread::sleep_for(std::chrono::seconds(5)); // takes a sample every five seconds
    }
}

void send_snapshot(ThreatHunter::Stub &stub)
{
    SnapshotRequest req;
    {
        std::lock_guard<std::mutex> lock(data_mutex);
        req.set_hostname(get_hostname());
        req.set_os("debian11");
        for (auto &p : collected_processes)
        {
            req.add_running_processes(p.name);
        }
        for (auto &c : collected_connections) 
        {
            req.add_network_connections(c.local_addr + "->" + c.remote_addr);
        }
    }

    ScanResult result;
    ClientContext ctx;
    Status status = stub.SendSystemSnapshot(&ctx, req, &result);

    if (status.ok()) {
        std::cout << "[Server Response] Threat Detected: " 
            << result.threat_detected() << " - " << result.summary() << "\n";
    }
    std::cout << "[Error] Failed to send a snapshot: " << status.error_message() << "\n";
}

void run_shell(std::unique_ptr<ThreatHunter::Stub> &stub) 
{
    std::string cmd;
    while (true) 
    {
        std::cout << "\n|\\|ThreatHunter Shell|/|\n";
        std::cout << "1. Start Data Collection\n";
        std::cout << "2. Stop Data Collection\n";
        std::cout << "3. Send Snapshot to Server\n";
        std::cout << "4. Exit\n";

        std::cout << "Select an option: ";
        std::getline(std::cin, cmd);

        switch(std::stoi(cmd)) {
            case 1:
                if (!collecting) {
                    collecting = true;
                    std::thread(background_collector).detach();
                    std::cout << "[+] Data collection started in background.\n";
                } else {
                    std::cout << "[!] Already collecting.\n";
                }
                break;
            case 2:
                collecting = false;
                std::cout << "[+] Data collection stopped\n";
                break;
            case 3:
                send_snapshot(*stub);
                break;
            case 4:
                collecting = false;
                std::cout << "[+] Exiting ThreatHunter shell\n";
                break;
            default:
                std::cout << "[!] Unknown command: " << cmd << "\n";
                break;
        }
    }
}


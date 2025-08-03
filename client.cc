
#include "protos/threathunter.grpc.pb.h"
#include <grpcpp/grpcpp.h>

#ifdef __linux__
//#include "linux/utils.h"
#include "linux_monitor.h"
#elif _WIN32
//#include "windows/monitor.cc"
#endif
#include <string>
#include <iostream>

using grpc::ClientContext;
using grpc::Status;
using grpc::Channel;
using threathunter::ThreatHunter;
using threathunter::SnapshotRequest;
using threathunter::ScanResult;
using threathunter::Ack;

class ThreatHunterClient 
{
 public:
    ThreatHunterClient(std::shared_ptr<Channel> channel) 
        : stub_(ThreatHunter::NewStub(channel)) {}

    std::string send_snapshot(const std::string& data) 
    {
        std::cout << data << std::endl;
        SnapshotRequest request;
        request.set_hostname("you-can-trust-me-13");
        request.set_os("windows");
        request.add_running_processes("powershell");
        request.add_running_processes("zsh");
        request.add_network_connections("192.168.0.101:5432");
        ScanResult result;
        ClientContext ctx;
        Status status = stub_->SendSystemSnapshot(&ctx, request, &result);
        Ack ack;
        if (status.ok())
        {
            std::cout << "Threat: " << result.threat_detected() << " - " << result.summary() << "\n";
            return ack.message();
        }
        std::cout << status.error_code() << ": " << status.error_message() << std::endl;
        return "rpc failed";
    }
 private:
    std::unique_ptr<ThreatHunter::Stub> stub_;
};

int
main(void) 
{
    hello("ep");
    /*
    ThreatHunterClient hunter(grpc::CreateChannel("0.0.0.0:50017", grpc::InsecureChannelCredentials()));
    std::string data("hello");
    std::string reply = hunter.send_snapshot(data);
    std::cout << "Hunter received: " << reply << std::endl;
    */
    return 0;
}


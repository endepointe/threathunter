
#include "utils.h"
#include "protos/threathunter.grpc.pb.h"
#include <grpcpp/grpcpp.h>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerReader;
using grpc::ServerContext;
using grpc::Status;
using threathunter::ThreatHunter;
using threathunter::SnapshotRequest;
using threathunter::ScanResult;
using threathunter::ClientInfo;
using threathunter::HuntInstruction;
using threathunter::AnomalyReport;
using threathunter::Ack;

class ThreatHunterServiceImpl final : public ThreatHunter::Service 
{
 public:
    grpc::Status SendSystemSnapshot(ServerContext* context,
                                    const SnapshotRequest* request,
                                    ScanResult* reply) override 
    {
        reply->set_threat_detected(true); // simulate it
        reply->set_summary("suspicious shell activity");
        return grpc::Status::OK;
    }

    grpc::Status GetHuntInstructions(ServerContext* context,
                                    const ClientInfo* request,
                                    HuntInstruction* reply) override 
    {
        reply->add_yara_rules("rule suspicious_exec { condition: uint16(0) == 0x5a4d }");
        reply->set_command("dump memory");
        return grpc::Status::OK;
    }

    grpc::Status StreamAnomalies(ServerContext* context,
                                 ServerReader<AnomalyReport>* reader,
                                 Ack* ack) override 
    {
        AnomalyReport report;
        while (reader->Read(&report)) 
        {
            std::cout << "Anomaly: " << report.description() << "\n";
        }
        ack->set_message("Report received.");
        return grpc::Status::OK;
    }
};

int
main(void) 
{
    std::cout << "Starting ThreatHuntingHub\n";
    std::string address = "0.0.0.0:50017";
    ThreatHunterServiceImpl service;
    ServerBuilder builder;
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "ThreatHuntingHub running at 0.0.0.0:50017.\n";
    server->Wait();

    return 0;
}


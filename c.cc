#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <thread>
#include <string>
#include <vector>
#include <chrono>
#include "protos/threathunter.grpc.pb.h"
#ifdef __linux__
#include "vendor/include/linux/utils.h"
#endif
//#define DBG

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientWriter;
using grpc::Status;
using threathunter::LogStream;
using threathunter::LogEntry;
using threathunter::Ack;

// LogStreamClient handles sending log entries to the gRPC server.
class LogStreamClient {
public:
    LogStreamClient(std::shared_ptr<Channel> channel)
        : stub_(LogStream::NewStub(channel)) {}

    // Sends a stream of LogEntry messages to the server.
    Status SendLogStream(const std::string& client_name, int num_entries) {
        ClientContext context;
        Ack ack;

        // Start the client-streaming RPC.
        std::unique_ptr<ClientWriter<LogEntry>> writer(stub_->SendLog(&context, &ack));

        for (int i = 0; i < num_entries; ++i) {
            LogEntry log_entry;
            log_entry.set_source("Client_" + client_name);
            log_entry.set_hostname("host_" + client_name + "_" + std::to_string(i));
            log_entry.set_path("/app/logs/client_" + client_name + ".log");
            log_entry.set_timestamp(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            );
            log_entry.set_content("Log message " + std::to_string(i) + " from client " + client_name);

            std::cout << "Client " << client_name << " sending log entry " << i << std::endl;
            // Write the log entry to the stream.
            if (!writer->Write(log_entry)) {
                // The stream is broken, probably the server has disconnected.
                std::cout << "Client " << client_name << ": Stream broken, failed to write." << std::endl;
                break;
            }
            // Add a small delay to simulate real-world log generation
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        // Signal that the client has finished writing to the stream.
        writer->WritesDone();

        // Wait for the server to send back the Ack.
        Status status = writer->Finish();

        if (status.ok()) {
            std::cout << "Client " << client_name << " received Ack: " << ack.message() << std::endl;
        } else {
            std::cout << "Client " << client_name << " RPC failed: "
                      << status.error_code() << ": " << status.error_message() << std::endl;
        }
        return status;
    }

private:
    std::unique_ptr<LogStream::Stub> stub_;
};

int 
main(int argc, char** argv) 
{
    std::string target_address = "localhost:50051";
    int num_clients = 1;
    int entries_per_client = 5;

    if (argc > 1) {
        num_clients = std::stoi(argv[1]);
    }
    if (argc > 2) {
        entries_per_client = std::stoi(argv[2]);
    }

    std::cout << "Starting " << num_clients << " client(s), each sending "
              << entries_per_client << " log entries." << std::endl;

    std::vector<std::thread> client_threads;
    for (int i = 0; i < num_clients; ++i) {
        std::string client_name = "cli" + std::to_string(i + 1);
        client_threads.emplace_back([target_address, client_name, entries_per_client]() {
            LogStreamClient client(grpc::CreateChannel(
                target_address, grpc::InsecureChannelCredentials()));
            client.SendLogStream(client_name, entries_per_client);
        });
    }

    // Join all client threads to wait for them to complete
    for (std::thread& t : client_threads) {
        t.join();
    }

    std::cout << "All clients finished." << std::endl;
    return 0;
}

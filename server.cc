/*
 * Server responsibilities:
 *  - accept streaming messages from multiple clients
 *  - read and print metadata
 *  - write to db or other buffer
 *  - produce reports for a specified time interval
 */

#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <thread>
#include <string>
#include <chrono>
#include "protos/threathunter.grpc.pb.h"
#ifdef __linux__
#include "vendor/include/linux/utils.h"
#endif
//#define DBG

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
//using grpc::ServerReaderWriter;
using grpc::Status;
using threathunter::LogStream;
using threathunter::LogEntry;
using threathunter::Ack;


// LogStreamServiceImpl implements the LogStream gRPC service.
class LogStreamServiceImpl final : public LogStream::Service {
public:
    // SendLog is a client-streaming RPC.
    // The client sends a stream of LogEntry messages, and the server sends a single Ack.
    Status SendLog(ServerContext* context, grpc::ServerReader<LogEntry>* reader, Ack* ack) override {
        LogEntry log_entry;
        int received_count = 0;

        // Read all LogEntry messages from the client's stream
        while (reader->Read(&log_entry)) {
            received_count++;
            std::cout << "Received LogEntry from " << context->peer() << ":\n";
            std::cout << "  Source: " << log_entry.source() << "\n";
            std::cout << "  Hostname: " << log_entry.hostname() << "\n";
            std::cout << "  Path: " << log_entry.path() << "\n";
            std::cout << "  Timestamp: " << log_entry.timestamp() << "\n";
            std::cout << "  Content: " << log_entry.content() << "\n";
            std::cout << "----------------------------------------\n";

            // In a real application, you would write this to a database, file, or message queue.
            // For this example, we just print it.
            // Example for database write (conceptual):
            // my_database_writer.WriteLogEntry(log_entry);
        }

        // Set the acknowledgment message
        ack->set_message("Server received " + std::to_string(received_count) + " log entries.");

        // Return OK status, indicating successful processing of the stream
        return Status::OK;
    }
};

// Function to run the gRPC server
void RunServer() {
    std::string server_address("0.0.0.0:50051"); // Listen on all interfaces, port 50051
    LogStreamServiceImpl service; // Instantiate our service implementation

    ServerBuilder builder;
    // Add the listening port without any authentication for this example.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    // Register our service implementation with the server builder.
    builder.RegisterService(&service);

    // Build and start the gRPC server
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;

    // Wait for the server to shut down. This keeps the server running.
    server->Wait();
}

int
main(void)
{
#ifdef __linux__
#ifdef DBG
    about();
#endif
#endif
    /*
    LogEntry log_entry;
    std::cout << "hello from server\n";
    // Set the fields of the LogEntry
    log_entry.set_source("example_source");
    log_entry.set_hostname("example_hostname");
    log_entry.set_path("/var/log/example.log");
    log_entry.set_timestamp(1678886400); // Example timestamp
    log_entry.set_content("This is an example log message.");

    // Access the fields
    std::cout << "Source: " << log_entry.source() << std::endl;
    std::cout << "Hostname: " << log_entry.hostname() << std::endl;
    std::cout << "Path: " << log_entry.path() << std::endl;
    std::cout << "Timestamp: " << log_entry.timestamp() << std::endl;
    std::cout << "Content: " << log_entry.content() << std::endl;
    */
    RunServer();
    return 0;
}

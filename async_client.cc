#include "protos/threathunter.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/initialize.h"
#include "absl/strings/str_format.h"

#include "utils.h"
#include "silo.h"


using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientAsyncResponseReader;
using grpc::CompletionQueue;
using grpc::Status;
using threathunter::Greeter;
using threathunter::HelloRequest;
using threathunter::HelloReply;

class GreeterClient 
{
 public:
    GreeterClient(std::shared_ptr<Channel> channel)
        : stub_(Greeter::NewStub(channel)) {}

    void StartReading() {
        std::thread cq_thread([this]() { ProcessReplies(); });
        // use pcap here
        for (int i = 0; i < 10; ++i) {
            SayHello_("user " + std::to_string(i));
        }
        cq_thread.join();
    }
 private:
    struct AsyncClientCall_ {
        HelloReply reply;
        ClientContext context;
        Status status;
        std::unique_ptr<ClientAsyncResponseReader<HelloReply>> response_reader;
    };

    void SayHello_(const std::string& user) 
    {
        HelloRequest request;
        request.set_name(user);

        AsyncClientCall_* call = new AsyncClientCall_;

        // TODO: probably should use the bidi proto stream from Greeter service
 
        call->response_reader = stub_->AsyncSayHello(&call->context, request, &cq_);
        call->response_reader->Finish(&call->reply, &call->status, (void*)call);

        /////////////////////////////////////////////////
        // using AsyncClientCall_ to process client data.
        //HelloReply reply;

        //ClientContext context;

        //CompletionQueue cq;
    
        //Status status;// = stub_->SayHello(&context, request, &reply);

        //std::unique_ptr<ClientAsyncResponseReader<HelloReply>> rpc(
        //        stub_->AsyncSayHello(&context, request, &cq));

        //rpc->Finish(&reply, &status, (void*)1);

        //void* got_tag;
        //bool ok = false; 

        ////block until result is available in cq.
        //CHECK(cq.Next(&got_tag, &ok));
        ////verify that it corresponds to previous request
        //CHECK_EQ(got_tag, (void*)1);
        ////is completed successfully
        //CHECK(ok);

        //if (status.ok()) {
        //    return reply.message();
        //} else {
        //    std::cout 
        //        << status.error_code() 
        //        << ": " 
        //        << status.error_message() << std::endl;
        //    return "RPC failed..";
        //}
        ///////////////////////////////////////////////
    }

    void ProcessReplies() {
        void* tag;
        bool ok = false;
        while (cq_.Next(&tag, &ok)) {
            AsyncClientCall_* call = static_cast<AsyncClientCall_*>(tag);

            if (ok && call->status.ok()) {
                std::cout << "Client received: " 
                    << call->reply.message() << std::endl;
            } else {
                std::cerr << "RPC failed: " 
                    << call->status.error_code() << ": " 
                    << call->status.error_message() << std::endl;
            }
            delete call;
        }
    }
 private:
    std::unique_ptr<Greeter::Stub> stub_;
    CompletionQueue cq_;
};

int
main(int argc, char** argv)
{
    // testing vendor headers.
    // TODO: specify what ports to listen to in a config file.
    //      use bpf filters to check if known malicious ip.
    //      what other data points can be checked using bpf filtering?
    //get_ip_address("endepointe.com");
    //bpf_filter_and_listen("tcp and port 443");
    ///////////////////////////////////////////
    //absl::ParseCommandLine(argc, argv);
    const std::string target_str("localhost:50053");
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = load_string_from_file("./credentials/root.crt");
    try {
        if (ssl_opts.pem_root_certs.empty()) {
            throw std::runtime_error("empty root.crt file");
        }
    } catch (const std::exception& e) {
        std::cerr << "unable to read " << e.what() << std::endl;
        throw;
    }
    GreeterClient greeter(grpc::CreateChannel(target_str, grpc::SslCredentials(ssl_opts)));
    //std::string user("world!");
    //std::string reply = greeter.SayHello(user);
    //std::cout << "Client rcvd: " << reply << std::endl;
    //greeter.StartReading();
    Silo silo;
    silo.filter_and_listen();
    return 0;
}

#include "protos/threathunter.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/initialize.h"
#include "absl/strings/str_format.h"

#include <iostream>
#include <memory>
#include <string>

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

    std::string SayHello(const std::string& user, const std::string& mood) 
    {
        HelloRequest request;
        request.set_name(user);
        request.set_mood(mood);

        HelloReply reply;

        ClientContext context;

        CompletionQueue cq;
    
        // async
        Status status;// = stub_->SayHello(&context, request, &reply);

        std::unique_ptr<ClientAsyncResponseReader<HelloReply>> rpc(
                stub_->AsyncSayHello(&context, request, &cq));

        rpc->Finish(&reply, &status, (void*)1);

        void* got_tag;
        bool ok = false; 

        //block until result is available in cq.
        CHECK(cq.Next(&got_tag, &ok));
        //verify that it corresponds to previous request
        CHECK_EQ(got_tag, (void*)1);
        //is completed successfully
        CHECK(ok);

        if (status.ok()) {
            return reply.message();
        } else {
            std::cout 
                << status.error_code() 
                << ": " 
                << status.error_message() << std::endl;
            return "RPC failed..";
        }
    }
private:
    std::unique_ptr<Greeter::Stub> stub_;
};

int
main(int argc, char** argv)
{
    absl::ParseCommandLine(argc, argv);
    const std::string target_str("0.0.0.0:50053");
    GreeterClient greeter(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));
    std::string user("world");
    std::string mood("eq");
    std::string reply = greeter.SayHello(user,mood);
    std::cout << "Greeter rcvd: " << reply << std::endl;
    return 0;
}

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
#include <thread>

using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCompletionQueue;
using grpc::Status;
using threathunter::Greeter;
using threathunter::HelloRequest;
using threathunter::HelloReply;

class ServerImpl final
{
public:
    ~ServerImpl() 
    {
        server_->Shutdown();
        cq_->Shutdown();
    }
    
    void Run(uint16_t port) 
    {
        std::string server_address("0.0.0.0:" + std::to_string(port));

        grpc::EnableDefaultHealthCheckService(true);

        ServerBuilder builder;

        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        builder.RegisterService(&service_);

        cq_ = builder.AddCompletionQueue();

        server_ = builder.BuildAndStart();

        std::cout << "Async server listening on " << server_address << std::endl;

        HandleRpcs();
    }

private:
    class CallData
    {
     public:
        CallData(Greeter::AsyncService* service, ServerCompletionQueue* cq)
            : service_(service), cq_(cq), responder_(&ctx_), status_(CREATE)
        {
            Proceed();
        }

        void Proceed() 
        {
            if (status_ == CREATE) {
                status_ = PROCESS;
                service_->RequestSayHello(&ctx_, &request_, &responder_, cq_, cq_, this);
            } else if (status_ == PROCESS) {
                new CallData(service_, cq_);
                std::string prefix("Hello ");
                reply_.set_message(prefix + request_.name());
                status_ = FINISH;
                responder_.Finish(reply_, Status::OK, this);
            } else {
                CHECK_EQ(status_, FINISH);
                delete this;
            }
        }
     private:
        Greeter::AsyncService* service_;
        ServerCompletionQueue* cq_;
        ServerContext ctx_;
        HelloRequest request_;
        HelloReply reply_;
        ServerAsyncResponseWriter<HelloReply> responder_;
        enum CallStatus { CREATE, PROCESS, FINISH };
        CallStatus status_;
    };

    void HandleRpcs() 
    {
        new CallData(&service_, cq_.get());
        void* tag;
        bool ok;
        while (true){
            CHECK(cq_->Next(&tag, &ok));
            CHECK(ok);
            static_cast<CallData*>(tag)->Proceed();
        }
    }
    
    std::unique_ptr<ServerCompletionQueue> cq_;
    Greeter::AsyncService service_;
    std::unique_ptr<Server> server_;
};

/* // blocking impl 
class GreeterServiceImpl final : public Greeter::Service 
{
    Status SayHello(ServerContext* ctx, 
                    const HelloRequest* request, 
                    HelloReply* reply) override
    {
        std::string prefix("Hello ");
        reply->set_message(prefix + request->name());
        return Status::OK;
    }
};
*/

/* // blocking
void 
RunServer(uint16_t port)
{
    const std::string server_address("0.0.0.0:" + std::to_string(port));
    GreeterServiceImpl service;
    
    grpc::EnableDefaultHealthCheckService(true);

    ServerBuilder builder;

    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Async server listening on " << server_address << std::endl;

    server->Wait();
}
*/

int
main(int argc, char** argv)
{
    absl::ParseCommandLine(argc, argv);
    absl::InitializeLog();
    ServerImpl server;

    server.Run(50053);

    return 0;
}


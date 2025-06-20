#include "protos/threathunter.grpc.pb.h"
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/initialize.h"
#include "absl/strings/str_format.h"

#include "utils.h"

#include <memory>
#include <thread>
#include <vector>
#include <stdexcept>

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
   
    // The port should not change in production, highly unlikely.
    // ...may remove the port param and just specify a set of ports
    // that the server can use.
    void Run(uint16_t port) 
    {
        std::string server_address("localhost:" + std::to_string(port));

        grpc::EnableDefaultHealthCheckService(true);

        std::ifstream file("server_config.toml");
        if (file.is_open()) {
            std::string line;
            bool in_silos = false;
            while (std::getline(file, line)) {
                if (!in_silos) {
                    line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
                    if (line.empty()) continue;
                    if (line[0] == '#') continue;
                    if (line[0] == ']') break;

                    line.erase(std::remove(line.begin(), line.end(), '"'), line.end());
                    line.erase(std::remove(line.begin(), line.end(), ','), line.end());

                    allowed_client_ips_.push_back(line);
                }
            }
        } else {
            throw std::runtime_error("unable to read server_config.toml");
        }

        for (long unsigned int i = 0; i < allowed_client_ips_.size(); i++) {
            std::cout << allowed_client_ips_[i]  << std::endl;
        }

        file.close();
    
        grpc::SslServerCredentialsOptions ssl_opts;
        grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert_pair;

        try {
            key_cert_pair.private_key = load_string_from_file("./credentials/localhost.key");
            if (key_cert_pair.private_key.empty()) {
                throw std::runtime_error("Empty key file");
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to read private key: " << e.what() << std::endl;
            throw;
        }

        try {
            key_cert_pair.cert_chain = load_string_from_file("./credentials/localhost.crt");
             if (key_cert_pair.cert_chain.empty()) {
                throw std::runtime_error("Empty cert file");
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to read certificate chain: " << e.what() << std::endl;
            throw;
        }

        ServerBuilder builder;

        ssl_opts.pem_key_cert_pairs.emplace_back(key_cert_pair);

        builder.AddListeningPort(server_address, grpc::SslServerCredentials(ssl_opts));

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
    }; // end CallData class

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
    } // end HandleRpcs fn

    std::unique_ptr<ServerCompletionQueue> cq_;
    Greeter::AsyncService service_;
    std::unique_ptr<Server> server_;
    std::vector<std::string> allowed_client_ips_;
};

/*
To verify if a server is using TLS from the bash command line, you can use `openssl s_client`.

```bash
openssl s_client -connect <host>:<port> -servername <host>
```

*   Replace `<host>` with the server's hostname or IP address.
*   Replace `<port>` with the port number the server is listening on.
*   The `-servername <host>` option is important for servers that use SNI (Server Name Indication) to host multiple TLS certificates on the same IP address.

If the server is using TLS, you'll see output that includes certificate information and the TLS handshake details. If it's not using TLS, the connection will likely fail, or you won't see any certificate information.

To specifically check the negotiated TLS version, you can add the `-ssl3`, `-tls1`, `-tls1_1`, `-tls1_2`, or `-tls1_3` options to force a specific version. If the connection succeeds, the server supports that TLS version. For example:

```bash
openssl s_client -connect <host>:<port> -servername <host> -tls1_2
```

If you only want to see the certificate:

```bash
openssl s_client -showcerts -connect <host>:<port> -servername <host> </dev/null
```
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


#include "utils.h"
#include "recon.h"

int
get_ip_address(const std::string& name)
{
    int status = 0;
    struct addrinfo hints, *res, *p;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(name.c_str(), NULL, &hints, &res)) != 0){
        std::cerr << "getaddrinfo: " << gai_strerror(status) << std::endl;
        return status;
    }

    std::cout << "IP addresses for hostname=endepointe.com:\n\n";

    for (p = res; p != nullptr; p = p->ai_next) {
        void *addr;
        std::string ipver;
        struct sockaddr_in *ipv4;
        struct sockaddr_in6 *ipv6;
        if (p->ai_family == AF_INET) {
            ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        std::cout << "\t" << ipver << ": " << ipstr << std::endl;
    }

    freeaddrinfo(res);

    return status;
}

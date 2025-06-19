#ifndef RECON_H
#define RECON_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int get_ip_address(const std::string&);

#endif

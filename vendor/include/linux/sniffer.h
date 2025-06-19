#ifndef SNIFFER_H 
#define SNIFFER_H

#include "utils.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int bpf_filter_and_listen(const std::string&);

#endif

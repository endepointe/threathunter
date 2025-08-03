#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <dirent.h>
#include <unistd.h>
#include <cstring>

void hello(const std::string&);

struct ProcessInfo {
    int pid;
    std::string name;
};

struct ConnectionInfo {
    std::string proto;
    std::string local_addr;
    std::string remote_addr;
};

std::vector<ProcessInfo> get_processes(void);

std::vector<ConnectionInfo> get_connections(const std::string&);

std::string get_hostname(void);

void collect_linux_system_info(void);

#include <iostream>
#include <vector>
#include <string>

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

void collect_windows_system_info(void);

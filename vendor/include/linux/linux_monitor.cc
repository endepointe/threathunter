#include "linux_monitor.h" 

void hello(const std::string& name) 
{
    std::cout << "hello " << name << "\n";
}

std::vector<ProcessInfo> get_processes(void) 
{
    std::vector<ProcessInfo> processes;
    DIR* proc = opendir("/proc");
    if (!proc) return processes;
    
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr)
    {
        if (entry->d_type == DT_DIR) {
            int pid = atoi(entry->d_name);
            if (pid > 0) {
                std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
                std::string name;
                if (comm) {
                    std::getline(comm, name);
                    processes.push_back({pid, name});
                }
            }
        }
    }
    closedir(proc);
    return processes;
}

std::vector<ConnectionInfo> get_connections(const std::string& proto) 
{
    std::vector<ConnectionInfo> conns;
    std::ifstream file("/proc/net/" + proto);
    if (!file) return conns;

    std::string line;
    //std::getline(file, line); //skips the header but I want to check this header. commenting out.

    while (std::getline(file, line)) 
    {
        std::istringstream iss(line);
        std::string local, remote, rest;
        int dummy;
        iss >> dummy >> local >> remote;
        conns.push_back({proto, local, remote});
    }
    return conns;
}

std::string get_hostname(void) 
{
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0) {
        return buf;
    }
    return "unknown";
}

void collect_linux_system_info(void) 
{
    std::cout << "Hostname: " << get_hostname() << "\n";
    std::vector processes = get_processes();
    for (auto &p : processes) 
    {
        std::cout << "PID: " << p.pid << " Name: " << p.name << "\n";
    }
    auto tcp = get_connections("tcp");
    auto udp = get_connections("udp");

    std::cout << "\nTCP Connections: " << tcp.size() << "\n";
    for (auto &c : tcp) 
    {
        std::cout << c.proto << " Local: " << c.local_addr << " Remote: " << c.remote_addr << "\n";
    }

    std::cout << "\nUDP Connections: " << tcp.size() << "\n";
    for (auto &c : udp) 
    {
        std::cout << c.proto << " Local: " << c.local_addr << " Remote: " << c.remote_addr << "\n";
    }
}

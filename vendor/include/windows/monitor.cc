#include <iostream>
#include <vector>
#include <string>

std::vector<ProcessInfo> get_processes(void) 
{
    // TODO: Implement with WMI Query or EnumProcesses API
    std::cout << "[Windows] Process enumeration not implemented.\n";
    return {};
}

std::vector<ConnectionInfo> get_connections(const std::string& proto) 
{
    // TODO: Implement with GetExtendedTcpTable / GetExtendedUdpTable
    std::cout << "[Windows] Connection enumeration not implemented.\n";
    return {};
}

std::string get_hostname(void) 
{
    // TODO: Use GetComputerNameEx
    return "[Windows] Hostname placeholder";
}

void collect_windows_system_info() {
    std::cout << "[Windows] System info collection not yet implemented.\n";
}

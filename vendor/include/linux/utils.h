#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <stdio.h>
#include <stdint.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <unordered_set>
#include <sys/sysinfo.h>
#include <random>

void about(void);

int get_ip_address(const std::string&);
std::string load_string_from_file(std::string path);

#endif


#include "utils.h"


void about()
{
    std::cout << "about() called from vendor/include/linux/utils.cc\n";
}

std::string load_string_from_file(std::string path)
{
    std::ifstream file(path);
    if (!file.is_open())
    {
        std::cout << "utils.cc:load_string_from_file - unable to open " << path << std::endl;
        return std::string("");
    }

    std::stringstream sstr;
    sstr << file.rdbuf();
    return sstr.str();
}

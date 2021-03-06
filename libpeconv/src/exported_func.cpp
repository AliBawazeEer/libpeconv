#include "peconv\exported_func.h"

#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace peconv;

char easytolower(char in)
{
    if (in<='Z' && in>='A')
    return in-('Z'-'z');
    return in;
}

std::string peconv::get_dll_name(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t found = str.find_last_of("/\\");
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(found+1, ext - (found+1));
    std::transform(name.begin(), name.end(), name.begin(), easytolower);
    return name;
}

size_t peconv::forwarder_name_len(BYTE* fPtr)
{
    bool has_dot = false;
    size_t len = 0;
    while ((*fPtr >= 'a' && *fPtr <= 'z')
            || (*fPtr >= 'A' && *fPtr <= 'Z')
            || (*fPtr >= '0' && *fPtr <= '9')
            || (*fPtr == '.')
            || (*fPtr == '_') 
            || (*fPtr == '-'))
    {
        if (*fPtr == '.') has_dot = true;
        len++;
        fPtr++;
    }
    if (*fPtr == '\0') {
        if (!has_dot) {
            return 0; //this is not a valid forwarder
        }
        return len;
    }
    return 0;
}

std::string peconv::get_func_name(const std::string& str)
{
    std::size_t len = str.length();
    std::size_t ext = str.find_last_of(".");
    if (ext >= len) return "";

    std::string name = str.substr(ext+1, len - (ext+1));
    return name;
}

std::string peconv::format_dll_func(const std::string& str)
{
    std::string dllName = get_dll_name(str);
    std::string funcName = get_func_name(str);
    if (dllName.length() == 0 || funcName.length() == 0) {
        return "";
    }
    std::transform(dllName.begin(), dllName.end(), dllName.begin(), easytolower);
    return dllName + "." + funcName;
}

ExportedFunc::ExportedFunc(std::string libName, std::string funcName, DWORD funcOrdinal)
{
    this->libName = ExportedFunc::formatName(libName);
    this->funcName = funcName;
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = false;
}

ExportedFunc::ExportedFunc(std::string libName, DWORD funcOrdinal)
{
    this->libName = ExportedFunc::formatName(libName);
    this->funcOrdinal = funcOrdinal;
    this->isByOrdinal = true;
}

ExportedFunc::ExportedFunc(const ExportedFunc& other)
{
    this->libName = other.libName;
    this->funcName = other.funcName;
    this->funcOrdinal = other.funcOrdinal;
    this->isByOrdinal = other.isByOrdinal;
}

ExportedFunc::ExportedFunc(const std::string &forwarderName)
{
    this->funcName = get_func_name(forwarderName);
    this->libName = get_dll_name(forwarderName);
    this->isByOrdinal = false;
}

std::string ExportedFunc::formatName(std::string name)
{
    if (name.length() == 0 || name.length() == 0) {
        return "";
    }
    std::transform(name.begin(), name.end(), name.begin(), easytolower);
    return name;
}

std::string ExportedFunc::toString() const
{
    std::stringstream stream;
    stream << this->libName;
    stream << ".";
    if (!this->isByOrdinal) {
        stream << this->funcName;
        stream << " ";
    }
    stream << "<";
    stream << std::hex << this->funcOrdinal;
    stream << ">";
    return stream.str();
}

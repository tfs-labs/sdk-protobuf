#ifndef __HIGH_PRECISION__
#define __HIGH_PRECISION__
#include<iostream>

namespace HighPrecision
{
    std::string add(std::string s1, std::string s2);
    std::string sub(std::string s1, std::string s2);
    bool cmp(std::string s1, std::string s2);
    std::string Add(std::string s1, std::string s2);
    std::string Sub(std::string s1, std::string s2);
    std::string multi(std::string s1, std::string s2);
    std::pair<std::string, std::string> divide(std::string s1, std::string s2);
}

#endif
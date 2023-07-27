#ifndef __HELPER_H__
#define __HELPER_H__

#include <string>

namespace IPSHelper
{

bool hasDeobfuscation();
std::string deobfuscateString(const std::string &str);
std::string deobfuscateKeyword(const std::string &str);

} // IPSHelper

#endif // __HELPER_H__

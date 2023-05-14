#include "helper.h"

#include "config.h"

using namespace std;

namespace IPSHelper
{

string
deobfuscateString(const string &str)
{
    if (str.substr(0, 7) == "M^AGI$C") reportConfigurationError("Deobfuscation isn't available in open-source mode");
    return str;
}

string
deobfuscateKeyword(const string &str)
{
    if (str.substr(0, 7) == "M^AGI$C") reportConfigurationError("Deobfuscation isn't available in open-source mode");
    return str;
}

}  // IPSHelper

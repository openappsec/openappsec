// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __AGENT_CORE_UTILITIES_H__
#define __AGENT_CORE_UTILITIES_H__

#include <sys/stat.h>
#include <string>
#include <boost/regex.hpp>

#include "maybe_res.h"

namespace NGEN
{

namespace Filesystem
{

bool exists(const std::string &path);
bool isDirectory(const std::string &path);
Maybe<std::vector<std::string>> getDirectoryFiles(const std::string &path);
bool makeDir(const std::string &path, mode_t permission = S_IRWXU);
bool makeDirRecursive(const std::string &path, mode_t permission = S_IRWXU);
bool deleteDirectory(const std::string &path, bool delete_content = false);

bool
copyFile(
    const std::string &src,
    const std::string &dest,
    bool overide_if_exists,
    mode_t permission = (S_IWUSR | S_IRUSR)
);

bool deleteFile(const std::string &path);

std::string convertToHumanReadable(uint64_t size_in_bytes);

std::string getFileName(const std::string &path);

}// namespace Filesystem

namespace Regex
{

bool
regexMatch(const char *file, int line, const char *sample, boost::cmatch &match, const boost::regex &regex);

bool
regexMatch(const char *file, int line, const std::string &sample, boost::smatch &match, const boost::regex &regex);

bool
regexMatch(const char *file, int line, const std::string &sample, const boost::regex &regex);

bool
regexMatch(const char *file, int line, std::string &sample, const boost::regex &regex);

bool
regexSearch(const char *file, int line, const std::string &sample, boost::smatch &match, const boost::regex &regex);

std::string
regexReplace(
    const char *file,
    int line,
    const std::string &sample,
    const boost::regex &regex,
    const std::string &replace
);

} // namespace Regex

namespace Strings
{

std::string removeTrailingWhitespaces(std::string str);

} // namespace Strings

} // namespace NGEN

#endif // __AGENT_CORE_UTILITIES_H__

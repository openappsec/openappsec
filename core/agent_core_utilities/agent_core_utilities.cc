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

#include "agent_core_utilities.h"

#include <sys/stat.h>
#include <string>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#include "debug.h"

using namespace std;
using namespace boost;

USE_DEBUG_FLAG(D_INFRA_UTILS);

namespace NGEN
{

namespace Filesystem
{

bool
exists(const string &path)
{
    dbgFlow(D_INFRA_UTILS) << "Checking if path exists. Path: " << path;
    struct stat buffer;
    if (stat(path.c_str(), &buffer) == 0) {
        dbgTrace(D_INFRA_UTILS) << "Path already exists. Path: " << path;
        return true;
    }

    dbgTrace(D_INFRA_UTILS) << "Path does not exists. Path: " << path;
    return false;
}

bool
isDirectory(const string &path)
{
    dbgFlow(D_INFRA_UTILS) << "Checking if path is a directory. Path: " << path;
    struct stat buffer;
    if (stat(path.c_str(), &buffer) != 0) {
        dbgTrace(D_INFRA_UTILS) << "Path does not exists. Path: " << path;
        return false;
    }

    if (buffer.st_mode & S_IFDIR) {
        dbgTrace(D_INFRA_UTILS) << "Path is a directory. Path: " << path;
        return true;
    }

    return false;
}

Maybe<vector<string>>
getDirectoryFiles(const string &path)
{
    if (!isDirectory(path)) return genError("Path: " + path + " is not a directory");

    struct dirent *entry = nullptr;
    DIR *directory = opendir(path.c_str());

    if (!directory) {
        dbgWarning(D_INFRA_UTILS) << "Fail to open directory. Path: " << path << ", Errno: " << errno;
        return genError("Failed to open directory: " + path);
    }

    vector<string> files;
    while ((entry = readdir(directory))) {
        if (entry->d_type == DT_REG) files.push_back(entry->d_name);
    }

    closedir(directory);

    return files;
}

bool
makeDir(const string &path, mode_t permission)
{
    dbgFlow(D_INFRA_UTILS)
        << "Trying to create directory. Path: "
        << path
        << ", permission: "
        << to_string(permission);

    if (mkdir(path.c_str(), permission) != 0) {
        int error = errno;
        dbgDebug(D_INFRA_UTILS) << "Failed to create directory. Path: " << path << ", Error: " << error;
        return false;
    }

    dbgTrace(D_INFRA_UTILS) << "Successfully created directory. Path: " << path;
    return true;
}

/// @brief Get basename of a path
/// @param path path to a file
/// @return base file name
string
getFileName(const string &path)
{
    dbgFlow(D_INFRA_UTILS) << "Trying to extract file name from path: " << path;
    size_t pos = path.rfind("/");
    if (pos != string::npos) return path.substr(pos+1, path.length() - pos);

    return path;
}

bool
makeDirRecursive(const string &path, mode_t permission)
{
    dbgFlow(D_INFRA_UTILS)
        << "Trying to create directory. Path: "
        << path
        << ", permission: "
        << to_string(permission);
    stringstream path_stream(path);
    const char path_delimiter = '/';
    string sub_path = (path.front() == path_delimiter ? "/" : "");
    string token;

    while (getline(path_stream, token, path_delimiter)) {
        if (token == "") continue;
        sub_path += (token + path_delimiter);
        if (!exists(sub_path) && !makeDir(sub_path, permission)) {
            dbgDebug(D_INFRA_UTILS) << "Failed to create directory. Path: " << path;
            return false;
        }
    }

    dbgTrace(D_INFRA_UTILS) << "Successfully created directory. Path: " << path;
    return true;
}

bool
copyFile(const string &src, const string &dest, bool overide_if_exists, mode_t permission)
{
    dbgFlow(D_INFRA_UTILS)
        << "Trying to copy file. Source: "
        << src
        << ", Destination: "
        << dest
        << ", Should override: "
        << (overide_if_exists? "true" : "false")
        << ", permission: "
        << to_string(permission);
    if (!exists(src)) {
        dbgDebug(D_INFRA_UTILS) << "Failed to copy file. Error: source file does not exists";
        return false;
    }

    if (exists(dest) && !overide_if_exists) {
        dbgDebug(D_INFRA_UTILS) << "Failed to copy file. Error: destination file already exists";
        return false;
    }

    struct stat stat_buf;
    int source_fd = open(src.c_str(), O_RDONLY);
    fstat(source_fd, &stat_buf);
    int dest_fd = open(dest.c_str(), O_WRONLY | O_CREAT | O_TRUNC, permission);
    int bytes_copied = 1;
    while (bytes_copied > 0) {
        static const int buf_size = 4096*1000;
        bytes_copied = sendfile(dest_fd, source_fd, 0, buf_size);
    }

    dbgTrace(D_INFRA_UTILS) << "Finished attempt to copy file. Res: " << (bytes_copied != -1 ? "Success" : "Error");
    close(source_fd);
    close(dest_fd);
    return bytes_copied != -1;
}


bool
deleteFile(const string &path)
{
    dbgFlow(D_INFRA_UTILS) << "Trying to delete file. Path: " << path;
    if (unlink(path.c_str()) != 0) {
        int error = errno;
        dbgDebug(D_INFRA_UTILS) << "Failed to delete file. Path: " << path << ", Error: " << error;
        return false;
    }

    dbgTrace(D_INFRA_UTILS) << "Successfully delete file. Path: " << path;
    return true;
}

string
resolveFullPath(const string &input_path) {
    dbgTrace(D_INFRA_UTILS) << "Resolving absolute path: " << input_path;
    char resolved_path[PATH_MAX];
    if (!realpath(input_path.c_str(), resolved_path)) {
        dbgWarning(D_INFRA_UTILS) << "Error resolving path: " << input_path << ", errno: " << errno;
        return "";
    }

    return string(resolved_path);
}

bool
deleteDirectory(const string &path, bool delete_content)
{
    dbgFlow(D_INFRA_UTILS)
        << "Trying to delete directory. Path: "
        << path
        << ", Delete content: "
        << (delete_content? "true" : "false");

    struct dirent *entry = nullptr;
    DIR *directory = opendir(path.c_str());

    if (directory == nullptr) {
        int orig_errno = errno;
        dbgWarning(D_INFRA_UTILS) << "Fail to open directory. Path: " << path << ", Errno: " << orig_errno;
        return false;
    }

    bool res = true;
    while (delete_content && (entry = readdir(directory))) {
        string entry_file_name = entry->d_name;
        static const string curr_dir(".");
        static const string parent_dir("..");
        if (entry_file_name == curr_dir || entry_file_name == parent_dir) {
            dbgTrace(D_INFRA_UTILS) << "Skipping irrelevant directory entries. Entry name: " << entry_file_name;
            continue;
        }

        entry_file_name = path + (path.back() == '/' ? "" : "/") + entry_file_name;
        struct stat statbuf;
        if (!stat(entry_file_name.c_str(), &statbuf)) {
            if (S_ISDIR(statbuf.st_mode)) {
                res &= deleteDirectory(entry_file_name, delete_content);
            } else {
                res &= deleteFile(entry_file_name);
            }
        }
    }

    res &= (rmdir(path.c_str()) == 0);
    dbgTrace(D_INFRA_UTILS) << "Finished attempt to delete directory. Res: " << (res ? "Success" : "Error");
    return res;
}

bool
touchFile(const string &path)
{
    dbgFlow(D_INFRA_UTILS) << "Trying to touch file, path: " << path;

    ofstream t_file(path);
    if (!t_file.is_open()) {
        dbgDebug(D_INFRA_UTILS) << "Failed to touch file. Path: " << path;
        return false;
    }

    t_file.close();
    dbgTrace(D_INFRA_UTILS) << "Successfully touched file, path: " << path;
    return true;
}

bool
copyDirectory(const string &src_dir_path, const string &dst_dir_path)
{
    dbgFlow(D_INFRA_UTILS)
        << "Trying to copy directory. Source: "
        << src_dir_path
        << ", Destination: "
        << dst_dir_path;

    if (!exists(src_dir_path) || !isDirectory(src_dir_path)) {
        dbgDebug(D_INFRA_UTILS) << "Failed to copy directory. Error: source directory does not exist";
        return false;
    }

    if (!exists(dst_dir_path)) {
        if (!makeDir(dst_dir_path, 0755)) {
            dbgDebug(D_INFRA_UTILS) << "Failed to copy directory. Error: failed to create destination directory";
            return false;
        }
    }

    if (!isDirectory(dst_dir_path)) {
        dbgDebug(D_INFRA_UTILS) << "Failed to copy directory. Error: destination path is not a directory";
        return false;
    }

    struct dirent *entry = nullptr;
    DIR *directory = opendir(src_dir_path.c_str());

    if (!directory) {
        dbgWarning(D_INFRA_UTILS) << "Fail to open directory. Path: " << src_dir_path;
        return false;
    }

    while ((entry = readdir(directory))) {
        string entry_name = entry->d_name;
        static const string curr_dir(".");
        static const string parent_dir("..");
        if (entry_name == curr_dir || entry_name == parent_dir) {
            dbgTrace(D_INFRA_UTILS) << "Skipping irrelevant directory entries. Entry name: " << entry_name;
            continue;
        }

        string src_entry_path = src_dir_path + (src_dir_path.back() == '/' ? "" : "/") + entry_name;
        string dst_entry_path = dst_dir_path + (dst_dir_path.back() == '/' ? "" : "/") + entry_name;
        struct stat statbuf;
        if (!stat(src_entry_path.c_str(), &statbuf)) {
            if (S_ISDIR(statbuf.st_mode)) {
                copyDirectory(src_entry_path, dst_entry_path);
            } else {
                copyFile(src_entry_path, dst_entry_path, true);
            }
        }
    }

    closedir(directory);

    return true;
}

string
convertToHumanReadable(uint64_t size_in_bytes)
{
    stringstream res;
    if (size_in_bytes < 1000) {
        res << size_in_bytes << " Bytes";
        return res.str();
    }
    float size = size_in_bytes;
    size /= 1024;
    res << setprecision(2) << fixed;
    if (size < 1000) {
        res << size << " KB";
        return res.str();
    }
    size /= 1024;
    if (size < 1000) {
        res << size << " MB";
        return res.str();
    }
    size /= 1024;
    res << size << " GB";
    return res.str();
}

}// namespace Filesystem

namespace Regex
{

bool
regexMatch(const char *file, int line, const char *sample, cmatch &match, const regex &regex)
{
    try {
        return regex_match(sample, match, regex);
    } catch (const runtime_error &err) {
        uint sample_len = strlen(sample);
        dbgError(D_INFRA_UTILS)
            << "FAILURE during regex_match @ "
            << file
            << ":"
            << line
            << "; sample size: "
            << sample_len
            << " sample='"
            << string(sample, min(100u, sample_len))
            << "', pattern='"
            << regex.str()
            << "': "
            << err.what();
        return false;
    }
}

bool
regexMatch(const char *file, int line, const string &sample, smatch &match, const regex &regex)
{
    try {
        return regex_match(sample, match, regex);
    } catch (const runtime_error &err) {
        dbgError(D_INFRA_UTILS)
            << "FAILURE during regex_match @ "
            << file
            << ":"
            << line
            << "; sample size: "
            << sample.size()
            << " sample='"
            << sample.substr(0, 100)
            << "', pattern='"
            << regex.str()
            << "': "
            << err.what();
        return false;
    }
}

bool
regexMatch(const char *file, int line, const string &sample, const regex &regex)
{
    try {
        return regex_match(sample, regex);
    } catch (const runtime_error &err) {
        dbgError(D_INFRA_UTILS)
            << "FAILURE during regex_match @ "
            << file
            << ":"
            << line
            << "; sample size: "
            << sample.size()
            << " sample='"
            << sample.substr(0, 100)
            << "', pattern='"
            << regex.str()
            << "': "
            << err.what();
        return false;
    }
}

bool
regexMatch(const char *file, int line, string &sample, const regex &regex)
{
    try {
        return regex_match(sample, regex);
    } catch (const runtime_error &err) {
        dbgError(D_INFRA_UTILS)
            << "FAILURE during regex_match @ "
            << file
            << ":"
            << line
            << "; sample size: "
            << sample.size()
            << " sample='"
            << sample.substr(0, 100)
            << "', pattern='"
            << regex.str()
            << "': "
            << err.what();
        return false;
    }
}

bool
regexSearch(const char *file, int line, const string &sample, smatch &match, const regex &regex)
{
    try {
        return regex_search(sample, match, regex);
    } catch (const runtime_error &err) {
        dbgError(D_INFRA_UTILS)
            << "FAILURE during regex_search @ "
            << file
            << ":"
            << line
            << "; sample size: "
            << sample.size()
            << " sample='"
            << sample.substr(0, 100)
            << "', pattern='"
            << regex.str()
            << "': "
            << err.what();
        return false;
    }
}

string
regexReplace(const char *file, int line, const string &sample, const regex &regex, const string &replace)
{
    try {
        return regex_replace(sample, regex, replace);
    } catch (const runtime_error &err) {
        dbgError(D_INFRA_UTILS)
            << "FAILURE during regex_replace @ "
            << file
            << ":"
            << line
            << ";  sample size: "
            << sample.size()
            << " sample='"
            << sample.substr(0, 100)
            << "', pattern='"
            << regex.str()
            << "', replace='"
            << replace
            << "': "
            << err.what();
        return sample;
    }
}

}// namespace Regex

namespace Strings
{

string
removeTrailingWhitespaces(string str)
{
    str.erase(
        find_if(str.rbegin(), str.rend(), [] (char c) { return !isspace(c); }).base(),
        str.end()
    );

    return str;
}

string
removeLeadingWhitespaces(string str)
{
    str.erase(
        str.begin(),
        find_if(str.begin(), str.end(), [] (char c) { return !isspace(c); })
    );

    return str;
}

string
trim(string str)
{
    return removeLeadingWhitespaces(removeTrailingWhitespaces(str));
}

} // namespace Strings

} // namespace NGEN

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

#include "nginx_utils.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <dirent.h>
#include <boost/regex.hpp>
#include <algorithm>

#include "debug.h"
#include "maybe_res.h"
#include "config.h"
#include "agent_core_utilities.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_MANAGER);

NginxConfCollector::NginxConfCollector(const string &input_path, const string &output_path)
        :
    main_conf_input_path(input_path),
    main_conf_output_path(output_path)
{
    main_conf_directory_path = main_conf_input_path.substr(0, main_conf_input_path.find_last_of('/'));
}

vector<string>
NginxConfCollector::expandIncludes(const string &include_pattern) const {
    vector<string> matching_files;
    string absolute_include_pattern = include_pattern;
    string maybe_directory = include_pattern.substr(0, include_pattern.find_last_of('/'));
    if (!maybe_directory.empty() && maybe_directory.front() != '/') {
        dbgTrace(D_NGINX_MANAGER) << "Include pattern is a relative path: " << include_pattern;
        maybe_directory = main_conf_directory_path + '/' + maybe_directory;
        absolute_include_pattern = main_conf_directory_path + '/' + include_pattern;
    }

    if (!NGEN::Filesystem::exists(maybe_directory)) {
        dbgTrace(D_NGINX_MANAGER) << "Include pattern directory/file does not exist: " << maybe_directory;
        return matching_files;
    }

    string filename_pattern = absolute_include_pattern.substr(absolute_include_pattern.find_last_of('/') + 1);
    boost::regex wildcard_regex("\\*");
    boost::regex pattern(
        NGEN::Regex::regexReplace(__FILE__, __LINE__, filename_pattern, wildcard_regex, string("[^/]*"))
    );

    if (!NGEN::Filesystem::isDirectory(maybe_directory)) {
        dbgTrace(D_NGINX_MANAGER) << "Include pattern is a file: " << absolute_include_pattern;
        matching_files.push_back(absolute_include_pattern);
        return matching_files;
    }

    DIR* dir = opendir(maybe_directory.c_str());
    if (!dir) {
        dbgTrace(D_NGINX_MANAGER) << "Could not open directory: " << maybe_directory;
        return matching_files;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (NGEN::Regex::regexMatch(__FILE__, __LINE__, entry->d_name, pattern)) {
            matching_files.push_back(maybe_directory + "/" + entry->d_name);
            dbgTrace(D_NGINX_MANAGER) << "Matched file: " << maybe_directory << '/' << entry->d_name;
        }
    }
    closedir(dir);
    sort(matching_files.begin(), matching_files.end());

    return matching_files;
}

void
NginxConfCollector::processConfigFile(const string &path, ostringstream &conf_output, vector<string> &errors) const
{
    ifstream file(path);
    if (!file.is_open()) return;

    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    dbgTrace(D_NGINX_MANAGER) << "Processing file: " << path;

    if (content.empty()) return;

    try {
        boost::regex include_regex(R"(^\s*include\s+([^;]+);)");
        boost::smatch match;

        while (NGEN::Regex::regexSearch(__FILE__, __LINE__, content, match, include_regex)) {
            string include_pattern = match[1].str();
            include_pattern = NGEN::Strings::trim(include_pattern);
            dbgTrace(D_NGINX_MANAGER) << "Include pattern: " << include_pattern;

            vector<string> included_files = expandIncludes(include_pattern);
            if (included_files.empty()) {
                dbgTrace(D_NGINX_MANAGER) << "No files matched the include pattern: " << include_pattern;
                content.replace(match.position(), match.length(), "");
                continue;
            }

            ostringstream included_content;
            for (const string &included_file : included_files) {
                dbgTrace(D_NGINX_MANAGER) << "Processing included file: " << included_file;
                processConfigFile(included_file, included_content, errors);
            }
            content.replace(match.position(), match.length(), included_content.str());
        }
    } catch (const boost::regex_error &e) {
        errors.emplace_back(e.what());
        return;
    } catch (const exception &e) {
        errors.emplace_back(e.what());
        return;
    }

    conf_output << content;
}

Maybe<string>
NginxConfCollector::generateFullNginxConf() const
{
    if (!NGEN::Filesystem::exists(main_conf_input_path)) {
        return genError("Input file does not exist: " + main_conf_input_path);
    }

    ostringstream conf_output;
    vector<string> errors;
    processConfigFile(main_conf_input_path, conf_output, errors);

    if (!errors.empty()) {
        for (const string &error : errors) dbgWarning(D_NGINX_MANAGER) << error;
        return genError("Errors occurred while processing configuration files");
    }

    ofstream single_nginx_conf_file(main_conf_output_path);
    if (!single_nginx_conf_file.is_open()) return genError("Could not create output file: " + main_conf_output_path);

    single_nginx_conf_file << conf_output.str();
    single_nginx_conf_file.close();

    return NGEN::Filesystem::resolveFullPath(main_conf_output_path);
}

string
NginxUtils::getMainNginxConfPath()
{
    static string main_nginx_conf_path;
    if (!main_nginx_conf_path.empty()) return main_nginx_conf_path;

    auto main_nginx_conf_path_setting = getProfileAgentSetting<string>("centralNginxManagement.mainConfPath");
    if (main_nginx_conf_path_setting.ok()) {
        main_nginx_conf_path = main_nginx_conf_path_setting.unpack();
        return main_nginx_conf_path;
    }

    string default_main_nginx_conf_path = "/etc/nginx/nginx.conf";
    string command = "nginx -V 2>&1";
    auto result = Singleton::Consume<I_ShellCmd>::by<NginxUtils>()->getExecOutputAndCode(command);
    if (!result.ok()) return default_main_nginx_conf_path;

    string output = result.unpack().first;
    boost::regex conf_regex(R"(--conf-path=([^ ]+))");
    boost::smatch match;
    if (!NGEN::Regex::regexSearch(__FILE__, __LINE__, output, match, conf_regex)) {
        main_nginx_conf_path = default_main_nginx_conf_path;
        return main_nginx_conf_path;
    }

    string conf_path = match[1].str();
    conf_path = NGEN::Strings::trim(conf_path);
    if (conf_path.empty()) {
        main_nginx_conf_path = default_main_nginx_conf_path;
        return main_nginx_conf_path;
    }

    main_nginx_conf_path = conf_path;
    return main_nginx_conf_path;
}

string
NginxUtils::getModulesPath()
{
    static string main_modules_path;
    if (!main_modules_path.empty()) return main_modules_path;

    auto modules_path_setting = getProfileAgentSetting<string>("centralNginxManagement.modulesPath");
    if (modules_path_setting.ok()) {
        main_modules_path = modules_path_setting.unpack();
        return main_modules_path;
    }

    string default_modules_path = "/usr/share/nginx/modules";
    string command = "nginx -V 2>&1";
    auto result = Singleton::Consume<I_ShellCmd>::by<NginxUtils>()->getExecOutputAndCode(command);
    if (!result.ok()) return default_modules_path;

    string output = result.unpack().first;
    boost::regex modules_regex(R"(--modules-path=([^ ]+))");
    boost::smatch match;
    if (!NGEN::Regex::regexSearch(__FILE__, __LINE__, output, match, modules_regex)) {
        main_modules_path = default_modules_path;
        return main_modules_path;
    }

    string modules_path = match[1].str();
    modules_path = NGEN::Strings::trim(modules_path);
    if (modules_path.empty()) {
        main_modules_path = default_modules_path;
        return main_modules_path;
    }

    main_modules_path = modules_path;
    return modules_path;
}

Maybe<void>
NginxUtils::validateNginxConf(const string &nginx_conf_path)
{
    dbgTrace(D_NGINX_MANAGER) << "Validating NGINX configuration file: " << nginx_conf_path;
    if (!NGEN::Filesystem::exists(nginx_conf_path)) return genError("Nginx configuration file does not exist");

    string command = "nginx -t -c " + nginx_conf_path + " 2>&1";
    auto result = Singleton::Consume<I_ShellCmd>::by<NginxUtils>()->getExecOutputAndCode(command);
    if (!result.ok()) return genError(result.getErr());
    if (result.unpack().second != 0) return genError(result.unpack().first);

    dbgTrace(D_NGINX_MANAGER) << "NGINX configuration file is valid";

    return {};
}

Maybe<void>
NginxUtils::reloadNginx(const string &nginx_conf_path)
{
    dbgTrace(D_NGINX_MANAGER) << "Applying and reloading new NGINX configuration file: " << nginx_conf_path;
    string main_nginx_conf_path = getMainNginxConfPath();

    string backup_conf_path = main_nginx_conf_path + ".bak";
    if (
        NGEN::Filesystem::exists(main_nginx_conf_path)
        && !NGEN::Filesystem::copyFile(main_nginx_conf_path, backup_conf_path, true)
    ) {
        return genError("Could not create backup of NGINX configuration file");
    }

    dbgTrace(D_NGINX_MANAGER) << "Copying new NGINX configuration file to: " << main_nginx_conf_path;
    if (!NGEN::Filesystem::copyFile(nginx_conf_path, main_nginx_conf_path, true)) {
        return genError("Could not copy new NGINX configuration file");
    }

    string command = "nginx -s reload 2>&1";
    auto result = Singleton::Consume<I_ShellCmd>::by<NginxUtils>()->getExecOutputAndCode(command);
    if (!result.ok() || result.unpack().second != 0) {
        if (!NGEN::Filesystem::copyFile(backup_conf_path, main_nginx_conf_path, true)) {
            return genError("Could not restore backup of NGINX configuration file");
        }
        dbgTrace(D_NGINX_MANAGER) << "Successfully restored backup of NGINX configuration file";
        return result.ok() ? genError(result.unpack().first) : genError(result.getErr());
    }

    dbgInfo(D_NGINX_MANAGER) << "Successfully reloaded NGINX configuration file";

    return {};
}

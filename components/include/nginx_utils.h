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

#ifndef __NGINX_UTILS_H__
#define __NGINX_UTILS_H__

#include <string>

#include "maybe_res.h"
#include "singleton.h"
#include "i_shell_cmd.h"

class NginxConfCollector
{
public:
    NginxConfCollector(const std::string &nginx_conf_input_path, const std::string &nginx_conf_output_path);
    Maybe<std::string> generateFullNginxConf() const;

private:
    std::vector<std::string> expandIncludes(const std::string &includePattern) const;
    void processConfigFile(
        const std::string &path,
        std::ostringstream &conf_output,
        std::vector<std::string> &errors
    ) const;

    std::string main_conf_input_path;
    std::string main_conf_output_path;
    std::string main_conf_directory_path;
};

class NginxUtils : Singleton::Consume<I_ShellCmd>
{
public:
    static std::string getModulesPath();
    static std::string getMainNginxConfPath();
    static Maybe<void> validateNginxConf(const std::string &nginx_conf_path);
    static Maybe<void> reloadNginx(const std::string &nginx_conf_path);
};

#endif // __NGINX_UTILS_H__

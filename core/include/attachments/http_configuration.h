// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __HTTP_CONFIGURATION_H__
#define __HTTP_CONFIGURATION_H__

#include <string>
#include <map>
#include <vector>

#include "cereal/archives/json.hpp"

struct DebugConfig
{
    void save(cereal::JSONOutputArchive &archive) const;
    void load(cereal::JSONInputArchive &archive);
    bool operator==(const DebugConfig &another) const;

    std::string client;
    std::string server;
    unsigned int port = 0;
    std::string method;
    std::string host;
    std::string uri;
};

class HttpAttachmentConfiguration
{
public:
    int init(const std::string &conf_file);

    void save(cereal::JSONOutputArchive &archive) const;
    void load(cereal::JSONInputArchive &archive);

    bool operator==(const HttpAttachmentConfiguration &other) const;

    unsigned int getNumericalValue(const std::string &key) const;
    const std::string & getStringValue(const std::string &key) const;
    const std::vector<std::string> & getExcludeSources() const { return exclude_sources; }
    const DebugConfig & getDebugContext() const { return dbg; }

    void setNumericalValue(const std::string &key, unsigned int value) { numerical_values[key] = value; }
    void setStringValue(const std::string &key, const std::string &value) { string_values[key] = value; }
    void setExcludeSources(const std::vector<std::string> &new_sources) { exclude_sources = new_sources; }
    void setDebugContext(const DebugConfig &_dbg) { dbg = _dbg; }

private:
    void loadNumericalValue(cereal::JSONInputArchive &archive, const std::string &name, unsigned int default_value);

    DebugConfig dbg;
    std::map<std::string, unsigned int> numerical_values;
    std::map<std::string, std::string> string_values;
    std::vector<std::string> exclude_sources;
    std::string empty;
};

#endif // __HTTP_CONFIGURATION_H__

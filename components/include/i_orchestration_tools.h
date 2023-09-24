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

#ifndef __I_ORCHESTRATION_TOOLS_H__
#define __I_ORCHESTRATION_TOOLS_H__

#include "package.h"
#include "debug.h"
#include "maybe_res.h"

#include <fstream>

USE_DEBUG_FLAG(D_ORCHESTRATOR);

class I_OrchestrationTools
{
public:
    // Used for the calculation of the manifest and the policy files
    static const Package::ChecksumTypes SELECTED_CHECKSUM_TYPE = Package::ChecksumTypes::SHA256;
    static constexpr const char * SELECTED_CHECKSUM_TYPE_STR = "sha256sum";
    using packageName = std::string;
    using packageDetails = std::string;

    template<class T>
    Maybe<T>
    jsonFileToObject(const std::string &file_path) const
    {
        Maybe<std::string> file_data = readFile(file_path);
        if (file_data.ok()) {
            return jsonStringToObject<T>(file_data.unpack());
        }
        return genError(file_data.getErr());
    }

    template<class T>
    Maybe<T>
    jsonStringToObject(const std::string &input) const
    {
        std::stringstream string_stream;
        string_stream << input;
        return jsonStringToObject<T>(string_stream);
    }

    template<class T>
    Maybe<T>
    jsonStringToObject(std::stringstream &string_stream) const
    {
        try {
            cereal::JSONInputArchive archive_in(string_stream);
            T object;
            object.serialize(archive_in);
            return object;
        } catch (cereal::Exception &e) {
            return genError(e.what());
        }
    }

    template<class T>
    bool
    objectToJsonFile(T &obj, const std::string &file_path) const
    {
        try {
            std::ofstream ostream(file_path);
            cereal::JSONOutputArchive archive_out(ostream);
            obj.serialize(archive_out);
        } catch (cereal::Exception &e) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to write object to JSON file. Object: " << typeid(T).name()
                    << ", file : "<< file_path << ", error: " << e.what();
            return false;
        }
        return true;
    }

    template<class T>
    Maybe<std::string>
    objectToJson(const T &obj) const
    {
        std::stringstream sstream;
        try {
            cereal::JSONOutputArchive archive_out(sstream);
            obj.serialize(archive_out);
        } catch (cereal::Exception &e) {
            std::string error_msg = "Failed to write object to JSON. Object: " + std::string(typeid(T).name())
                + ", error: " + e.what();
            return genError(error_msg);
        }
        return sstream.str();
    }

    virtual bool packagesToJsonFile(const std::map<packageName, Package> &packages, const std::string &path) const = 0;
    virtual Maybe<std::map<packageName, Package>> loadPackagesFromJson(const std::string &path) const = 0;

    virtual Maybe<std::map<packageName, packageDetails>> jsonObjectSplitter(
        const std::string &json,
        const std::string &tenant_id = "",
        const std::string &profile_id = "") const = 0;

    virtual bool isNonEmptyFile(const std::string &path) const = 0;
    virtual std::shared_ptr<std::ifstream> fileStreamWrapper(const std::string &path) const = 0;
    virtual Maybe<std::string> readFile(const std::string &path) const = 0;
    virtual bool writeFile(const std::string &text, const std::string &path, bool append_mode = false) const = 0;
    virtual bool removeFile(const std::string &path) const = 0;
    virtual bool removeDirectory(const std::string &path, bool delete_content) const = 0;
    virtual void deleteVirtualTenantProfileFiles(
        const std::string &tenant_id,
        const std::string &profile_id,
        const std::string &conf_path) const = 0;
    virtual bool copyFile(const std::string &src_path, const std::string &dst_path) const = 0;
    virtual bool doesFileExist(const std::string &file_path) const = 0;
    virtual void getClusterId() const = 0;
    virtual void fillKeyInJson(
        const std::string &filename,
        const std::string &_key,
        const std::string &_val) const = 0;
    virtual bool createDirectory(const std::string &directory_path) const = 0;
    virtual bool doesDirectoryExist(const std::string &dir_path) const = 0;
    virtual bool executeCmd(const std::string &cmd) const = 0;
    virtual void loadTenantsFromDir(const std::string &dir_path) const = 0;

    virtual std::string base64Encode(const std::string &input) const = 0;
    virtual std::string base64Decode(const std::string &input) const = 0;

    virtual Maybe<std::string> calculateChecksum(
        Package::ChecksumTypes checksum_type,
        const std::string &path) const = 0;
};

#endif // __I_ORCHESTRATION_TOOLS_H__

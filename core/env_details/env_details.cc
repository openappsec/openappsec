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

#include "env_details.h"

#include "config.h"
#include "debug.h"

#include <sys/stat.h>

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

static const string k8s_service_account = "/var/run/secrets/kubernetes.io/serviceaccount";

static bool
checkExistence(const string &path, bool is_dir)
{
    try {
        struct stat info;
        if (stat(path.c_str(), &info) != 0) return false;
        int flag = is_dir ? S_IFDIR : S_IFREG;
        return info.st_mode & flag;
    } catch (exception &e) {
        return false;
    }
}

// LCOV_EXCL_START Reason: can't use on the pipline environment
EnvDetails::EnvDetails() : Component("EnvDetails")
{
    if (doesFileExist("/.dockerenv")) env_type = EnvType::DOCKER;
    token = retrieveToken();
    agent_namespace = retrieveNamespace();
    if (!token.empty()) {
        auto env_res = getenv("deployment_type");
        env_type = env_res != nullptr && env_res == string("non_crd_k8s") ? EnvType::NON_CRD_K8S : EnvType::K8S;
    }
}

EnvType
EnvDetails::getEnvType()
{
    return env_type;
}

string
EnvDetails::getToken()
{
    return token;
}

string
EnvDetails::getNameSpace()
{
    return agent_namespace;
}

string
EnvDetails::retrieveToken()
{
    return readFileContent(k8s_service_account + "/token");
}

string
EnvDetails::retrieveNamespace()
{
    return readFileContent(k8s_service_account + "/namespace");
}

string
EnvDetails::readFileContent(const string &file_path)
{
    try {
        ifstream file(file_path);
        stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    } catch (ifstream::failure &f) {
        dbgWarning(D_LOCAL_POLICY)
            << "Cannot read the file"
            << " File: " << file_path
            << " Error: " << f.what();
        return "";
    }
}

bool
EnvDetails::doesFileExist(const string &file_path) const
{
    return checkExistence(file_path, false);
}

// LCOV_EXCL_STOP

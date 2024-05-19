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
#include "orchestration_tools.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

static const string k8s_service_account = "/var/run/secrets/kubernetes.io/serviceaccount";
// LCOV_EXCL_START Reason: can't use on the pipline environment
EnvDetails::EnvDetails() : env_type(EnvType::LINUX)
{
    auto tools = Singleton::Consume<I_OrchestrationTools>::from<OrchestrationTools>();
    if (tools->doesFileExist("/.dockerenv")) env_type = EnvType::DOCKER;
    token = retrieveToken();
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
EnvDetails::retrieveToken()
{
    return readFileContent(k8s_service_account + "/token");
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

// LCOV_EXCL_STOP

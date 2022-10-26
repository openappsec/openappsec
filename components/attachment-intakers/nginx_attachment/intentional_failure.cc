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

#include "intentional_failure.h"

#include <string>

#include <unistd.h>
#include "config.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_ATTACHMENT);

IntentionalFailureHandler::FailureType
getFailureTypeFromString(const string &failure)
{
    if (failure == "create socket") return IntentionalFailureHandler::FailureType::CreateSocket;
    if (failure == "accept socket") return IntentionalFailureHandler::FailureType::AcceptSocket;
    if (failure == "initialize connection channel")
        return IntentionalFailureHandler::FailureType::InitializeConnectionChannel;
    if (failure == "write to socket") return IntentionalFailureHandler::FailureType::WriteDataToSocket;
    if (failure == "read from socket") return IntentionalFailureHandler::FailureType::ReceiveDataFromSocket;
    if (failure == "parse response") return IntentionalFailureHandler::FailureType::ParsingResponse;
    if (failure == "get data from attachment") return IntentionalFailureHandler::FailureType::GetDataFromAttchment;
    if (failure == "register attachment") return IntentionalFailureHandler::FailureType::RegisterAttchment;
    if (failure == "get instance id") return IntentionalFailureHandler::FailureType::GetInstanceID;
    
    if (failure != "") {
        dbgInfo(D_NGINX_ATTACHMENT) << "Ignoring unknown intentional failure type:" << failure;
    }
    return IntentionalFailureHandler::FailureType::None;
}

void
IntentionalFailureHandler::RegisterIntentionalFailure()
{
    is_failure_enabled = getConfigurationWithDefault<bool>(
        false, "HTTP manager", "Enable intentional failure mode"
    );
    
    string failure_type_str = getConfigurationWithDefault<string>("", "HTTP manager", "Intentional failure type");
    failure_type = getFailureTypeFromString(failure_type_str);
    if (failure_type == FailureType::None) is_failure_enabled = false;
    
    allow_count = getConfigurationWithDefault<int>(0, "HTTP manager", "Intentional failure allow times");
    fail_count = getConfigurationWithDefault<int>(-1, "HTTP manager", "Intentional failure limit");
    is_limited = fail_count > 0;
    
    is_delay_enabled = getConfigurationWithDefault<bool>(
        false, "HTTP manager", "Enable intentional delay mode"
    );

    string delay_failure_type_str = getConfigurationWithDefault<string>(
        "", "HTTP manager", "Intentional delay failure type"
    );
    delay_failure_type = getFailureTypeFromString(delay_failure_type_str);

    delay_amount = chrono::microseconds(
        getConfigurationWithDefault<int>(-1, "HTTP manager", "Intentional delay amount")
    );
    
    if (delay_failure_type == FailureType::None || delay_amount <= chrono::microseconds(0)) is_delay_enabled = false;

    if (is_failure_enabled) {
        dbgInfo(D_NGINX_ATTACHMENT) << "Registered Intentional failure. Type: " << failure_type_str
            << ", will allow first " << to_string(allow_count) << " actions"
            << ", fail limit: " << (is_limited ? to_string(fail_count) : "unlimited");
    }

    if (is_delay_enabled) {
        dbgInfo(D_NGINX_ATTACHMENT) << "Registered Intentional delay. Type: " << delay_failure_type_str
            << ", amount: " << delay_amount.count() << " microseconds";
    }

}

void
IntentionalFailureHandler::init()
{
    RegisterIntentionalFailure();
    registerConfigLoadCb([this]() { RegisterIntentionalFailure(); });
    if (!is_failure_enabled && !is_delay_enabled) {
        dbgInfo(D_NGINX_ATTACHMENT) << "Initialized Intentional failure. No failure/delay was specified";
    }
}

bool
IntentionalFailureHandler::shouldFail(
    bool was_originaly_successful,
    IntentionalFailureHandler::FailureType failure,
    bool *failed_on_purpose
)
{
    *failed_on_purpose = false;
    if (is_failure_enabled && failure_type == failure) {
        if (allow_count > 0) {
            allow_count --;
            dbgInfo(D_NGINX_ATTACHMENT) << "Intentional failure: allowed action, remaining tries to be allowed: "
                << to_string(allow_count);
            return !was_originaly_successful;
        }
        if (is_limited) {
            if (fail_count <= 0) return !was_originaly_successful;
            fail_count --;
        }
        dbgInfo(D_NGINX_ATTACHMENT) << "Intentional failure was activated, remaining failures: "
            << (is_limited ? to_string(fail_count) : "unlimited");
        *failed_on_purpose = true;
        return true;
    }
    return !was_originaly_successful;
}

void
IntentionalFailureHandler::delayIfNeeded(IntentionalFailureHandler::FailureType failure)
{
    if (is_delay_enabled && delay_failure_type == failure) {
        dbgInfo(D_NGINX_ATTACHMENT) << "Intentional delay was activated (" << delay_amount.count() << " microseconds)";
        usleep(delay_amount.count());
    }
}

void
IntentionalFailureHandler::preload()
{
    registerExpectedConfiguration<bool>("HTTP manager", "Enable intentional failure mode");
    registerExpectedConfiguration<string>("HTTP manager", "Intentional failure type");
    registerExpectedConfiguration<int>("HTTP manager", "Intentional failure limit");
    registerExpectedConfiguration<int>("HTTP manager", "Intentional failure allow times");
    registerExpectedConfiguration<bool>("HTTP manager", "Enable intentional delay mode");
    registerExpectedConfiguration<string>("HTTP manager", "Intentional delay failure type");
    registerExpectedConfiguration<int>("HTTP manager", "Intentional delay amount");
}

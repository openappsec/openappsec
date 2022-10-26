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

#ifndef __INTENTIONAL_FAILURE__
#define __INTENTIONAL_FAILURE__

#include <chrono>

class IntentionalFailureHandler
{
public:
    enum class FailureType {
        None,
        CreateSocket,
        AcceptSocket,
        InitializeConnectionChannel,
        WriteDataToSocket,
        ReceiveDataFromSocket,
        ParsingResponse,
        GetDataFromAttchment,
        RegisterAttchment,
        GetInstanceID,
        COUNT
    };

    void init();
    bool shouldFail(bool was_originaly_successful, FailureType failure, bool *failed_on_purpose);
    void delayIfNeeded(FailureType failure);
    
    void preload();

private:
    void RegisterIntentionalFailure();

    FailureType failure_type;
    bool is_failure_enabled;
    bool is_limited;
    int fail_count;
    int allow_count;

    FailureType delay_failure_type;
    bool is_delay_enabled;
    std::chrono::microseconds delay_amount;
};

#endif // __INTENTIONAL_FAILURE__

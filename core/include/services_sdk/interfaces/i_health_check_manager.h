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

#ifndef __I_HEALTH_CHECK_MANAGER__
#define __I_HEALTH_CHECK_MANAGER__

#include <fstream>

#include "health_check_status/health_check_status.h"

class I_Health_Check_Manager
{
public:
    virtual HealthCheckStatus getAggregatedStatus() = 0;
    virtual void printRepliesHealthStatus(std::ofstream &output_file) = 0;

protected:
    ~I_Health_Check_Manager() {}
};

#endif //__I_HEALTH_CHECK_MANAGER__

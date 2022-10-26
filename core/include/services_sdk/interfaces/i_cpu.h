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

#ifndef __I_CPU_H__
#define __I_CPU_H__

#include "enum_array.h"

class I_CPU
{
public:
    enum CPUGeneralDataEntryType {
        USER,
        NICE,
        SYS,
        IDLE,
        IOWAIT,
        IRQ,
        SOFTIRQ,
        STEAL,
        GUEST,
        GUEST_NICE,

        COUNT
    };

    virtual double getCurrentProcessCPUUsage() = 0;
    virtual Maybe<double> getCurrentGeneralCPUUsage() = 0;
};

#endif // __I_CPU_H__

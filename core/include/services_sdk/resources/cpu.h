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

#ifndef __CPU_H__
#define __CPU_H__

#include <sys/time.h>

#include "i_mainloop.h"
#include "i_time_get.h"
#include "i_environment.h"
#include "i_cpu.h"
#include "i_failopen.h"
#include "cpu/failopen_mode_status.h"
#include "cpu/cpu_metric.h"
#include "enum_array.h"
#include "maybe_res.h"
#include "component.h"

using cpu_data_array = EnumArray<I_CPU::CPUGeneralDataEntryType, double>;

class CPUCalculator
        :
    public Component,
    Singleton::Provide<I_CPU>::SelfInterface,
    Singleton::Consume<I_TimeGet>
{
public:
    CPUCalculator();

    void init();
    void fini();

    double getCurrentProcessCPUUsage();
    Maybe<double> getCurrentGeneralCPUUsage();

private:
    std::chrono::microseconds
    calcTimeDiff(const timeval &current_cpu_time, const timeval &last_cpu_time) const;

    Maybe<cpu_data_array> getGeneralCPUData();
    double GetGeneralCPUActiveTime(const cpu_data_array &cpu_data);

    I_TimeGet *i_time_get;
    std::chrono::microseconds last_cpu_process_time;
    timeval last_cpu_usage_time_in_user_mod;
    timeval last_cpu_usage_time_in_kernel;

    std::chrono::microseconds last_cpu_general_time;
    double last_cpu_general_time_active;
};

class CPUManager
        :
    public Component,
    Singleton::Provide<I_Failopen>::SelfInterface,
    Singleton::Consume<I_CPU>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Environment>
{
public:
    CPUManager() : Component("CPUManager"), cpu_process_metric(false), cpu_general_metric(true) {}
    void init();
    bool isFailOpenMode() const;
    void preload();

private:
    void checkCPUStatus();
    void loadCPUConfig();
    bool isCPUAboveHighWatermark(double current_cpu) const;
    bool isCPUUnderHighWatermark(double current_cpu) const;
    bool isCPUUnderLowWatermark(double current_cpu) const;

    I_MainLoop *i_mainloop;
    I_TimeGet *i_time_get;
    I_CPU *i_cpu;
    I_Environment *i_env;
    FailopenModeEvent failopen_mode_event;

    int failopen_counter;
    int current_counter;
    bool is_failopen_mode;

    uint high_watermark;
    uint low_watermark;
    std::chrono::seconds watermark_period;
    std::chrono::seconds sampling_interval;
    std::chrono::seconds debug_period;

    std::chrono::seconds metric_report_interval;
    CPUMetric cpu_process_metric;
    CPUMetric cpu_general_metric;
};

#endif // __CPU_H__

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

#include "cpu.h"

#include <sys/resource.h>
#include <fstream>
#include <sstream>

#include "debug.h"
#include "log_generator.h"

using namespace std;

USE_DEBUG_FLAG(D_MONITORING);

static const int micro_seconds_in_second = 1000000;

CPUCalculator::CPUCalculator() : Component("CPUCalculator")
{
    last_cpu_process_time = chrono::microseconds(0);
    last_cpu_general_time = chrono::microseconds(0);
    last_cpu_general_time_active = 0;
    i_time_get = nullptr;
}

void CPUCalculator::init() { i_time_get = Singleton::Consume<I_TimeGet>::by<CPUCalculator>(); }

void CPUCalculator::fini() { i_time_get = nullptr; }

// LCOV_EXCL_START Reason: Compilation server dependency
double
CPUCalculator::GetGeneralCPUActiveTime(const cpu_data_array &cpu_data)
{
    double current_time_active =
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::USER] +
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::NICE] +
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::SYS] +
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::IRQ] +
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::SOFTIRQ] +
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::STEAL] +
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::GUEST] +
        cpu_data[CPUCalculator::CPUGeneralDataEntryType::GUEST_NICE];

    return (current_time_active - last_cpu_general_time_active);
}

Maybe<cpu_data_array>
CPUCalculator::getGeneralCPUData()
{
    static const string cpu_data_file = "/proc/stat";
    ifstream fileStat(cpu_data_file);
    string line;

    static const int max_lines_nead_to_read = 9;
    int lines_count = 0;
    while (lines_count < max_lines_nead_to_read && getline(fileStat, line))
    {
        lines_count++;
        static const string cpu_str = "cpu";
        if (line.compare(0, cpu_str.size(), cpu_str)) continue;
        istringstream iss(line);
        string ignore;
        iss >> ignore;
        cpu_data_array tmp_cpu_data;
        for (CPUGeneralDataEntryType cpu_type : NGEN::Range<CPUGeneralDataEntryType>() ) {
            string entry;
            iss >> entry;
            tmp_cpu_data[cpu_type] = atof(entry.c_str());
        }
        return tmp_cpu_data;
    }

    return genError("Could not fill general cpu data array.");
}

Maybe<double>
CPUCalculator::getCurrentGeneralCPUUsage()
{
    Maybe<cpu_data_array> current_cpu_data = getGeneralCPUData();

    if (!current_cpu_data.ok()) return genError(current_cpu_data.getErr());

    if (last_cpu_general_time == chrono::microseconds(0)) {
        last_cpu_general_time = i_time_get->getMonotonicTime();
        last_cpu_general_time_active = GetGeneralCPUActiveTime(current_cpu_data.unpack());
        return 0;
    }

    auto current_time = i_time_get->getMonotonicTime();
    auto elapsed_time = current_time - last_cpu_general_time;

    double cpu_usage_active_time = GetGeneralCPUActiveTime(current_cpu_data.unpack());
    double elapsed_time_count = static_cast<double>(elapsed_time.count());
    double general_cpu_perc = cpu_usage_active_time/elapsed_time_count;

    last_cpu_general_time = current_time;
    last_cpu_general_time_active += cpu_usage_active_time;

    return general_cpu_perc * 100;
}

double
CPUCalculator::getCurrentProcessCPUUsage()
{
    struct rusage usage;
    if (last_cpu_process_time == chrono::microseconds(0)) {
        last_cpu_process_time = i_time_get->getMonotonicTime();
        getrusage (RUSAGE_SELF, &usage);
        last_cpu_usage_time_in_user_mod = usage.ru_utime;
        last_cpu_usage_time_in_kernel = usage.ru_stime;
        return 0;
    }
    auto current_time = i_time_get->getMonotonicTime();
    auto elapsed_time = current_time - last_cpu_process_time;

    getrusage(RUSAGE_SELF, &usage);
    chrono::microseconds cpu_usage_time_in_user_mod = calcTimeDiff(usage.ru_utime, last_cpu_usage_time_in_user_mod);
    chrono::microseconds cpu_usage_time_in_kernel = calcTimeDiff(usage.ru_stime, last_cpu_usage_time_in_kernel);

    double general_cpu_time =
        static_cast<double>(cpu_usage_time_in_kernel.count() + cpu_usage_time_in_user_mod.count());
    double elapsed_time_count = static_cast<double>(elapsed_time.count());
    double general_cpu_perc = general_cpu_time/elapsed_time_count;

    last_cpu_process_time = current_time;
    last_cpu_usage_time_in_user_mod = usage.ru_utime;
    last_cpu_usage_time_in_kernel = usage.ru_stime;

    return general_cpu_perc * 100;
}

chrono::microseconds
CPUCalculator::calcTimeDiff(const timeval &current_cpu_time, const timeval &last_cpu_time) const
{
    auto diff_in_usec = current_cpu_time.tv_usec - last_cpu_time.tv_usec;
    auto diff_in_sec = current_cpu_time.tv_sec - last_cpu_time.tv_sec;
    if (diff_in_usec < 0) {
        diff_in_usec += micro_seconds_in_second;
        diff_in_sec -= 1;
    }

    return static_cast<chrono::microseconds>(diff_in_sec * micro_seconds_in_second + diff_in_usec);
}
// LCOV_EXCL_STOP

void
CPUManager::loadCPUConfig()
{
    high_watermark = getConfigurationWithDefault<uint>(85, "CPU", "high watermark");
    low_watermark = getConfigurationWithDefault<uint>(60, "CPU", "low watermark");
    watermark_period = chrono::seconds(getConfigurationWithDefault<uint>(30, "CPU", "watermark period"));
    sampling_interval = chrono::seconds(getConfigurationWithDefault<uint>(5, "CPU", "sampling interval"));
    debug_period = chrono::seconds(getConfigurationWithDefault<uint>(30, "CPU", "debug period"));
    metric_report_interval = chrono::seconds(
        getConfigurationWithDefault<uint>(600, "CPU", "metric reporting interval")
    );
    failopen_counter = watermark_period/sampling_interval;
}

void
CPUManager::init()
{
    loadCPUConfig();

    i_mainloop = Singleton::Consume<I_MainLoop>::by<CPUManager>();
    i_time_get = Singleton::Consume<I_TimeGet>::by<CPUManager>();
    i_cpu = Singleton::Consume<I_CPU>::by<CPUManager>();
    i_env = Singleton::Consume<I_Environment>::by<CPUManager>();

    current_counter = 0;
    is_failopen_mode = false;
    i_env->registerValue("Failopen Status", is_failopen_mode);

    cpu_process_metric.init(
        "CPU process usage",
        ReportIS::AudienceTeam::AGENT_CORE,
        ReportIS::IssuingEngine::AGENT_CORE,
        metric_report_interval,
        true
    );
    cpu_process_metric.registerListener();

    if (Singleton::exists<I_Environment>()) {
        auto name = Singleton::Consume<I_Environment>::by<CPUManager>()->get<string>("Service Name");
        string orch_service_name = getConfigurationWithDefault<string>(
            "Orchestration",
            "orchestration",
            "Service name"
        );
        if (name.ok() && *name == orch_service_name) {
            cpu_general_metric.init(
                "CPU general usage",
                ReportIS::AudienceTeam::AGENT_CORE,
                ReportIS::IssuingEngine::AGENT_CORE,
                metric_report_interval,
                false
            );
            cpu_general_metric.registerContext<string>("Service Name", "all");
            cpu_general_metric.registerListener();
        }
    }

    i_mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Timer,
        [this]() { checkCPUStatus(); },
        "CPU manager status check",
        false
    );
}

bool
CPUManager::isFailOpenMode() const
{
    return is_failopen_mode;
}

void
CPUManager::preload()
{
    registerExpectedConfiguration<uint>("CPU", "high watermark");
    registerExpectedConfiguration<uint>("CPU", "low watermark");
    registerExpectedConfiguration<uint>("CPU", "watermark period");
    registerExpectedConfiguration<uint>("CPU", "sampling interval");
    registerExpectedConfiguration<uint>("CPU", "metric reporting interval");
    registerExpectedConfiguration<uint>("CPU", "debug period");
    registerExpectedConfiguration<string>("orchestration", "Service name");
}

bool
CPUManager::isCPUAboveHighWatermark(double current_cpu) const
{
    return
        current_cpu > high_watermark &&
        current_counter >= 0 &&
        current_counter < failopen_counter;
}

bool
CPUManager::isCPUUnderHighWatermark(double current_cpu) const
{
    return
        current_cpu < high_watermark &&
        current_counter > 0 &&
        !is_failopen_mode;
}

bool
CPUManager::isCPUUnderLowWatermark(double current_cpu) const
{
    return current_cpu <= low_watermark && is_failopen_mode;
}

void
CPUManager::checkCPUStatus()
{
    while (true) {
        loadCPUConfig();

        auto is_orchestrator = Singleton::Consume<I_Environment>::by<CPUManager>()->get<bool>("Is Orchestrator");
        if (is_orchestrator.ok() && is_orchestrator.unpack()) {
            Maybe<double> current_general_cpu = i_cpu->getCurrentGeneralCPUUsage();
            if (!current_general_cpu.ok()) {
                dbgWarning(D_MONITORING) << current_general_cpu.getErr();
            } else {
                CPUEvent(current_general_cpu.unpack(), true).notify();
            }
        }

        auto current_process_cpu = i_cpu->getCurrentProcessCPUUsage();
        dbgTrace(D_MONITORING) << "Current process CPU usage: " << current_process_cpu;
        CPUEvent(current_process_cpu, false).notify();

        if (isCPUAboveHighWatermark(current_process_cpu)) {
            current_counter++;
        } else {
            if (isCPUUnderHighWatermark(current_process_cpu)) {
                current_counter=0;
            } else {
                if (isCPUUnderLowWatermark(current_process_cpu)) {
                    current_counter--;
                }
            }
        }

        if (current_counter == failopen_counter && !is_failopen_mode) {
            is_failopen_mode = true;
            i_env->registerValue("Failopen Status", is_failopen_mode);
            failopen_mode_event.setFailopenMode(is_failopen_mode);
            failopen_mode_event.notify();

            dbgInfo(D_MONITORING) << "Failopen mode is ON, CPU usage is above "
                << high_watermark
                << "% for "
                << watermark_period.count()
                << " seconds";

            if (debug_period == chrono::seconds::zero()) {
                dbgInfo(D_MONITORING) << "Debug period for Failopen mode is zero seconds";
            } else {
                Debug::failOpenDebugMode(debug_period);
            }
        }

        if (current_counter == 0 && is_failopen_mode) {
            is_failopen_mode = false;
            i_env->registerValue("Failopen Status", is_failopen_mode);
            failopen_mode_event.setFailopenMode(is_failopen_mode);
            failopen_mode_event.notify();

            dbgInfo(D_MONITORING) << "Failopen mode is OFF, CPU usage is below "
                << low_watermark
                << "% for "
                << watermark_period.count()
                << " seconds";
        }

        i_mainloop->yield(sampling_interval);
    }
}

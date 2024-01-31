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

#include "memory_consumption.h"
#include "memory_metric.h"
#include <unistd.h>

using namespace std;

USE_DEBUG_FLAG(D_MONITORING);

class MemoryCalculator::Impl
{
public:
    void
    init()
    {
        I_MainLoop *i_mainloop = Singleton::Consume<I_MainLoop>::by<MemoryCalculator>();

        memory_metric.init(
            "Memory usage",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            chrono::seconds(600),
            true
        );
        memory_metric.registerListener();

        i_mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::Timer,
            chrono::seconds(60),
            [this] () { getCurrentMemoryUsage(); },
            "Memory consumption getter",
            false
        );

        memory_values.insert(make_pair(virtual_process_memory_key, 0));
        memory_values.insert(make_pair(rss_process_key, 0));
        memory_values.insert(make_pair(general_total_memory_key, 0));
    }

    void
    getCurrentMemoryUsage()
    {
        getCurrentProcessMemoryUsage();
        if (Singleton::exists<I_Environment>()) {
            auto name = Singleton::Consume<I_Environment>::by<MemoryCalculator>()->get<string>("Service Name");
            string orch_service_name = getConfigurationWithDefault<string>(
                "Orchestration",
                "orchestration",
                "Service name"
            );
            if (name.ok() && *name == orch_service_name) {
                getCurrentGeneralTotalMemoryUsage();
            } else {
                memory_values[general_total_memory_key] = 0;
            }
        } else {
            memory_values[general_total_memory_key] = 0;
        }

        memory_event.setMemoryValues(memory_values);
        memory_event.notify();
    }

private:
    void
    getCurrentProcessMemoryUsage()
    {
        unsigned long vsize;
        long rss;
        {
            string ignore;
            ifstream ifs("/proc/self/stat", ios_base::in);
            for (uint ignored_stat_data = 0; ignored_stat_data < 22; ignored_stat_data++) {
                ifs >> ignore;
            }
            ifs >> vsize >> rss;
        }

        long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024;
        memory_values[virtual_process_memory_key] = vsize / 1024;
        memory_values[rss_process_key] = rss * page_size_kb;
    }

    void
    getCurrentGeneralTotalMemoryUsage()
    {
        static const string general_total_mem_file = "/proc/meminfo";
        ifstream ifs(general_total_mem_file, ios_base::in);
        double mem_general_total = 0;
        double mem_free = 0;
        string word, value, ignore;

        static const int max_words_to_read = 150;
        int words_count = 0;
        while (words_count < max_words_to_read && ifs >> word) {
            words_count++;
            if (word != "") {
                //Reduce last letter which is ':' in order to get clean memory string.
                word = word.substr(0, word.size()-1);
            }
            static const string mem_general_total_str = "MemTotal";
            static const set<string> mem_free_strings = { "MemFree", "Buffers", "Cached" };
            if (word == mem_general_total_str) {
                ifs >> value;
                mem_general_total = atof(value.c_str());
            } else if (mem_free_strings.find(word) != mem_free_strings.end()) {
                ifs >> value;
                mem_free += atof(word.c_str());
            } else {
                ifs >> ignore;
            }
            ifs >> ignore;
        }

        dbgTrace(D_MONITORING) << "General total value of memory in use: " << mem_general_total;
        dbgTrace(D_MONITORING) << "General total value of free memory: " << mem_free;
        memory_values[general_total_memory_key] = (mem_general_total - mem_free);
    }

    map<string, double> memory_values;
    MemoryConsumptionEvent memory_event;
    MemoryMetric memory_metric;
};

MemoryCalculator::MemoryCalculator() : Component("MemoryCalculator"), pimpl(make_unique<Impl>()) {}

MemoryCalculator::~MemoryCalculator() {}

void
MemoryCalculator::preload()
{
    registerExpectedConfiguration<string>("orchestration", "Service name");
}

void MemoryCalculator::init() { pimpl->init(); }

void
MemoryMetric::upon(const MemoryConsumptionEvent &event)
{
    virtual_process_memory_max.report(event.getMemoryValue(memory_type_metric::VM_PROC_MAX));
    virtual_process_memory_min.report(event.getMemoryValue(memory_type_metric::VM_PROC_MIN));
    virtual_process_memory_average.report(event.getMemoryValue(memory_type_metric::VM_PROC_AVERAGE));

    rss_process_max.report(event.getMemoryValue(memory_type_metric::RSS_PROC_MAX));
    rss_process_min.report(event.getMemoryValue(memory_type_metric::RSS_PROC_MIN));
    rss_process_average.report(event.getMemoryValue(memory_type_metric::RSS_PROC_AVERAGE));

    general_total_memory_max.report(event.getMemoryValue(memory_type_metric::GENERAL_TOTAL_MAX));
    general_total_memory_min.report(event.getMemoryValue(memory_type_metric::GENERAL_TOTAL_MIN));
    general_total_memory_average.report(event.getMemoryValue(memory_type_metric::GENERAL_TOTAL_AVERAGE));
}

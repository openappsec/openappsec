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

#include "time_proxy.h"
#include <chrono>
#include <string>
#include <time.h>
#include <sstream>
#include "debug.h"

#include "singleton.h"
#include "i_time_get.h"
#include "i_time_set.h"

using namespace std;
using std::chrono::microseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;
using std::chrono::system_clock;
using std::chrono::time_point;
using std::chrono::duration_cast;

static const int no_of_ticks_in_a_second = 1000000;
static const int no_of_digits_after_the_dot_precision = 6;

class TimeProxyComponent::Impl
        :
    Singleton::Provide<I_TimeGet>::From<TimeProxyComponent>,
    Singleton::Provide<I_TimeSet>::From<TimeProxyComponent>
{
public:
    //    Monotonic Time API
    microseconds
    getMonotonicTime() override
    {
        if (is_monotomic_set) return monotonic_now;

        return duration_cast<microseconds>(steady_clock::now() - monotonic_start);
    }

    void
    setMonotonicTime(microseconds new_time) override
    {
        if (is_monotomic_set) {
            dbgAssert((new_time+monotonic_delta) >= monotonic_now) << "Monotonic time must not go back!";
        } else {
            // The first time that the monotonic time is been set, we take the current value to be the base line.
            // This is in order to avoid the clock going backwards.
            // So we calulate the delta from the current time to the vale we were given, and later on add it to
            // any we get. That delta assures that setMonotonicTime can be used without concern as to what was the
            // exact time when we started setting it.
            auto curr = duration_cast<microseconds>(steady_clock::now() - monotonic_start);
            monotonic_delta = curr - new_time;
            is_monotomic_set = true;
        }

        monotonic_now = new_time + monotonic_delta;
    }

    //    Wall Time API
    microseconds
    getWalltime() override
    {
        if (is_walltime_set) return walltime_now;

        return duration_cast<microseconds>(system_clock::now().time_since_epoch());
    }

    void
    setWalltime(microseconds new_time)
    {
        walltime_now = new_time;
        is_walltime_set = true;
    }

    std::string getWalltimeStr() override { return getWalltimeStr(getWalltime()); }

    std::string
    getWalltimeStr(const microseconds &time_to_convert)
    {
        time_t ttime = duration_cast<seconds>(time_to_convert).count();
        struct tm *gm_time = gmtime(&ttime);
        return parseTime(time_to_convert, gm_time);
    }

    std::string
    getLocalTimeStr()
    {
        microseconds time_in_microseconds = getWalltime();
        time_t ttime = duration_cast<seconds>(time_in_microseconds).count();
        struct tm *local_time = localtime(&ttime);
        return parseTime(time_in_microseconds, local_time);
    }

private:
    bool is_monotomic_set = false;
    bool is_walltime_set = false;
    microseconds walltime_now;
    microseconds monotonic_now;
    microseconds monotonic_delta;
    time_point<steady_clock> monotonic_start = steady_clock::now();

    std::string
    parseTime(const microseconds &time_in_microseconds, const struct tm *time_struct)
    {
        // Using ISO 8601 Format: YYYY-MM-DD'T'hh:mm:ss
        char date[24];
        size_t date_len = strftime(date, sizeof(date), "%FT%T", time_struct);
        // Adding micro seconds too
        stringstream str;
        str.width(no_of_digits_after_the_dot_precision);
        str.fill('0');
        str << (time_in_microseconds.count() % no_of_ticks_in_a_second);
        return string(date, date_len) + "." + str.str();
    }
};

TimeProxyComponent::TimeProxyComponent()
        :
    Component("TimeProxyComponent"),
    pimpl(make_unique<Impl>())
{
}

TimeProxyComponent::~TimeProxyComponent()
{
}

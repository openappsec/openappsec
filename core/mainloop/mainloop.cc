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

#include "mainloop.h"

#include <memory>
#include <system_error>
#include <map>
#include <sstream>
#include <poll.h>
#include <unistd.h>

#include "config.h"
#include "coroutine.h"
#include "singleton.h"
#include "debug.h"
#include "i_time_get.h"
#include "report/log_rest.h"
#include "mainloop/mainloop_metric.h"

using namespace std;

USE_DEBUG_FLAG(D_MAINLOOP);

bool fini_signal_flag = false;

class MainloopStop {};

class MainloopComponent::Impl : Singleton::Provide<I_MainLoop>::From<MainloopComponent>
{
    using RoutineMap = map<RoutineID, RoutineWrapper>;

public:
    void run() override;

    RoutineID
    addOneTimeRoutine(
        RoutineType priority,
        Routine func,
        const string &routine_name,
        bool is_primary
    ) override;

    RoutineID
    addRecurringRoutine(
        RoutineType priority,
        chrono::microseconds time,
        Routine func,
        const string &routine_name,
        bool is_primary
    ) override;

    RoutineID
    addFileRoutine(
        RoutineType priority,
        int fd,
        Routine func,
        const string &routine_name,
        bool is_primary
    ) override;

    bool doesRoutineExist(RoutineID id) override;

    Maybe<RoutineID> getCurrentRoutineId() const override;

    void updateCurrentStress(bool is_busy) override;

    void yield(bool force) override;
    void yield(chrono::microseconds time) override;
    void stopAll() override;
    void stop() override;
    void stop(RoutineID id) override;

    void halt() override;
    void halt(RoutineID id) override;

    void resume(RoutineID id) override;

    void
    init()
    {
        fini_signal_flag = false;
        addOneTimeRoutine(
            RoutineType::Offline,
            [this](){ reportStartupEvent(); },
            "Nano service startup report",
            false
        );

        metric_report_interval = chrono::seconds(
            getConfigurationWithDefault<uint>(600, "Mainloop", "metric reporting interval")
        );
        mainloop_metric.init(
            "Mainloop sleep time data",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            metric_report_interval,
            false
        );
        mainloop_metric.registerListener();
    }

    void
    fini()
    {
        timer = nullptr;
        fini_signal_flag = false;
    }

private:
    void reportStartupEvent();
    void stop(const RoutineMap::iterator &iter);
    uint32_t getCurrentTimeSlice(uint32_t current_stress);
    RoutineID getNextID();

    I_TimeGet *
    getTimer()
    {
        if (timer == nullptr) timer = Singleton::Consume<I_TimeGet>::by<MainloopComponent>();
        return timer;
    }

    I_TimeGet *timer = nullptr;

    RoutineMap routines;
    RoutineMap::iterator curr_iter = routines.end();
    RoutineID next_routine_id = 0;

    bool do_stop = false;
    bool is_running = false;
    chrono::microseconds stop_time;
    uint32_t current_stress = 0;

    chrono::seconds metric_report_interval;
    MainloopEvent mainloop_event;
    MainloopMetric mainloop_metric;
};

static I_MainLoop::RoutineType rounds[] = {
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::Timer,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::System,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::Timer,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::RealTime,
    I_MainLoop::RoutineType::Offline,
};

void
MainloopComponent::Impl::reportStartupEvent()
{
    chrono::microseconds curr_time = Singleton::Consume<I_TimeGet>::by<MainloopComponent>()->getWalltime();

    ReportIS::AudienceTeam audience_team = ReportIS::AudienceTeam::NONE;
    auto i_env = Singleton::Consume<I_Environment>::by<MainloopComponent>();
    auto team = i_env->get<ReportIS::AudienceTeam>("Audience Team");
    if (team.ok()) audience_team = *team;

    Report startup_message(
        "Nano service successfully started",
        curr_time,
        ReportIS::Type::EVENT,
        ReportIS::Level::LOG,
        ReportIS::LogLevel::INFO,
        ReportIS::Audience::INTERNAL,
        audience_team,
        ReportIS::Severity::INFO,
        ReportIS::Priority::HIGH,
        chrono::seconds(0),
        LogField("agentId", Singleton::Consume<I_AgentDetails>::by<MainloopComponent>()->getAgentId()),
        ReportIS::Tags::INFORMATIONAL
    );

    string fog_event_uri = getConfigurationWithDefault<string>(
        "/api/v1/agents/events",
        "Logging",
        "Fog Log URI"
    );

    LogRest startup_message_client_rest(startup_message);

    Singleton::Consume<I_Messaging>::by<MainloopComponent>()->sendObjectWithPersistence(
        startup_message_client_rest,
        I_Messaging::Method::POST,
        fog_event_uri,
        "",
        true,
        MessageTypeTag::REPORT
    );

    dbgInfo(D_MAINLOOP) << "Startup report was successfully sent to fog";
}

void
MainloopComponent::Impl::run()
{
    dbgAssert(!is_running) << "MainloopComponent::Impl::run was called while it was already running";
    is_running = true;

    bool has_primary_routines = true;
    uint round = 0;
    uint64_t sleep_count = 0;
    dbgInfo(D_MAINLOOP) << "Starting the Mainloop";
    chrono::microseconds last_iter = getTimer()->getMonotonicTime();
    const chrono::seconds one_sec(1);

    string service_name = "Unnamed Nano Service";
    auto name = Singleton::Consume<I_Environment>::by<MainloopComponent>()->get<string>("Service Name");
    if (name.ok()) service_name = *name;

    string error_prefix = "Service " + service_name + " crashed. Error details: ";
    string error;

    while (has_primary_routines) {
        mainloop_event.setStressValue(current_stress);
        int time_slice_to_use = getCurrentTimeSlice(current_stress);
        mainloop_event.setTimeSlice(time_slice_to_use);
        chrono::microseconds basic_time_slice(time_slice_to_use);
        chrono::milliseconds large_exceeding(getConfigurationWithDefault(100u, "Mainloop", "Exceed Warning"));
        auto start_time = getTimer()->getMonotonicTime();
        has_primary_routines = false;

        curr_iter = routines.begin();
        while (curr_iter != routines.end()) {
            if (fini_signal_flag) {
                break;
            }
            if (!curr_iter->second.isActive()) {
                curr_iter = routines.erase(curr_iter);
                continue;
            }

            if (curr_iter->second.isPrimary()) has_primary_routines = true;

            if (curr_iter->second.shouldRun(rounds[round])) {
                // Set the time upon which `hasAdditionalTime` will yield.
                stop_time = getTimer()->getMonotonicTime() + basic_time_slice;
                dbgTrace(D_MAINLOOP) <<
                    "Starting execution of corutine. Routine named: " <<
                    curr_iter->second.getRoutineName();

                try {
                    curr_iter->second.run();
                } catch (const exception &e) {
                    error =
                        error_prefix
                        + "Routine: '"
                        + curr_iter->second.getRoutineName()
                        + "' thrown exception: "
                        + e.what();
                } catch (...) {
                    error =
                        error_prefix
                        + "Unknown generic error exception thrown during execution of mainloop. Routine name: '"
                        + curr_iter->second.getRoutineName()
                        + "'";
                }

                if (error != "") {
                    cerr << error << endl;
                    if (Singleton::exists<I_SignalHandler>()) {
                        Singleton::Consume<I_SignalHandler>::by<MainloopComponent>()->dumpErrorReport(error);
                    }
                    fini_signal_flag = true;
                    continue;
                }

                dbgTrace(D_MAINLOOP) <<
                    "Ending execution of corutine. Routine named: " <<
                    curr_iter->second.getRoutineName();
                if (
                    getTimer()->getMonotonicTime() > stop_time + large_exceeding &&
                    curr_iter->second.getRoutineName() != "Orchestration runner"
                ) {
                    dbgWarning(D_MAINLOOP)
                        << "Routine execution exceeded run time. Routine name: "
                        << curr_iter->second.getRoutineName();
                }
            }

            curr_iter++;
        }
        round = (round + 1) % (sizeof(rounds)/sizeof(rounds[0]));

        uint64_t signed_sleep_time = 0;
        chrono::microseconds current_time = getTimer()->getMonotonicTime();
        if (start_time + basic_time_slice > current_time) {
            chrono::microseconds sleep_time = start_time + basic_time_slice - current_time;
            signed_sleep_time = sleep_time.count();
            sleep_count += signed_sleep_time;
            usleep(signed_sleep_time);
        }

        mainloop_event.setSleepTime(signed_sleep_time);
        mainloop_event.notify();

        if (start_time - last_iter > one_sec) {
            dbgTrace(D_MAINLOOP) <<
                "During the last second the process slept for " <<
                sleep_count <<
                " microseconds, stress: " <<
                current_stress <<
                ", time slice: " <<
                time_slice_to_use;
            sleep_count = 0;
            last_iter = start_time;
        }
    }

    dbgInfo(D_MAINLOOP) << "Mainloop ended - stopping all routines";
    stopAll();
    routines.clear();
}

string
getRoutineTypeString(I_MainLoop::RoutineType priority)
{
    switch (priority) {
        case I_MainLoop::RoutineType::RealTime: return "RealTime";
        case I_MainLoop::RoutineType::Timer: return "Timer";
        case I_MainLoop::RoutineType::System: return "System";
        case I_MainLoop::RoutineType::Offline: return "Offline";
    }
    return "unknown";
}

I_MainLoop::RoutineID
MainloopComponent::Impl::addOneTimeRoutine(
    RoutineType priority,
    Routine func,
    const string &_routine_name,
    bool is_primary)
{
    auto id = getNextID();

    string routine_name = _routine_name.empty() ? string("Generic routine, id: " + to_string(id)) : _routine_name;
    auto env = Singleton::Consume<I_Environment>::by<MainloopComponent>()->createEnvironment();
    Routine func_wrapper = [this, env, func, routine_name] () mutable {
        Singleton::Consume<I_Environment>::by<MainloopComponent>()->loadEnvironment(move(env));

        try {
            if (this->do_stop) return;
            func();
        } catch (MainloopStop) {
            return;
        }
    };

    routines.emplace(id, RoutineWrapper(priority, func_wrapper, is_primary, routine_name));
    dbgDebug(D_MAINLOOP)
        << "Added new routine. Name: "
        << routine_name
        << ", Priority: "
        << getRoutineTypeString(priority)
        << ", total routines: "
        << routines.size();
    return id;
}

I_MainLoop::RoutineID
MainloopComponent::Impl::addRecurringRoutine(
    RoutineType priority,
    chrono::microseconds time,
    Routine func,
    const string &routine_name,
    bool is_primary
)
{
    Routine func_wrapper = [this, time, func] () {
        while (true) {
            func();
            yield(time);
        }
    };
    return addOneTimeRoutine(priority, func_wrapper, routine_name, is_primary);
}

I_MainLoop::RoutineID
MainloopComponent::Impl::addFileRoutine(
    RoutineType priority,
    int fd,
    Routine func,
    const string &routine_name,
    bool is_primary)
{
    Routine func_wrapper = [this, fd, func, priority] () {
        while (true) {
            struct pollfd s_poll;
            s_poll.fd = fd;
            s_poll.events = POLLIN;
            s_poll.revents = 0;
            int rc = poll(&s_poll, 1, 0);
            if (rc > 0 && (s_poll.revents & POLLIN) != 0) {
                func();
                if (priority == I_MainLoop::RoutineType::RealTime) {
                    if (s_poll.revents & POLLHUP) {
                        updateCurrentStress(false);
                    } else {
                        updateCurrentStress(true);
                    }
                }
            } else {
                if (priority == I_MainLoop::RoutineType::RealTime) updateCurrentStress(false);
            }
            yield(true);
        }
    };

    return addOneTimeRoutine(priority, func_wrapper, routine_name, is_primary);
}

bool
MainloopComponent::Impl::doesRoutineExist(RoutineID id)
{
    return routines.find(id) != routines.end();
}

Maybe<I_MainLoop::RoutineID>
MainloopComponent::Impl::getCurrentRoutineId() const
{
    if (curr_iter == routines.end()) return genError("No routine currently runs");
    return curr_iter->first;
}

void
MainloopComponent::Impl::yield(bool force)
{
    dbgAssert(curr_iter != routines.end()) << "Calling 'yield' without a running current routine";
    if (do_stop) throw MainloopStop();
    if (!force && getTimer()->getMonotonicTime() < stop_time) return;

    auto env = Singleton::Consume<I_Environment>::by<MainloopComponent>()->saveEnvironment();
    curr_iter->second.yield();
    Singleton::Consume<I_Environment>::by<MainloopComponent>()->loadEnvironment(move(env));
    if (do_stop) throw MainloopStop();
}

void
MainloopComponent::Impl::yield(chrono::microseconds time)
{
    if (time == chrono::microseconds::zero()) {
        yield(true);
        return;
    }
    chrono::microseconds restart_time = getTimer()->getMonotonicTime() + time;
    while (getTimer()->getMonotonicTime() < restart_time) {
        yield(true);
    }
}

void
MainloopComponent::Impl::stopAll()
{
    for (auto iter = routines.begin(); iter != routines.end(); iter++) {
        // We can't stop the current routine from inside the loop, since this will also stop the loop and we won't
        // reach the routines that come after the current routine. So we skip the current routine and come back to
        // it (if it exists) after the end of the loop.
        if (iter != curr_iter) stop(iter);
    }
    try {
        if (curr_iter != routines.end()) stop(curr_iter);
    } catch (MainloopStop) {
    }
}

void
MainloopComponent::Impl::stop()
{
    dbgAssert(curr_iter != routines.end()) << "Attempting to stop a routine when none is running";
    stop(curr_iter);
}

void
MainloopComponent::Impl::stop(RoutineID id)
{
    auto iter = routines.find(id);
    if (iter == routines.end()) {
        dbgError(D_MAINLOOP) << "Attempting to stop the routine " << id << " that does not exist";
        return;
    }
    stop(iter);
}

void
MainloopComponent::Impl::halt()
{
    dbgAssert(curr_iter != routines.end()) << "Calling 'halt' without a running current routine";
    curr_iter->second.halt();
    yield(true);
}

void
MainloopComponent::Impl::halt(RoutineID id)
{
    auto iter = routines.find(id);
    dbgAssert(iter != routines.end()) << "No routine " << id << " to halt";
    iter->second.halt();
    if (iter == curr_iter) yield(true);
}

void
MainloopComponent::Impl::resume(RoutineID id)
{
    auto iter = routines.find(id);
    dbgAssert(iter != routines.end()) << "No routine " << id << " to resume";
    iter->second.resume();
}

void
MainloopComponent::Impl::stop(const RoutineMap::iterator &iter)
{
    if (iter == curr_iter) {
        dbgDebug(D_MAINLOOP) << "Stoping the current routine " << iter->first;
        throw MainloopStop();
    }
    if (iter->second.isActive()) {
        dbgDebug(D_MAINLOOP) << "Stoping the routine " << iter->first;
        do_stop = true;
        auto env = Singleton::Consume<I_Environment>::by<MainloopComponent>()->saveEnvironment();
        RoutineMap::iterator save_routine  = curr_iter;
        curr_iter = iter;
        // We are going to let the routine run one last time, so it can throw an exception which will cause the stack
        // to clean up nicely.
        // We swap curr_iter to in case the routine will print debug messages and we can see the real Routine id
        curr_iter->second.run();
        curr_iter = save_routine;
        Singleton::Consume<I_Environment>::by<MainloopComponent>()->loadEnvironment(move(env));
        do_stop = false;
    }
}

I_MainLoop::RoutineID
MainloopComponent::Impl::getNextID()
{
    next_routine_id++;
    while (routines.find(next_routine_id) != routines.end()) {
        next_routine_id++;
    }

    return next_routine_id;
}

void
MainloopComponent::Impl::updateCurrentStress(bool is_busy)
{
    const int stress_factor = 6; // calculated by trial and error, should be revisited
    if (is_busy) {
        if (current_stress < 95) {
            current_stress += stress_factor;
        } else {
            current_stress = 100;
        }
    } else {
        if (current_stress > 0) current_stress--;
    }
}

uint32_t
MainloopComponent::Impl::getCurrentTimeSlice(uint32_t current_stress)
{
    int idle_time_slice = getConfigurationWithDefault<int>(1000, "Mainloop", "Idle routine time slice");
    int busy_time_slice = getConfigurationWithDefault<int>(1, "Mainloop", "Busy routine time slice");
    return idle_time_slice - (((idle_time_slice - busy_time_slice) * current_stress) / 100);
}

MainloopComponent::MainloopComponent() : Component("MainloopComponent"), pimpl(make_unique<Impl>())
{
}

MainloopComponent::~MainloopComponent()
{
}

void MainloopComponent::init() { pimpl->init(); }
void MainloopComponent::fini() { pimpl->fini(); }

void
MainloopComponent::preload()
{
    registerExpectedConfiguration<int>("Mainloop", "Idle routine time slice");
    registerExpectedConfiguration<int>("Mainloop", "Busy routine time slice");
    registerExpectedConfiguration<uint>("Mainloop", "metric reporting interval");
    registerExpectedConfiguration<uint>("Mainloop", "Exceed Warning");
}

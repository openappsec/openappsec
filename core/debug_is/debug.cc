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

#include "debug_ex.h"

#include <iostream>
#include <map>
#include <array>
#include <algorithm>
#include <unistd.h>

#include "enum_array.h"
#include "i_time_get.h"
#include "i_mainloop.h"
#include "i_environment.h"
#include "config.h"
#include "i_instance_awareness.h"
#include "i_signal_handler.h"

using namespace std;

using FlagsArray = EnumArray<Debug::DebugFlags, Debug::DebugLevel>;

static constexpr Debug::DebugLevel default_level = Debug::DebugLevel::INFO;

#define DEFINE_FLAG(flag_name, parent_name) \
extern const Debug::DebugFlags flag_name = Debug::DebugFlags::flag_name;
#include "debug_flags.h"
#undef DEFINE_FLAG

static multimap<Debug::DebugFlags, Debug::DebugFlags> flags_hierarchy = {

#define DEFINE_FLAG(flag_name, parent_name) \
    { Debug::DebugFlags::parent_name, Debug::DebugFlags::flag_name },
#include "debug_flags.h"
#undef DEFINE_FLAG

};

static map<string, shared_ptr<Debug::DebugStream>> active_streams = {
    { "STDOUT", make_shared<Debug::DebugStream>(&cout) }
};

pair<Debug::DebugFlags, string>
convertFlagToSettingString(const string &flag_name, const Debug::DebugFlags &flag)
{
    static const string setting_name_prefix = "agent.debug.flag.";

    string debug_setting_name = setting_name_prefix;
    string token;
    istringstream tokenStream(flag_name);
    uint iter_num = 0;
    while (getline(tokenStream, token, '_'))
    {
        if (iter_num == 0 && token == "D") {
            iter_num++;
            continue;
        }

        transform(token.begin(), token.end(), token.begin(), [](unsigned char letter){ return tolower(letter); });
        if (iter_num > 1) token.front() = toupper(token.front());
        iter_num++;
        debug_setting_name += token;
    }
    return make_pair(flag, debug_setting_name);
}

static map<Debug::DebugFlags, string> flags_to_setting_name = {
    convertFlagToSettingString("D_ALL", Debug::DebugFlags::D_ALL),
#define DEFINE_FLAG(flag_name, parent_name) convertFlagToSettingString(#flag_name, Debug::DebugFlags::flag_name),
#include "debug_flags.h"
#undef DEFINE_FLAG
};

static map<string, shared_ptr<Debug::DebugStream>> preparing_streams;

static FlagsArray global_flags_levels(FlagsArray::Fill(), default_level);
static FlagsArray flags_levels_override(FlagsArray::Fill(), Debug::DebugLevel::NOISE);
static FlagsArray preparing_global_flags;

class DebugStreamConfiguration
{
public:
    DebugStreamConfiguration(const string &_stream_name)
            :
        stream_name(_stream_name)
    {
        if(stream_name == "FOG") {
            flag_values.fill(Debug::DebugLevel::ERROR);
        }
        else {
            flag_values.fill(default_level);
        }
    }

    DebugStreamConfiguration() : DebugStreamConfiguration("STDOUT") {}

    void
    load(cereal::JSONInputArchive &ar)
    {
        ar(cereal::make_nvp("Output", stream_name));
        if (stream_name.empty()) stream_name = "STDOUT";
        if (stream_name != "FOG" && stream_name != "STDOUT" && stream_name.front() != '/') {
            stream_name = getLogFilesPathConfig() + "/" + stream_name;
        }
#define DEFINE_FLAG(flag_name, parent_name)                                                              \
        try {                                                                                            \
            string level;                                                                                \
            ar(cereal::make_nvp(#flag_name, level));                                                     \
            assignValueToFlagRecursively(flag_values, Debug::DebugFlags::flag_name, turnToLevel(level)); \
        } catch (cereal::Exception &) {                                                                  \
            ar.setNextName(nullptr);                                                                     \
        }
DEFINE_FLAG(D_ALL, D_ALL)
#include "debug_flags.h"
#undef DEFINE_FLAG

        for (auto flag : makeRange<Debug::DebugFlags>()) {
            if (flag_values[flag] < preparing_global_flags[flag]) preparing_global_flags[flag] = flag_values[flag];
        }

        insertConfigurationToPendingMap();
    }

    static void
    assignValueToFlagRecursively(FlagsArray &flag_levels, Debug::DebugFlags flag, Debug::DebugLevel level)
    {
        flag_levels[flag] = level;
        auto sub_flags_range = flags_hierarchy.equal_range(flag);
        for (auto flag_iterator = sub_flags_range.first; flag_iterator != sub_flags_range.second; flag_iterator++) {
            assignValueToFlagRecursively(flag_levels, flag_iterator->second, level);
        }
    }

    FlagsArray flag_values;
    string stream_name;

private:
    Debug::DebugLevel
    turnToLevel(const string &level)
    {
        if (level == "Error")   return Debug::DebugLevel::ERROR;
        if (level == "Warning") return Debug::DebugLevel::WARNING;
        if (level == "Info")    return Debug::DebugLevel::INFO;
        if (level == "Debug")   return Debug::DebugLevel::DEBUG;
        if (level == "Trace")   return Debug::DebugLevel::TRACE;

        throw Config::ConfigException("Illegal debug flag level");
        return Debug::DebugLevel::NOISE;
    }

    void
    insertConfigurationToPendingMap()
    {
        if (stream_name.empty()) return;

        if (preparing_streams.count(stream_name) > 0) return;

        if (active_streams.count(stream_name) > 0) {
            preparing_streams[stream_name] = active_streams[stream_name];
            return;
        }

        if (stream_name == "STDOUT") {
            preparing_streams[stream_name] = make_shared<Debug::DebugStream>(&cout);
            return;
        }

        if (stream_name == "FOG") {
            preparing_streams[stream_name] = make_shared<DebugFogStream>();
            return;
        }

        if (!isValidFileStreamName()) throw Config::ConfigException("Illegal debug stream name: " + stream_name);

        auto inst_aware =
            Singleton::exists<I_InstanceAwareness>() ? Singleton::Consume<I_InstanceAwareness>::by<Debug>() : nullptr;
        preparing_streams[stream_name] = make_shared<DebugFileStream>(
            stream_name + (inst_aware ? inst_aware->getUniqueID("") : "")
        );
    }

    bool
    isValidFileStreamName()
    {
        string debug_file_prefix = Debug::findDebugFilePrefix(stream_name);
        if (debug_file_prefix == "") return false;

        auto file_name_begins = stream_name.begin() + debug_file_prefix.size();
        int num_forbidden_chars = count_if(
            file_name_begins,
            stream_name.end(),
            [] (unsigned char c) { return !isalnum(c) && c != '/' && c != '_' && c != '-' && c != '.'; }
        );
        if (num_forbidden_chars > 0) return false;

        return true;
    }
};

class DebugConfiguration
{
public:
    DebugConfiguration()
    {
        streams_in_context.push_back(DebugStreamConfiguration());
        streams_in_context.push_back(DebugStreamConfiguration("FOG"));
    }

    DebugConfiguration(const string &stream) : DebugConfiguration()
    {
        streams_in_context.push_back(DebugStreamConfiguration(stream));
        streams_in_context.push_back(DebugStreamConfiguration("FOG"));
    }

    vector<DebugStreamConfiguration> streams_in_context;

    void
    load(cereal::JSONInputArchive &ar)
    {
        ar(cereal::make_nvp("Streams", streams_in_context));
    }
};

static DebugConfiguration default_config;

// LCOV_EXCL_START - function is covered in unit-test, but not detected bt gcov
Debug::Debug(
    const string &file_name,
    const string &func_name,
    const uint &line)
{
    if (Singleton::exists<Config::I_Config>()) {
        do_assert = getConfigurationWithDefault<bool>(true, "Debug I/S", "Abort on assertion");
    } else {
        do_assert = true;
    }

    auto current_configuration =
        Singleton::exists<Config::I_Config>() ? getConfigurationWithDefault(default_config, "Debug") : default_config;

    for (auto &stream : current_configuration.streams_in_context) {
        addActiveStream(stream.stream_name);
    }

    for (const string &stream_name : streams_from_mgmt) {
        addActiveStream(stream_name);
    }
    startStreams(DebugLevel::ASSERTION, file_name, func_name, line);
}
// LCOV_EXCL_STOP

#define evalWithOverride(orig_cond, flag, level) (                                      \
    (debug_override_exist && flags_levels_override[flag] != Debug::DebugLevel::NOISE) ? \
    flags_levels_override[flag] <= level :                                              \
    (orig_cond)                                                                         \
)

bool
Debug::shouldApplyFailOpenOnStream(const string &name) const
{
    return name != "FOG" && is_fail_open_mode;
}

Debug::Debug(
    const string &file_name,
    const string &func_name,
    const uint &line,
    const DebugLevel &level,
    const DebugFlags &flag1)
        :
    do_assert(false)
{
    isCommunicationFlag(flag1);

    auto current_configuration =
        Singleton::exists<Config::I_Config>() ? getConfigurationWithDefault(default_config, "Debug") : default_config;
    for (auto &stream : current_configuration.streams_in_context) {
        if (shouldApplyFailOpenOnStream(stream.stream_name) ||
            evalWithOverride((stream.flag_values[flag1] <= level), flag1, level)
        ) {
            addActiveStream(stream.stream_name);
        }
    }

    for (const string &stream_name : streams_from_mgmt) {
        if (shouldApplyFailOpenOnStream(stream_name) || evalWithOverride(false, flag1, level)) {
            addActiveStream(stream_name);
        }
    }

    startStreams(level, file_name, func_name, line);
}

Debug::Debug(
    const string &file_name,
    const string &func_name,
    const uint &line,
    const DebugLevel &level,
    const DebugFlags &flag1,
    const DebugFlags &flag2)
        :
    do_assert(false)
{
    isCommunicationFlag(flag1);
    isCommunicationFlag(flag2);

    auto current_configuration =
        Singleton::exists<Config::I_Config>() ? getConfigurationWithDefault(default_config, "Debug") : default_config;

    for (auto &stream : current_configuration.streams_in_context) {
        if (shouldApplyFailOpenOnStream(stream.stream_name) ||
            evalWithOverride((stream.flag_values[flag1] <= level), flag1, level) ||
            evalWithOverride((stream.flag_values[flag2] <= level), flag2, level)
        ) {
            addActiveStream(stream.stream_name);
        }
    }

    for (const string &stream_name : streams_from_mgmt) {
        if (shouldApplyFailOpenOnStream(stream_name) ||
            evalWithOverride(false, flag1, level) ||
            evalWithOverride(false, flag2, level)
        ) {
            addActiveStream(stream_name);
        }
    }

    startStreams(level, file_name, func_name, line);
}

Debug::Debug(
    const string &file_name,
    const string &func_name,
    const uint &line,
    const DebugLevel &level,
    const DebugFlags &flag1,
    const DebugFlags &flag2,
    const DebugFlags &flag3)
        :
    do_assert(false)
{
    isCommunicationFlag(flag1);
    isCommunicationFlag(flag2);
    isCommunicationFlag(flag3);

    auto current_configuration =
        Singleton::exists<Config::I_Config>() ? getConfigurationWithDefault(default_config, "Debug") : default_config;

    for (auto &stream : current_configuration.streams_in_context) {
        if (shouldApplyFailOpenOnStream(stream.stream_name) ||
            evalWithOverride((stream.flag_values[flag1] <= level), flag1, level) ||
            evalWithOverride((stream.flag_values[flag2] <= level), flag2, level) ||
            evalWithOverride((stream.flag_values[flag3] <= level), flag3, level)
        ) {
            addActiveStream(stream.stream_name);
        }
    }

    for (const string &stream_name : streams_from_mgmt) {
        if (shouldApplyFailOpenOnStream(stream_name) ||
            evalWithOverride(false, flag1, level) ||
            evalWithOverride(false, flag2, level) ||
            evalWithOverride(false, flag3, level)
        ) {
            addActiveStream(stream_name);
        }
    }

    startStreams(level, file_name, func_name, line);
}

Debug::Debug(
    const string &file_name,
    const string &func_name,
    const uint &line,
    const DebugLevel &level,
    const DebugFlags &flag1,
    const DebugFlags &flag2,
    const DebugFlags &flag3,
    const DebugFlags &flag4)
        :
    do_assert(false)
{
    isCommunicationFlag(flag1);
    isCommunicationFlag(flag2);
    isCommunicationFlag(flag3);
    isCommunicationFlag(flag4);

    auto current_configuration =
        Singleton::exists<Config::I_Config>() ? getConfigurationWithDefault(default_config, "Debug") : default_config;

    for (auto &stream : current_configuration.streams_in_context) {
        if (shouldApplyFailOpenOnStream(stream.stream_name) ||
            evalWithOverride((stream.flag_values[flag1] <= level), flag1, level) ||
            evalWithOverride((stream.flag_values[flag2] <= level), flag2, level) ||
            evalWithOverride((stream.flag_values[flag3] <= level), flag3, level) ||
            evalWithOverride((stream.flag_values[flag4] <= level), flag4, level)
        ) {
            addActiveStream(stream.stream_name);
        }
    }

    for (const string &stream_name : streams_from_mgmt) {
        if (shouldApplyFailOpenOnStream(stream_name) ||
            evalWithOverride(false, flag1, level) ||
            evalWithOverride(false, flag2, level) ||
            evalWithOverride(false, flag3, level) ||
            evalWithOverride(false, flag4, level)
        ) {
            addActiveStream(stream_name);
        }
    }

    startStreams(level, file_name, func_name, line);
}

Debug::~Debug()
{
    if (do_assert) {
        stream << "\nPanic!";
        printBacktraceBeforeAbort();
    }

    for (auto &added_stream : current_active_streams) {
        added_stream->finishMessage();
    }

    if (do_assert) abort();

    is_debug_running = false;
}

void
Debug::preload()
{
    registerExpectedConfiguration<DebugConfiguration>("Debug");
    registerExpectedConfiguration<string>("Debug I/S", "Fog Debug URI");
    registerExpectedConfiguration<bool>("Debug I/S", "Enable bulk of debugs");
    registerExpectedConfiguration<uint>("Debug I/S", "Debug bulk size");
    registerExpectedConfiguration<uint>("Debug I/S", "Debug bulk sending interval in msec");
    registerExpectedConfiguration<uint>("Debug I/S", "Threshold debug bulk size");
    registerExpectedConfiguration<bool>("Debug I/S", "Abort on assertion");

    registerConfigPrepareCb(Debug::prepareConfig);
    registerConfigLoadCb(Debug::commitConfig);
    registerConfigAbortCb(Debug::abortConfig);

    active_streams["STDOUT"] = make_shared<Debug::DebugStream>(&cout);
    active_streams["FOG"] = make_shared<DebugFogStream>();
}

void
Debug::init()
{
    time = Singleton::Consume<I_TimeGet>::by<Debug>();
    mainloop = Singleton::Consume<I_MainLoop>::by<Debug>();
    env = Singleton::Consume<I_Environment>::by<Debug>();

    auto executable = env->get<string>("Executable Name");

    if (executable.ok() && *executable != "") {
        string default_debug_output_file_path = *executable;
        auto file_path_end = default_debug_output_file_path.find_last_of("/");
        if (file_path_end != string::npos) {
            default_debug_file_stream_path = default_debug_output_file_path.substr(file_path_end + 1);
        }
        auto file_sufix_start = default_debug_file_stream_path.find_first_of(".");
        if (file_sufix_start != string::npos) {
            default_debug_file_stream_path = default_debug_file_stream_path.substr(0, file_sufix_start);
        }

        string log_files_prefix = getLogFilesPathConfig();
        default_debug_file_stream_path = log_files_prefix + "/nano_agent/" + default_debug_file_stream_path + ".dbg";
    }
}

void
Debug::fini()
{
    time = nullptr;
    mainloop = nullptr;
    env = nullptr;
    active_streams.clear();
}

void
Debug::prepareConfig()
{
    preparing_streams.clear();
    preparing_global_flags.fill(default_level);
}

void
Debug::abortConfig()
{
    preparing_streams.clear();
}

Debug::DebugLevel
getLevelFromSettingString(const string &level)
{
    if (level == "error")   return Debug::DebugLevel::ERROR;
    if (level == "warning") return Debug::DebugLevel::WARNING;
    if (level == "info")    return Debug::DebugLevel::INFO;
    if (level == "debug")   return Debug::DebugLevel::DEBUG;
    if (level == "trace")   return Debug::DebugLevel::TRACE;

    return Debug::DebugLevel::NOISE;
}

void
Debug::applyOverrides()
{
    streams_from_mgmt.clear();
    auto fog_stream_setting_state = getProfileAgentSetting<bool>("agent.debug.stream.fog");
    if (fog_stream_setting_state.ok()) {
        if (*fog_stream_setting_state == false) {
            active_streams.erase("FOG");
        } else if (active_streams.find("FOG") == active_streams.end()) {
            active_streams["FOG"] = make_shared<DebugFogStream>();
            streams_from_mgmt.push_back("FOG");
        }
    }

    auto local_stream_setting_state = getProfileAgentSetting<bool>("agent.debug.stream.file");
    if (local_stream_setting_state.ok()) {
        if (*local_stream_setting_state == false) {
            vector<string> active_stream_keys;
            for (auto stream : active_streams) {
                if (stream.first != "FOG") active_stream_keys.push_back(stream.first);
            }
            for (auto stream : active_stream_keys) {
                active_streams.erase(stream);
            }
        } else {
            auto should_add_file_stream = true;
            for (const auto &elem : active_streams) {
                if (elem.first != "STDOUT" && elem.first != "FOG") should_add_file_stream = false;
                break;
            }

            if (should_add_file_stream) {
                if (default_debug_file_stream_path != "") {
                    streams_from_mgmt.push_back(default_debug_file_stream_path);

                    auto inst_aware = Singleton::exists<I_InstanceAwareness>() ?
                        Singleton::Consume<I_InstanceAwareness>::by<Debug>() :
                        nullptr;

                    active_streams[default_debug_file_stream_path] = make_shared<DebugFileStream>(
                        default_debug_file_stream_path + string(inst_aware ? inst_aware->getUniqueID("") : "")
                    );
                } else {
                    active_streams["STDOUT"] = make_shared<DebugStream>(&cout);
                }
            }
        }
    }

    debug_override_exist = false;
    flags_levels_override.fill(Debug::DebugLevel::NOISE);
    for (auto setting_flag : flags_to_setting_name) {
        auto override = getProfileAgentSetting<string>(setting_flag.second);
        if (!override.ok()) continue;

        Debug::DebugLevel level = getLevelFromSettingString(override.unpack());
        if (level == Debug::DebugLevel::NOISE) continue;

        debug_override_exist = true;
        DebugStreamConfiguration::assignValueToFlagRecursively(flags_levels_override, setting_flag.first, level);
    }

    if (getProfileAgentSettingWithDefault<bool>(false, "agent.debug.stream.kernel")) {
        debug_override_exist = true;
        DebugStreamConfiguration::assignValueToFlagRecursively(
            flags_levels_override,
            Debug::DebugFlags::D_MESSAGE_READER,
            Debug::DebugLevel::TRACE
        );
    }

    if (!debug_override_exist) return;
    for (const auto &level : flags_levels_override) {
        if (level < lowest_global_level && level != Debug::DebugLevel::NOISE) lowest_global_level = level;
    }
}

void
Debug::commitConfig()
{
    active_streams = move(preparing_streams);
    auto agent_mode = Singleton::Consume<I_AgentDetails>::by<Debug>()->getOrchestrationMode();
    if (
        (agent_mode == OrchestrationMode::OFFLINE || agent_mode == OrchestrationMode::HYBRID) &&
        active_streams.find("FOG") != active_streams.end()
    ) {
        active_streams.erase("FOG");
    }

    if (active_streams.size() == 0) {
        active_streams["STDOUT"] = make_shared<DebugStream>(&cout);
    }

    global_flags_levels = move(preparing_global_flags);
    lowest_global_level = global_flags_levels[Debug::DebugFlags::D_ALL];
    for (const auto &level : global_flags_levels) {
        if (level < lowest_global_level) lowest_global_level = level;
    }

    applyOverrides();
}

void
Debug::failOpenDebugMode(chrono::seconds debug_period)
{
    static int debug_routine_counter = 0;
    static FlagsArray global_flags_temp(global_flags_levels);
    static Debug::DebugLevel lowest_global_level_temp = lowest_global_level;

    if (debug_period == chrono::seconds::zero()) return;

    is_fail_open_mode = true;
    debug_routine_counter++;
    if (debug_routine_counter == 1) {
        global_flags_temp = global_flags_levels;
        lowest_global_level_temp = lowest_global_level;

        global_flags_levels.fill(DebugLevel::NOISE);
        lowest_global_level = DebugLevel::NOISE;
    }
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::System,
        [debug_period] ()
        {
            auto mainloop = Singleton::Consume<I_MainLoop>::by<Debug>();
            mainloop->yield(debug_period);
            if (debug_routine_counter == 1) {
                is_fail_open_mode = false;
                global_flags_levels = move(global_flags_temp);
                lowest_global_level = lowest_global_level_temp;
            }
            debug_routine_counter--;
        },
        "Debug fail open handler",
        false
    );
}

bool
Debug::evalFlagByFlag(Debug::DebugLevel level, Debug::DebugFlags flag)
{
    if (flags_levels_override[flag] != Debug::DebugLevel::NOISE) return flags_levels_override[flag] <= level;
    return global_flags_levels[flag] <= level;
}

void
Debug::setNewDefaultStdout(ostream *new_stream)
{
    active_streams["STDOUT"] = make_shared<Debug::DebugStream>(new_stream);

    if (active_streams.find("FOG") != active_streams.end()) {
        active_streams.erase("FOG");
    }
}

bool
Debug::isFlagAtleastLevel(Debug::DebugFlags flag, Debug::DebugLevel level)
{
    return global_flags_levels[flag] <= level;
}

void
Debug::setUnitTestFlag(Debug::DebugFlags flag, Debug::DebugLevel level)
{
    if (lowest_global_level > level) lowest_global_level = level;
    global_flags_levels[flag] = level;
    default_config.streams_in_context[0].flag_values[flag] = level;

    for (DebugStreamConfiguration stream : default_config.streams_in_context) {
        if (stream.stream_name == "FOG") {
            stream.flag_values.fill(Debug::DebugLevel::NONE);
        };
    }
}

string
Debug::findDebugFilePrefix(const string &file_name)
{
    string log_files_prefix = getLogFilesPathConfig() + "/";
    static const vector<string> allowed_debug_file_prefixes({ "/tmp/", "/var/log/", log_files_prefix });
    for (const string &single_prefix : allowed_debug_file_prefixes) {
        if (file_name.find(single_prefix) == 0) return single_prefix;
    }

    return "";
}

void
Debug::addActiveStream(const string &name)
{
    if (is_communication && name == "FOG") return;
    auto stream_entry = active_streams.find(name);
    if (stream_entry != active_streams.end()) {
        current_active_streams.insert(stream_entry->second);
    }
}

// LCOV_EXCL_START - function is covered in unit-test, but not detected bt gcov
void
Debug::printBacktraceBeforeAbort()
{
    if (!Singleton::exists<I_SignalHandler>()) return;

    Maybe<vector<string>> bt_strings = Singleton::Consume<I_SignalHandler>::by<Debug>()->getBacktrace();
    if (!bt_strings.ok()) {
        stream << "\nNo backtrace to present";
        return;
    }

    stream << "\nPresenting backtrace:";
    for (const string &bt_line : bt_strings.unpack()) {
        stream << "\n" << bt_line;
    }
}
// LCOV_EXCL_STOP

void
Debug::startStreams(
    const DebugLevel &level,
    const string &file_name,
    const string &func_name,
    const uint &line
)
{
    for (auto &added_stream : current_active_streams) {
        added_stream->printHeader(time, env, mainloop, level, file_name, func_name, line);
        stream.addStream(added_stream->getStream());
    }

    is_debug_running = true;
}

void
Debug::isCommunicationFlag(const DebugFlags &flag)
{
    is_communication |= (flag == D_HTTP_REQUEST || flag == D_COMMUNICATION);
}

Debug::DebugLevel Debug::lowest_global_level = default_level;
I_TimeGet *Debug::time = nullptr;
I_MainLoop *Debug::mainloop = nullptr;
I_Environment *Debug::env = nullptr;
bool Debug::is_debug_running = false;
bool Debug::is_fail_open_mode = false;
bool Debug::debug_override_exist = false;
string Debug::default_debug_file_stream_path = "";
vector<string> Debug::streams_from_mgmt;

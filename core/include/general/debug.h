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

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <set>
#include <functional>
#include <chrono>
#include <vector>

#include "common.h"
#include "singleton.h"
#include "scope_exit.h"

class I_TimeGet;
class I_Messaging;
class I_MainLoop;
class I_Environment;
class I_InstanceAwareness;
class I_Encryptor;
class I_AgentDetails;
class I_SignalHandler;

namespace Config { enum class Errors; }
std::ostream & operator<<(std::ostream &, const Config::Errors &);

class Debug
        :
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_InstanceAwareness>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_Encryptor>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_SignalHandler>
{
public:
    class DebugStream;
    enum class DebugLevel { NOISE, TRACE, DEBUG, INFO, WARNING, ERROR, ASSERTION, NONE };
    enum class DebugFlags;

    class DebugStreamAggr
    {
        template <typename T, typename Helper = void>
        struct Print
        {
            Print(std::ostream *str, const T &obj) { (*str) << obj; }
        };

        template <typename T>
        struct Print<T, decltype(std::declval<T>().print(std::declval<std::ostream &>()))>
        {
            Print(std::ostream *str, const T &obj) { obj.print(*str); }
        };

    public:
        template <typename T>
        DebugStreamAggr &
        operator<<(const T &obj)
        {
            for (auto &stream : streams) {
                Print<T>(stream, obj);
            }
            return *this;
        }

        DebugStreamAggr &
        operator<<(std::ostream & (*func)(std::ostream &))
        {
            for (auto &stream : streams) {
                func(*stream);
            }
            return *this;
        }

        void addStream(std::ostream *stream) { streams.insert(stream); }

    private:
        std::set<std::ostream *> streams;
    };

    class DebugLockState
    {
    private:
        friend class Environment;
        static bool getState() { return is_debug_running; }
        static void setState(const bool _is_debug_running) { is_debug_running = _is_debug_running; }
    };

public:
    Debug(
        const std::string &file_name,
        const std::string &func_name,
        const uint &line
    );

    Debug(
        const std::string &file_name,
        const std::string &func_name,
        const uint &line,
        const DebugLevel &level,
        const DebugFlags &flag1
    );

    Debug(
        const std::string &file_name,
        const std::string &func_name,
        const uint &line,
        const DebugLevel &level,
        const DebugFlags &flag1,
        const DebugFlags &flag2
    );

    Debug(
        const std::string &file_name,
        const std::string &func_name,
        const uint &line,
        const DebugLevel &level,
        const DebugFlags &flag1,
        const DebugFlags &flag2,
        const DebugFlags &flag3
    );

    Debug(
        const std::string &file_name,
        const std::string &func_name,
        const uint &line,
        const DebugLevel &level,
        const DebugFlags &flag1,
        const DebugFlags &flag2,
        const DebugFlags &flag3,
        const DebugFlags &flag4
    );

    ~Debug();

    DebugStreamAggr &
    getStreamAggr() __attribute__((warn_unused_result))
    {
        return stream;
    }

    static void preload();

    static void init();
    static void fini();

    static std::string getName() { return "DebugIS"; }

    static void prepareConfig();
    static void commitConfig();
    static void abortConfig();

    static void failOpenDebugMode(std::chrono::seconds debug_period);

    template <typename... Args>
    static bool
    evalFlags(DebugLevel level, DebugFlags flag, Args... args)
    {
        return !is_debug_running && level>=lowest_global_level && evalFlagByFlag(level, flag, args...);
    }

    static bool isFlagAtleastLevel(DebugFlags flag, DebugLevel level);

    static void setNewDefaultStdout(std::ostream *new_stream);
    static void setUnitTestFlag(DebugFlags flag, DebugLevel level);

    static std::string findDebugFilePrefix(const std::string &file_name);

private:
    template <typename T, typename... Args>
    static bool
    evalFlagByFlag(DebugLevel _level, T flag, Args... args)
    {
        return evalFlagByFlag(_level, flag) || evalFlagByFlag(_level, args...);
    }
    static bool evalFlagByFlag(DebugLevel _level, DebugFlags flag);
    static bool evalFlagByFlag(DebugLevel) { return true; }

    static void applyOverrides();

    bool shouldApplyFailOpenOnStream(const std::string &name) const;

    void addActiveStream(const std::string &name);

    void printBacktraceBeforeAbort();

    void startStreams(
        const DebugLevel &level,
        const std::string &file_name,
        const std::string &func_name,
        const uint &line
    );

    void isCommunicationFlag(const DebugFlags &flag);

    static DebugLevel lowest_global_level;
    static I_TimeGet *time;
    static I_MainLoop *mainloop;
    static I_Environment *env;
    static bool is_debug_running;
    static bool is_fail_open_mode;
    static bool debug_override_exist;
    static std::string default_debug_file_stream_path;
    static std::vector<std::string> streams_from_mgmt;

    bool do_assert;
    bool is_communication = false;
    DebugStreamAggr stream;
    std::set<std::shared_ptr<DebugStream>> current_active_streams;
};

#define USE_DEBUG_FLAG(x) extern const Debug::DebugFlags x

// This function extract the base name from a full path.
// The `iter` variable holds the current place of the iteration over the full path.
// The `base` variable holds where we currently think the base name starts
static inline constexpr const char *
getBaseName(const char *iter, const char *base)
{
    // If `iter` doesn't point to the next charecter in the string, then return where we think the base name starts.
    return (iter==nullptr || *iter=='\0') ? base :
            // If `iter` points to '/' char, then now we thik the next char is the start of the base name, otherwise we
            // stil think that `base` points to the start of the base name.
            // In any case, we recursively progress  `iter` to check the next char.
            (*iter=='/' ? getBaseName(iter+1, iter+1) : getBaseName(iter+1, base));
}

#define __FILENAME__ getBaseName(__FILE__, __FILE__)

#define dbgAssert(cond) \
    if (CP_LIKELY(cond)) { \
    } else Debug(__FILENAME__, __FUNCTION__, __LINE__).getStreamAggr()

// Macros to allow simple debug messaging
#define DBG_GENERIC(level, ...) \
    if (!Debug::evalFlags(Debug::DebugLevel::level, __VA_ARGS__)) { \
    } else Debug(__FILENAME__, __FUNCTION__, __LINE__, Debug::DebugLevel::level, __VA_ARGS__).getStreamAggr()

#define isDebugRequired(level, flag) (Debug::evalFlags(Debug::DebugLevel::level, flag))

#define dbgTrace(...)   DBG_GENERIC(TRACE,   __VA_ARGS__)
#define dbgDebug(...)   DBG_GENERIC(DEBUG,   __VA_ARGS__)
#define dbgInfo(...)    DBG_GENERIC(INFO,    __VA_ARGS__)
#define dbgWarning(...) DBG_GENERIC(WARNING, __VA_ARGS__)
#define dbgError(...)   DBG_GENERIC(ERROR,   __VA_ARGS__)

// Macro for automatic printouts on entering and leaving scope
// Should be in the first line of a function
// Output is in Trace level
#define dbgFlow(...) \
    auto __function_name = __FUNCTION__; \
    auto __scope_exit = std::make_scope_exit( \
        [__function_name] () { \
            if (Debug::evalFlags(Debug::DebugLevel::TRACE, __VA_ARGS__)) { \
                Debug(__FILENAME__, __function_name, __LINE__, Debug::DebugLevel::TRACE, __VA_ARGS__) \
                    .getStreamAggr() << "Exit"; \
            } \
        } \
    ); \
    dbgTrace(__VA_ARGS__) << "Enter "

#endif // __DEBUG_H__

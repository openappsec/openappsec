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

#include "signal_handler.h"

#include <algorithm>
#include <string>
#include <memory>
#include <fstream>
#include <streambuf>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <iosfwd>
#include <chrono>
#include <boost/regex.hpp>

#ifdef UNWIND_LIBRARY
#define UNW_LOCAL_ONLY
#include <cxxabi.h>
#include <libunwind.h>
#endif // UNWIND_LIBRARY

#include "debug.h"
#include "common.h"
#include "config.h"
#include "mainloop.h"
#include "report/log_rest.h"
#include "report/report.h"
#include "agent_core_utilities.h"

#define stack_trace_max_len 64

using namespace std;
using namespace ReportIS;

USE_DEBUG_FLAG(D_SIGNAL_HANDLER);

class SignalHandler::Impl : Singleton::Provide<I_SignalHandler>::From<SignalHandler>
{
public:
    void
    fini()
    {
        if (out_trace_file_fd != -1) close(out_trace_file_fd);
        out_trace_file_fd = -1;
    }

    void
    dumpErrorReport(const string &error) override
    {
        ofstream export_error_file(trace_file_path);
        export_error_file << error << endl;
    }

    void
    init()
    {
        addSignalHandlerRoutine();
        addReloadConfigurationRoutine();
    }

    Maybe<vector<string>>
    getBacktrace() override
    {
#ifdef UNWIND_LIBRARY

        vector<string> symbols;
        unw_cursor_t cursor;
        unw_context_t context;

        // Initialize cursor to current frame for local unwinding.
        unw_getcontext(&context);
        unw_init_local(&cursor, &context);

        char buf[1024];
        // Unwind frames one by one, going up the frame stack.
        while (unw_step(&cursor) > 0) {
            unw_word_t offset, pc;
            unw_get_reg(&cursor, UNW_REG_IP, &pc);
            if (pc == 0) break;

            char sym[256];
            if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
                char *nameptr = sym;
                int status;
                char *demangled = abi::__cxa_demangle(sym, nullptr, nullptr, &status);
                if (status == 0) {
                    nameptr = demangled;
                }
                snprintf(buf, sizeof(buf), "(%s+0x%lx) [0x%lx]", nameptr, offset, pc);
                free(demangled);
            } else {
                snprintf(buf, sizeof(buf), "-- error: unable to obtain symbol name for this frame");
            }
            symbols.push_back(buf);
        }

        return symbols;

#else // UNWIND_LIBRARY

        return genError("Could not print any backtrace entries using uclibc (backtrace_symbols not supported)");

#endif // UNWIND_LIBRARY
    }

private:
    void
    addSignalHandlerRoutine()
    {
        Singleton::Consume<I_MainLoop>::by<SignalHandler>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::Offline,
            [this] ()
            {
                string service_name = "Unnamed Nano Service";
                if (Singleton::exists<I_Environment>()) {
                    auto name = Singleton::Consume<I_Environment>::by<SignalHandler>()->get<string>(
                        "Service Name"
                    );
                    if (name.ok()) service_name = *name;
                }
                string service_underscore_name = service_name;
                replace(service_underscore_name.begin(), service_underscore_name.end(), ' ', '_');

                trace_file_path = getConfigurationWithDefault<string>(
                    "/var/log/nano_agent/trace_export_files/" + service_underscore_name + "_trace_file.dbg",
                    "SignalHandler",
                    "outputFilePath"
                );
                ifstream in_trace_file(trace_file_path);

                if (in_trace_file.peek() != ifstream::traits_type::eof()) {
                    stringstream buffer;
                    buffer << in_trace_file.rdbuf();
                    if (buffer.str() != " " && buffer.str() != "\n") {
                        const boost::regex reg("(\\+0x[A-z0-9]*)|( [0x[A-z0-9]*])");
                        const string fixed_trace_str = NGEN::Regex::regexReplace(
                            __FILE__,
                            __LINE__,
                            buffer.str(),
                            reg,
                            ""
                        );
                        generateLog(fixed_trace_str);
                        dbgInfo(D_SIGNAL_HANDLER)
                            << "Service started after crash ERROR: "
                            << endl
                            << fixed_trace_str;
                    }
                }

                in_trace_file.close();

                ofstream out_trace_file(trace_file_path, ofstream::out | ofstream::trunc);
                out_trace_file.close();

                setSignalHanlders();
            },
            "Send crash trace report"
        );
    }

    void
    generateLog(const string &trace_file_data)
    {
        auto i_time = Singleton::Consume<I_TimeGet>::by<SignalHandler>();
        chrono::microseconds curr_time = i_time!=nullptr ? i_time->getWalltime() : chrono::microseconds(0);

        if (!Singleton::exists<I_Messaging>()) return;

        AudienceTeam audience_team = AudienceTeam::NONE;
        if (Singleton::exists<I_Environment>()) {
            auto team = Singleton::Consume<I_Environment>::by<SignalHandler>()->get<AudienceTeam>("Audience Team");
            if (team.ok()) audience_team = *team;
        }

        set<ReportIS::Tags> tags;
        Report message_to_fog(
            "Nano service startup after crash",
            curr_time,
            Type::EVENT,
            Level::LOG,
            LogLevel::ERROR,
            Audience::INTERNAL,
            audience_team,
            Severity::HIGH,
            Priority::HIGH,
            chrono::seconds(0),
            LogField("agentId", Singleton::Consume<I_AgentDetails>::by<SignalHandler>()->getAgentId()),
            tags,
            Tags::INFORMATIONAL
        );

        message_to_fog << LogField("eventMessage", trace_file_data);

        string fog_signalHandler_uri = getConfigurationWithDefault<string>(
            "/api/v1/agents/events",
            "SignalHandler",
            "fogSignalHandlerURI"
        );

        LogRest signalHandler_client_rest(message_to_fog);

        Singleton::Consume<I_Messaging>::by<SignalHandler>()->sendObjectWithPersistence(
            signalHandler_client_rest,
            I_Messaging::Method::POST,
            fog_signalHandler_uri,
            "",
            true,
            MessageTypeTag::REPORT
        );

        dbgInfo(D_SIGNAL_HANDLER) << "Sent crash log to fog" << endl;
    }

    void
    setSignalHanlders()
    {
        out_trace_file_fd = open(trace_file_path.c_str(),  O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        int errno_copy = errno;
        if (out_trace_file_fd < 0) {
            dbgError(D_SIGNAL_HANDLER)
                << "Failed to open signal handler backtrace file. Path: "
                << trace_file_path
                << ", Errno: "
                << to_string(errno_copy)
                << ", Error: "
                << strerror(errno_copy);
        }
        setHandlerPerSignalNum();
    }

    void
    setHandlerPerSignalNum()
    {
        static const vector<int> signals = {
            SIGABRT,
            SIGKILL,
            SIGQUIT,
            SIGINT,
            SIGTERM,
            SIGSEGV,
            SIGBUS,
            SIGILL,
            SIGFPE,
            SIGPIPE,
            SIGUSR2
        };

        for (int sig : signals) {
            signal(sig, signalHandlerCB);
        }
    }

// LCOV_EXCL_START Reason: Cannot crash unitest or send signal during execution
    static bool
    writeData(const char *data, uint32_t len)
    {
        uint32_t bytes_sent = 0;
        while (bytes_sent  < len) {
            int res = write(out_trace_file_fd, data + bytes_sent, len - bytes_sent);
            if (res <= 0) return false;

            bytes_sent += res;
        }

        return true;
    }

    static void
    signalHandlerCB(int _signal)
    {
        const char *signal_name = "";
        char signal_num[3];

        reset_signal_handler = true;

        switch(_signal) {
            case SIGABRT: {
                signal_name = "SIGABRT";
                fini_signal_flag = true;
                return;
            }
            case SIGKILL: {
                signal_name = "SIGKILL";
                fini_signal_flag = true;
                return;
            }
            case SIGQUIT: {
                signal_name = "SIGQUIT";
                fini_signal_flag = true;
                return;
            }
            case SIGINT: {
                signal_name = "SIGINT";
                fini_signal_flag = true;
                return;
            }
            case SIGTERM: {
                signal_name = "SIGTERM";
                fini_signal_flag = true;
                return;
            }
            case SIGSEGV: {
                signal_name = "SIGSEGV";
                break;
            }
            case SIGBUS: {
                signal_name = "SIGBUS";
                break;
            }
            case SIGILL: {
                signal_name = "SIGILL";
                break;
            }
            case SIGFPE: {
                signal_name = "SIGFPE";
                break;
            }
            case SIGPIPE: {
                signal_name = "SIGPIPE";
                return;
            }
            case SIGUSR2: {
                reload_settings_flag = true;
                return;
            }
        }

        if (out_trace_file_fd == -1) exit(_signal);

        for (uint i = 0; i < sizeof(signal_num); ++i) {
            uint placement = sizeof(signal_num) - 1 - i;
            signal_num[placement] = _signal%10 + '0';
            _signal /= 10;
        }
        const char *signal_error_prefix = "Caught signal ";
        writeData(signal_error_prefix, strlen(signal_error_prefix));
        writeData(signal_num, sizeof(signal_num));
        if (strlen(signal_name)) {
            const char *open_braces = "(";
            writeData(open_braces, strlen(open_braces));
            writeData(signal_name, strlen(signal_name));
            const char *close_braces = ")\n";
            writeData(close_braces, strlen(close_braces));
        }

        printStackTrace();

        close(out_trace_file_fd);
        out_trace_file_fd = -1;

        exit(_signal);
    }

    static void
    printStackTrace()
    {
#ifdef UNWIND_LIBRARY

        if (out_trace_file_fd == -1) return;

        const char *stack_trace_title = "Stack trace:\n";
        writeData(stack_trace_title, strlen(stack_trace_title));

        unw_cursor_t cursor;
        unw_context_t uc;
        unw_getcontext(&uc);
        if (unw_init_local(&cursor, &uc) < 0) {
            const char *unw_init_local_error = "unw_init_local failed!\n";
            writeData(unw_init_local_error, strlen(unw_init_local_error));
            return;
        }

        char name[256];
        unw_word_t ip, sp, off;
        for (uint i = 0 ; i < stack_trace_max_len ; i++) {
            unw_get_reg(&cursor, UNW_REG_IP, &ip);
            unw_get_reg(&cursor, UNW_REG_SP, &sp);

            if (unw_get_proc_name(&cursor, name, sizeof(name), &off) == 0) {
                const char *open_braces = "<";
                writeData(open_braces, strlen(open_braces));
                writeData(name, strlen(name));
                const char *close_braces = ">\n";
                writeData(close_braces, strlen(close_braces));
            }


            if (unw_step(&cursor) <= 0) return;
        }

#else // UNWIND_LIBRARY

        const char *uclibc_error =
            "Could not print any backtrace entries using uclibc (backtrace_symbols not supported)\n";
        writeData(uclibc_error, strlen(uclibc_error));

#endif // UNWIND_LIBRARY
    }
// LCOV_EXCL_STOP

    void
    addReloadConfigurationRoutine()
    {
        Singleton::Consume<I_MainLoop>::by<SignalHandler>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [&] ()
            {
                while (true) {
                    if (reset_signal_handler) {
                        setHandlerPerSignalNum();
                    }
                    if (reload_settings_flag == true) {
                        reload_settings_flag = false;
                        if (reloadConfiguration("")) {
                            dbgInfo(D_SIGNAL_HANDLER) << "Reloaded configuration";
                        } else {
                            dbgWarning(D_SIGNAL_HANDLER) << "Failed to reload configuration";
                        }
                    }
                    Singleton::Consume<I_MainLoop>::by<SignalHandler>()->yield(chrono::seconds(1));
                }
            },
            "Reload configuration signal handler"
        );
    }

    static string trace_file_path;
    static bool reload_settings_flag;
    static bool reset_signal_handler;
    static int out_trace_file_fd;
};

string SignalHandler::Impl::trace_file_path;
bool SignalHandler::Impl::reload_settings_flag = false;
bool SignalHandler::Impl::reset_signal_handler = false;
int SignalHandler::Impl::out_trace_file_fd = -1;

SignalHandler::SignalHandler() : Component("SignalHandler"), pimpl(make_unique<Impl>()) {}
SignalHandler::~SignalHandler() {}

void SignalHandler::init() { pimpl->init(); }

void
SignalHandler::preload()
{
    registerExpectedConfiguration<int>("SignalHandler", "outputFilePath");
    registerExpectedConfiguration<int>("SignalHandler", "fogSignalHandlerURI");
}

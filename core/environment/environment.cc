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

#include "environment.h"
#include "context.h"
#include "singleton.h"
#include "common.h"
#include "debug.h"
#include "evaluator_registration.h"
#include "environment_evaluator.h"
#include "i_rest_api.h"
#include "rest.h"
#include "environment/trace.h"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "config.h"
#include "environment/tracing_metric.h"

using namespace std;

USE_DEBUG_FLAG(D_ENVIRONMENT);
USE_DEBUG_FLAG(D_TRACE);

class Environment::Impl
        :
    public Singleton::Provide<I_Environment>::From<Environment>
{
public:
    void init();
    void fini();

    void preload();

    void setActiveTenantAndProfile(const string &tenant_id, const string &profile_id) override;
    void unsetActiveTenantAndProfile() override;

    void registerContext(Context *ptr) override;
    void unregisterContext(Context *ptr) override;
    ActiveContexts createEnvironment() override;
    ActiveContexts saveEnvironment() override;
    void loadEnvironment(ActiveContexts &&env) override;
    Context & getConfigurationContext() override;

    map<string, string> getAllStrings(const EnvKeyAttr::ParamAttr &params) const override;
    map<string, uint64_t> getAllUints(const EnvKeyAttr::ParamAttr &params) const override;
    map<string, bool> getAllBools(const EnvKeyAttr::ParamAttr &params) const override;

    string getCurrentTrace() const override;
    string getCurrentSpan() const override;
    string getCurrentHeaders() override;

    void startNewTrace(bool new_span, const string &_trace_id) override;
    void startNewSpan(Span::ContextType _type, const string &prev_span, const string &trace) override;
    using on_exit = scope_exit<function<void(void)>>;
    on_exit startNewSpanScope(Span::ContextType _type, const string &prev_span, const string &trace) override;
    void finishTrace(const string &trace) override;
    void finishSpan(const string &span) override;

private:
    const ActiveContexts & getActiveContexts() const override { return active_contexts; }
    void loadEnvConfig();

    I_TenantManager *tenant_manager = nullptr;
    ActiveContexts active_contexts;
    Context global;
    map<string, TraceWrapper> active_traces;
    map<string, SpanWrapper> active_spans;
    map<string, int> tracing_stats;
    TracingMetric tracing_metric;
    TraceEvent trace_event;
    TraceFinishEvent trace_finish_event;
    bool is_metric_enabled = false;
    TracingStatus tracing_status = TracingStatus::OFF;
    bool was_initialized = false;
};

class DeclareBooleanVariable : public ServerRest
{
public:
    void
    doCall() override
    {
        auto func = genEvaluator<bool>(expr);
        if (!func.ok()) {
            dbgWarning(D_ENVIRONMENT) << "Failed to generate boolean function: " << func.getErr();
            return;
        }
        dbgTrace(D_ENVIRONMENT) << "Boolean function was generated";
        auto env = Singleton::Consume<I_Environment>::from<Environment>();
        env->getConfigurationContext().registerFunc(name, func.unpackMove());
    }

private:
    C2S_PARAM(string, name);
    C2S_PARAM(string, expr);
};

void
Environment::Impl::loadEnvConfig()
{
    auto tracing_conf = getConfigurationWithDefault<bool>(false, "environment", "enable tracing");
    if (tracing_status == TracingStatus::DISABLED) return;
    tracing_status = tracing_conf ? TracingStatus::ON : TracingStatus::OFF;
    if (tracing_status == TracingStatus::ON && !is_metric_enabled) {
        auto metric_report_interval = chrono::seconds(
            getConfigurationWithDefault<uint>(600, "environment", "tracingMetricReportInterval")
        );
        tracing_metric.init(
            "tracing",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            metric_report_interval,
            false
        );
        tracing_metric.registerListener();
        is_metric_enabled = true;
    }
}

void
Environment::Impl::init()
{
    was_initialized = true;
    loadEnvConfig();
    if (!Singleton::exists<I_RestApi>()) return;
    auto rest = Singleton::Consume<I_RestApi>::by<Environment>();
    rest->addRestCall<DeclareBooleanVariable>(RestAction::ADD, "declare-boolean-variable");
}

void
Environment::Impl::fini()
{
}

void
Environment::Impl::setActiveTenantAndProfile(const string &tenant_id, const string &profile_id)
{
    if (tenant_manager == nullptr) tenant_manager = Singleton::Consume<I_TenantManager>::by<Environment>();
    tenant_manager->addActiveTenantAndProfile(tenant_id, profile_id);
    registerValue<string>("ActiveTenantId", tenant_id);
    registerValue<string>("ActiveProfileId", profile_id);
}

void
Environment::Impl::unsetActiveTenantAndProfile()
{
    getConfigurationContext().unregisterKey<string>("ActiveTenantId");
    getConfigurationContext().unregisterKey<string>("ActiveProfileId");
}

map<string, string>
Environment::Impl::getAllStrings(const EnvKeyAttr::ParamAttr &params) const
{
    map<string, string> result;

    for (auto &iter : active_contexts.first) {
        auto partial_results = iter->getAllStrings(params);
        for (auto &entry : partial_results) {
            result.emplace(entry);
        }
    }

    return result;
}

map<string, uint64_t>
Environment::Impl::getAllUints(const EnvKeyAttr::ParamAttr &params) const
{
    map<string, uint64_t> result;

    for (auto &iter : active_contexts.first) {
        auto partial_results = iter->getAllUints(params);
        for (auto &entry : partial_results) {
            result.emplace(entry);
        }
    }

    return result;
}

map<string, bool>
Environment::Impl::getAllBools(const EnvKeyAttr::ParamAttr &params) const
{
    map<string, bool> result;

    for (auto &iter : active_contexts.first) {
        auto partial_results = iter->getAllBools(params);
        for (auto &entry : partial_results) {
            result.emplace(entry);
        }
    }

    return result;
}

void
Environment::Impl::registerContext(Context *ptr)
{
    active_contexts.first.push_back(ptr);
}

void
Environment::Impl::unregisterContext(Context *ptr)
{
    dbgAssert(active_contexts.first.back() == ptr) <<
        "Contexts are supposed to unregister in reverse order to their registration";
    active_contexts.first.pop_back();
}

string
Environment::Impl::getCurrentTrace() const
{
    if (tracing_status != TracingStatus::ON) return "";

    auto trace = get<string>("trace id");
    if (trace.ok()) return trace.unpack();
    return "";
}

string
Environment::Impl::getCurrentSpan() const
{
    if (tracing_status != TracingStatus::ON) return "";

    auto span = get<string>("span id");
    if (span.ok()) return span.unpack();
    return "";
}

string
Environment::Impl::getCurrentHeaders()
{
    string tracing_headers;
    auto trace_id = getCurrentTrace();
    if (!trace_id.empty()) {
        tracing_headers += "X-Trace-Id: " + trace_id + "\r\n";
    } else {
        string correlation_id_string = "00000000-0000-0000-0000-000000000000";
        try {
            boost::uuids::random_generator uuid_random_gen;
            correlation_id_string = boost::uuids::to_string(uuid_random_gen());
        } catch (const boost::uuids::entropy_error &e) {
            dbgTrace(D_ENVIRONMENT)
                << "Failed to generate random correlation id - entropy exception. Exception: "
                << e.what();
            tracing_status = TracingStatus::DISABLED;
        }
        tracing_headers += "X-Trace-Id: " + correlation_id_string + "\r\n";
    }

    auto span_id = getCurrentSpan();
    if (!span_id.empty()) {
        tracing_headers += "X-Span-Id: " + span_id + "\r\n";
    }
    return tracing_headers;
}

void
Environment::Impl::startNewTrace(bool new_span, const string &_trace_id)
{
    if (tracing_status != TracingStatus::ON) return;

    try {
        TraceWrapper trace(_trace_id);
        auto trace_id = trace.getTraceId();
        active_traces.emplace(trace_id, trace);
        tracing_stats[trace_id] = 0;
        if (new_span) {
            SpanWrapper span(trace_id);
            auto span_id = span.getSpanId();
            active_spans.emplace(span_id, span);
        }
        trace_event.setTraceAmount(active_traces.size());
        trace_event.notify();

    } catch (const boost::uuids::entropy_error &e) {
        tracing_status = TracingStatus::DISABLED;
        dbgWarning(D_TRACE)
            << "Failed to generate random id - entropy exception. Exception: "
            << e.what();
        return;
    }
}

void
Environment::Impl::startNewSpan(Span::ContextType context_type, const string &prev_span, const string &trace)
{
    if (tracing_status != TracingStatus::ON) return;

    string selected_trace = !trace.empty() ? trace : getCurrentTrace();
    string selected_span = !prev_span.empty() ? prev_span : getCurrentSpan();
    try {
        SpanWrapper span(selected_trace, context_type, selected_span);
        active_spans.emplace(span.getSpanId(), span);
    } catch (const boost::uuids::entropy_error &e) {
        tracing_status = TracingStatus::DISABLED;
        dbgWarning(D_TRACE)
            << "Failed to generate random id - entropy exception. Exception: "
            << e.what();
        return;
    }
}

void
Environment::Impl::finishTrace(const string &trace)
{
    if (tracing_status != TracingStatus::ON) return;

    auto deleted_trace = trace.empty() ? getCurrentTrace() : trace;
    if (deleted_trace.empty()) {
        dbgWarning(D_ENVIRONMENT) << "There is no current trace to finish";
        return;
    }

    trace_finish_event.setSpanAmount(tracing_stats[deleted_trace]);
    active_traces.erase(deleted_trace);
    tracing_stats.erase(deleted_trace);

    trace_event.setTraceAmount(active_traces.size());
    trace_event.notify();
    trace_finish_event.notify();
}

void
Environment::Impl::finishSpan(const string &span)
{
    if (tracing_status != TracingStatus::ON) return;

    auto deleted_span = span.empty() ? getCurrentSpan() : span;
    if (deleted_span.empty()) {
        dbgWarning(D_ENVIRONMENT) << "There is no current span to finish";
        return;
    }
    auto span_iter = active_spans.find(deleted_span);
    if (span_iter != active_spans.end())  {
        auto trace_id = span_iter->second.getTraceId();
        tracing_stats[trace_id]++;
    }

    active_spans.erase(deleted_span);
}

scope_exit<function<void(void)>>
Environment::Impl::startNewSpanScope(Span::ContextType context_type, const string &prev_span, const string &trace)
{
    startNewSpan(context_type, prev_span, trace);
    function<void(void)> release_function = [&] () { finishSpan(""); };
    return make_scope_exit(move(release_function));
}

I_Environment::ActiveContexts
Environment::Impl::createEnvironment()
{
    return ActiveContexts({ &global }, Debug::DebugLockState::getState());
}

I_Environment::ActiveContexts
Environment::Impl::saveEnvironment()
{
    return move(active_contexts);
}

void
Environment::Impl::loadEnvironment(ActiveContexts &&env)
{
    active_contexts = move(env);
    Debug::DebugLockState::setState(active_contexts.second);
}

Context &
Environment::Impl::getConfigurationContext()
{
    return global;
}

void
Environment::Impl::preload()
{
    registerBaseEvaluators();
    global.activate();
    registerExpectedConfiguration<bool>("environment", "enable tracing");
    registerExpectedConfiguration<uint>("environment", "tracingMetricReportInterval");
    registerConfigLoadCb(
        [this] ()
        {
            if (was_initialized) loadEnvConfig();
        }
    );
}

Environment::Environment() : Component("Environment"), pimpl(make_unique<Impl>()) {}

Environment::~Environment() {}

void
Environment::init()
{
    pimpl->init();
}

void
Environment::fini()
{
    pimpl->fini();
}

void
Environment::preload()
{
    pimpl->preload();
}

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

#include "environment/span.h"

#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "debug.h"

using namespace std;
using namespace boost::uuids;

USE_DEBUG_FLAG(D_TRACE);

Span::Span(string _trace_id, ContextType _type, string _prev_span)
        :
    trace_id(_trace_id),
    context_type(_type),
    prev_span_id(_prev_span)
{

    if (trace_id.empty()) {
        dbgError(D_TRACE) << "Provided trace id is empty. Span cannot be created";
        return;
    }

    if (context_type != ContextType::NEW && prev_span_id.empty()) {
        dbgError(D_TRACE) << "The provided previous span ID is empty. Cannot create span.";
        return;
    }

    boost::uuids::random_generator uuid_random_gen;
    span_id = to_string(uuid_random_gen());

    context.registerValue<string>("span id", span_id);
    context.activate();

    dbgTrace(D_TRACE) << "New span was created " << span_id
        << ", trace id " << trace_id
        << ", context type " << convertSpanContextTypeToString(context_type)
        << (context_type == ContextType::NEW ? string() : ", previous span id " + prev_span_id);
}

Span::~Span()
{
    dbgTrace(D_TRACE) << "Current span has ended " << span_id;
    context.unregisterKey<string>("span id");
    context.deactivate();
}

string
Span::getTraceId() const
{
    return trace_id;
}

string
Span::getSpanId() const
{
    return span_id;
}

Span::ContextType
Span::getSpanContextType() const
{
    return context_type;
}

string
Span::getPrevSpanId() const
{
    return prev_span_id;
}

string
Span::convertSpanContextTypeToString(ContextType type)
{
    switch(type) {
        case ContextType::NEW: {
            return "New";
        }
        case ContextType::CHILD_OF: {
            return "Child of";
        }
        case ContextType::FOLLOWS_FROM: {
            return "Follows from";
        }
    }
    dbgAssert(false) << "Span context not supported";
    return string();
}

SpanWrapper::SpanWrapper(string _trace_id, Span::ContextType _type, string _prev_span)
        :
    span(make_shared<Span>(_trace_id, _type, _prev_span))
{}

string
SpanWrapper::getTraceId() const
{
    return span->getTraceId();
}

string
SpanWrapper::getSpanId() const
{
    return span->getSpanId();
}

Span::ContextType
SpanWrapper::getSpanContextType() const
{
    return span->getSpanContextType();
}

string
SpanWrapper::getPrevSpanId() const
{
    return span->getPrevSpanId();
}

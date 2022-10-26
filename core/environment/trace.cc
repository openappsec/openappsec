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

#include "environment/trace.h"

#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "debug.h"

using namespace std;
using namespace boost::uuids;

USE_DEBUG_FLAG(D_TRACE);

Trace::Trace(string _id)
        :
    trace_id(_id)
{
    if (trace_id.empty()) {
        boost::uuids::random_generator uuid_random_gen;
        trace_id = to_string(uuid_random_gen());
    }
    context.registerValue<string>("trace id", trace_id);
    context.activate();
    dbgTrace(D_TRACE) << "New trace was created " << trace_id;
}

Trace::~Trace()
{
    dbgTrace(D_TRACE) << "Current trace has ended " << trace_id;
    context.unregisterKey<string>("trace id");
    context.deactivate();
}

string
Trace::getTraceId() const
{
    return trace_id;
}

TraceWrapper::TraceWrapper(string _id) : trace(make_shared<Trace>(_id)) {}

string
TraceWrapper::getTraceId() const
{
    return trace->getTraceId();
}

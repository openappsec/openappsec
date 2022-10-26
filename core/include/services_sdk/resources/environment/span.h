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

#ifndef __SPAN_H__
#define __SPAN_H__

#include <string>
#include "context.h"

class Span
{
public:

    enum class ContextType
    {
        NEW,
        CHILD_OF,
        FOLLOWS_FROM
    };

    std::string
    convertSpanContextTypeToString(ContextType type);

    Span(std::string _trace_id, ContextType _type = ContextType::NEW, std::string _prev_span = std::string());
    ~Span();

    std::string getTraceId() const;
    std::string getSpanId() const;
    ContextType getSpanContextType() const;
    std::string getPrevSpanId() const;

private:
    std::string trace_id;
    std::string span_id;
    ContextType context_type;
    std::string prev_span_id;
    Context context;
};

class SpanWrapper
{
public:
    SpanWrapper(
        std::string _trace_id,
        Span::ContextType _type = Span::ContextType::NEW,
        std::string _prev_span = std::string()
    );
    std::string getTraceId() const;
    std::string getSpanId() const;
    Span::ContextType getSpanContextType() const;
    std::string getPrevSpanId() const;

private:
    std::shared_ptr<Span> span;
};
#endif // __SPAN_H__

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

#ifndef __I_HTTP_MANAGER_H__
#define __I_HTTP_MANAGER_H__

#include "http_inspection_events.h"

class I_HttpManager
{
public:
    virtual FilterVerdict inspect(const HttpTransactionData &event) = 0;
    virtual FilterVerdict inspect(const HttpHeader &event, bool is_request) = 0;
    virtual FilterVerdict inspect(const HttpBody &event, bool is_request) = 0;
    virtual FilterVerdict inspect(const ResponseCode &event) = 0;
    virtual FilterVerdict inspectEndRequest() = 0;
    virtual FilterVerdict inspectEndTransaction() = 0;
    virtual FilterVerdict inspectDelayedVerdict() = 0;

protected:
    virtual ~I_HttpManager() {}
};

#endif // __I_HTTP_MANAGER_H__

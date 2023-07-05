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

#ifndef __I_REST_API__
#define __I_REST_API__

#include "rest.h"

#include <string>
#include <memory>

#include "common.h"

enum class RestAction { ADD, SET, SHOW, DELETE };

// The RestInit class provides an interface through which new JsonRest object can be created.
class RestInit
{
public:
    ~RestInit() {}
    virtual std::unique_ptr<ServerRest> getRest() = 0;
};

template <typename T>
class SpecificRestInit : public RestInit
{
public:
    std::unique_ptr<ServerRest> getRest() override { return std::make_unique<T>(); }
};

class I_RestApi
{
public:
    template <typename T>
    bool
    addRestCall(RestAction oper, const std::string &uri)
    {
        return addRestCall(oper, uri, std::make_unique<SpecificRestInit<T>>());
    }

    virtual uint16_t getListeningPort() const = 0;

protected:
    ~I_RestApi() {}
    virtual bool addRestCall(RestAction oper, const std::string &uri, std::unique_ptr<RestInit> &&init) = 0;
};

#endif // __I_REST_API__

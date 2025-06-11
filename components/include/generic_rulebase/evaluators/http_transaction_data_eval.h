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

#ifndef __HTTP_TRANSACTION_DATA_EVAL_H__
#define __HTTP_TRANSACTION_DATA_EVAL_H__

#include "environment/evaluator_templates.h"
#include "i_environment.h"
#include "singleton.h"
#include "connkey.h"

class EqualHost : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    EqualHost(const std::vector<std::string> &params);

    static std::string getName() { return "EqualHost"; }

    Maybe<bool, Context::Error> evalVariable() const override;

private:
    std::string host;
};

class WildcardHost : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    WildcardHost(const std::vector<std::string> &params);

    static std::string getName() { return "WildcardHost"; }

    Maybe<bool, Context::Error> evalVariable() const override;

private:
    std::string host;
};

class EqualWafTag : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
EqualWafTag(const std::vector<std::string> &params);

    static std::string getName() { return "EqualWafTag"; }

    Maybe<bool, Context::Error> evalVariable() const override;

private:
    std::string waf_tag;
};

class EqualListeningIP : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    EqualListeningIP(const std::vector<std::string> &params);

    static std::string getName() { return "EqualListeningIP"; }

    Maybe<bool, Context::Error> evalVariable() const override;

private:
    IPAddr listening_ip;
};

class EqualListeningPort : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    EqualListeningPort(const std::vector<std::string> &params);

    static std::string getName() { return "EqualListeningPort"; }

    Maybe<bool, Context::Error> evalVariable() const override;

private:
    PortNumber listening_port;
};

class BeginWithUri : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    BeginWithUri(const std::vector<std::string> &params);

    static std::string getName() { return "BeginWithUri"; }

    Maybe<bool, Context::Error> evalVariable() const override;

private:
    std::string uri_prefix;
};

#endif // __HTTP_TRANSACTION_DATA_EVAL_H__

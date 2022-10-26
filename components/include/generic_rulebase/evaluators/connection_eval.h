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

#ifndef __CONNECTION_EVAL_H__
#define __CONNECTION_EVAL_H__

#include "environment/evaluator_templates.h"
#include "i_environment.h"
#include "singleton.h"
#include "connkey.h"

class IpAddressMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    IpAddressMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "ipAddress"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::vector<CustomRange<IPAddr>> values;
};

class SourceIpMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    SourceIpMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "sourceIP"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::vector<CustomRange<IPAddr>> values;
};

class DestinationIpMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    DestinationIpMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "destinationIP"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::vector<CustomRange<IPAddr>> values;
};

class SourcePortMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    SourcePortMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "sourcePort"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::vector<CustomRange<PortNumber>> values;
};

class ListeningPortMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    ListeningPortMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "listeningPort"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::vector<CustomRange<PortNumber>> values;
};

class IpProtocolMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    IpProtocolMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "ipProtocol"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::vector<CustomRange<IPProto>> values;
};

class UrlMatcher : public EnvironmentEvaluator<bool>, Singleton::Consume<I_Environment>
{
public:
    UrlMatcher(const std::vector<std::string> &params);

    static std::string getName() { return "url"; }

    Maybe<bool, Context::Error> evalVariable() const override;

    static std::string ctx_key;

private:
    std::vector<std::string> values;
};

#endif // __CONNECTION_EVAL_H__

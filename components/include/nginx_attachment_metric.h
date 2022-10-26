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

#ifndef __NGINX_ATTACHMENT_METRIC_H__
#define __NGINX_ATTACHMENT_METRIC_H__

#include "generic_metric.h"

class nginxAttachmentEvent : public Event<nginxAttachmentEvent>
{
public:
    enum class networkVerdict {
        REGISTRATION_SUCCESS,
        REGISTRATION_FAIL,
        CONNECTION_FAIL
    };

    enum class trafficVerdict {
        INSPECT,
        ACCEPT,
        DROP,
        INJECT,
        IRRELEVANT,
        RECONF,
        WAIT
    };

    void resetAllCounters();

    void addNetworkingCounter(networkVerdict _verdict);

    void addTrafficVerdictCounter(trafficVerdict _verdict);

    void addResponseInspectionCounter(uint64_t _counter);

    uint64_t getNetworkingCounter(networkVerdict _verdict) const;

    uint64_t getTrafficVerdictCounter(trafficVerdict _verdict) const;

    uint64_t getResponseInspectionCounter() const;

private:
    uint64_t successfull_registrations_counter = 0;
    uint64_t failed_registrations_counter = 0;
    uint64_t failed_connections_counter = 0;
    uint64_t accept_verdict_counter = 0;
    uint64_t inspect_verdict_counter = 0;
    uint64_t drop_verdict_counter = 0;
    uint64_t inject_verdict_counter = 0;
    uint64_t irrelevant_verdict_counter = 0;
    uint64_t reconf_verdict_counter = 0;
    uint64_t response_inspection_counter = 0;
    uint64_t wait_verdict_counter = 0;
};

class nginxAttachmentMetric
        :
    public GenericMetric,
    public Listener<nginxAttachmentEvent>
{
public:
    void upon(const nginxAttachmentEvent &event) override;

private:
    MetricCalculations::Counter successfull_registrations{this, "successfullRegistrationsSum"};
    MetricCalculations::Counter failed_registrations{this, "failedRegistrationsSum"};
    MetricCalculations::Counter failed_connections{this, "failedConnectionsSum"};
    MetricCalculations::Counter inspect_verdict{this, "inspectVerdictSum"};
    MetricCalculations::Counter accept_verdict{this, "acceptVeridctSum"};
    MetricCalculations::Counter drop_verdict{this, "dropVerdictSum"};
    MetricCalculations::Counter inject_verdict{this, "injectVerdictSum"};
    MetricCalculations::Counter irrelevant_verdict{this, "irrelevantVerdictSum"};
    MetricCalculations::Counter reconf_verdict{this, "reconfVerdictSum"};
    MetricCalculations::Counter response_inspection{this, "responseInspection"};
};

#endif // __NGINX_ATTACHMENT_METRIC_H__

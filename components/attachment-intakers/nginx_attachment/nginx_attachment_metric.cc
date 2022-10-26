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

#include "nginx_attachment_metric.h"

USE_DEBUG_FLAG(D_METRICS_NGINX_ATTACHMENT);

void
nginxAttachmentEvent::resetAllCounters()
{
    successfull_registrations_counter = 0;
    failed_registrations_counter = 0;
    failed_connections_counter = 0;
    accept_verdict_counter = 0;
    inspect_verdict_counter = 0;
    drop_verdict_counter = 0;
    inject_verdict_counter = 0;
    irrelevant_verdict_counter = 0;
    reconf_verdict_counter = 0;
    wait_verdict_counter = 0;
}

void
nginxAttachmentEvent::addNetworkingCounter(networkVerdict _verdict)
{
    switch (_verdict) {
        case networkVerdict::REGISTRATION_SUCCESS: {
            successfull_registrations_counter += 1;
            break;
        }
        case networkVerdict::REGISTRATION_FAIL: {
            failed_registrations_counter += 1;
            break;
        }
        case networkVerdict::CONNECTION_FAIL: {
            failed_connections_counter += 1;
            break;
        }
        default:
            dbgWarning(D_METRICS_NGINX_ATTACHMENT) << "Unsupported metric type. Type: " << static_cast<int>(_verdict);
            return;
    }
}

void
nginxAttachmentEvent::addTrafficVerdictCounter(trafficVerdict _verdict)
{
    switch (_verdict) {
        case trafficVerdict::INSPECT: {
            inspect_verdict_counter += 1;
            break;
        }
        case trafficVerdict::ACCEPT: {
            accept_verdict_counter += 1;
            break;
        }
        case trafficVerdict::DROP: {
            drop_verdict_counter += 1;
            break;
        }
        case trafficVerdict::INJECT: {
            inject_verdict_counter += 1;
            break;
        }
        case trafficVerdict::IRRELEVANT: {
            irrelevant_verdict_counter += 1;
            break;
        }
        case trafficVerdict::RECONF: {
            reconf_verdict_counter += 1;
            break;
        }
        case trafficVerdict::WAIT: {
            wait_verdict_counter += 1;
            break;
        }

        default:
            dbgWarning(D_METRICS_NGINX_ATTACHMENT) << "Unsupported metric type. Type: " << static_cast<int>(_verdict);
            return;
    }
}

void
nginxAttachmentEvent::addResponseInspectionCounter(uint64_t _counter)
{
    response_inspection_counter += _counter;
}

uint64_t
nginxAttachmentEvent::getNetworkingCounter(networkVerdict _verdict) const
{
    switch (_verdict) {
        case networkVerdict::REGISTRATION_SUCCESS:
            return successfull_registrations_counter;
        case networkVerdict::REGISTRATION_FAIL:
            return failed_registrations_counter;
        case networkVerdict::CONNECTION_FAIL:
            return failed_connections_counter;
        default:
            dbgWarning(D_METRICS_NGINX_ATTACHMENT) << "Unsupported metric type. Type: " << static_cast<int>(_verdict);
            return 0;
    }
}

uint64_t
nginxAttachmentEvent::getTrafficVerdictCounter(trafficVerdict _verdict) const
{
    switch (_verdict) {
        case trafficVerdict::INSPECT:
            return inspect_verdict_counter;
        case trafficVerdict::ACCEPT:
            return accept_verdict_counter;
        case trafficVerdict::DROP:
            return drop_verdict_counter;
        case trafficVerdict::INJECT:
            return inject_verdict_counter;
        case trafficVerdict::IRRELEVANT:
            return irrelevant_verdict_counter;
        case trafficVerdict::RECONF:
            return reconf_verdict_counter;
        case trafficVerdict::WAIT:
            return wait_verdict_counter;
        default:
            dbgWarning(D_METRICS_NGINX_ATTACHMENT) << "Unsupported metric type. Type: " << static_cast<int>(_verdict);
            return 0;
    }
}

uint64_t
nginxAttachmentEvent::getResponseInspectionCounter() const
{
    return response_inspection_counter;
}

void
nginxAttachmentMetric::upon(const nginxAttachmentEvent &event)
{
    successfull_registrations.report(
        event.getNetworkingCounter(nginxAttachmentEvent::networkVerdict::REGISTRATION_SUCCESS)
    );
    failed_registrations.report(
        event.getNetworkingCounter(nginxAttachmentEvent::networkVerdict::REGISTRATION_FAIL)
    );
    failed_connections.report(event.getNetworkingCounter(nginxAttachmentEvent::networkVerdict::CONNECTION_FAIL));
    inspect_verdict.report(event.getTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::INSPECT));
    accept_verdict.report(event.getTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::ACCEPT));
    drop_verdict.report(event.getTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::DROP));
    inject_verdict.report(event.getTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::INJECT));
    irrelevant_verdict.report(event.getTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::IRRELEVANT));
    reconf_verdict.report(event.getTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::RECONF));
    response_inspection.report(event.getResponseInspectionCounter());
}

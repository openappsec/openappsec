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

#ifndef __WAAP_COMPONENT_IMPL_H__
#define __WAAP_COMPONENT_IMPL_H__

#include "waap.h"
#include "config.h"
#include "table_opaque.h"
#include "i_transaction.h"
#include "waap_clib/DeepAnalyzer.h"
#include "waap_clib/WaapAssetState.h"
#include "waap_clib/WaapAssetStatesManager.h"
#include "reputation_features_agg.h"

// WaapComponent implementation
class WaapComponent::Impl
        :
    public Listener<NewHttpTransactionEvent>,
    public Listener<HttpRequestHeaderEvent>,
    public Listener<HttpRequestBodyEvent>,
    public Listener<EndRequestEvent>,
    public Listener<ResponseCodeEvent>,
    public Listener<HttpResponseHeaderEvent>,
    public Listener<HttpResponseBodyEvent>,
    public Listener<EndTransactionEvent>
{
public:
    explicit Impl();
    virtual ~Impl();

    void init();
    void fini();

    std::string getListenerName() const override;

    EventVerdict respond(const NewHttpTransactionEvent &event) override;
    EventVerdict respond(const HttpRequestHeaderEvent &event) override;
    EventVerdict respond(const HttpRequestBodyEvent &event) override;
    EventVerdict respond(const EndRequestEvent &) override;

    EventVerdict respond(const ResponseCodeEvent &event) override;
    EventVerdict respond(const HttpResponseHeaderEvent &event) override;
    EventVerdict respond(const HttpResponseBodyEvent &event) override;
    EventVerdict respond(const EndTransactionEvent &) override;

private:

    void init(const std::string &waapDataFileName);
    EventVerdict waapDecisionAfterHeaders(IWaf2Transaction& waf2Transaction);
    EventVerdict waapDecision(IWaf2Transaction& waf2Transaction);
    void finishTransaction(IWaf2Transaction& waf2Transaction);

    bool waf2_proc_start(const std::string& waapDataFileName);
    void waf2_proc_exit();
    void validateFirstRequestForAsset(const ReportIS::Severity severity);
    void sendNotificationForFirstRequest(
        const std::string& asset_id,
        const std::string& asset_name,
        const ReportIS::Severity severity
    );

    EventVerdict pending_response;
    EventVerdict accept_response;
    EventVerdict drop_response;
    WaapMetricWrapper waap_metric;
    AssetsMetric assets_metric;
    I_Table* waapStateTable;
    // Count of transactions processed by this WaapComponent instance
    uint64_t transactionsCount;
    // instance of singleton classes
    DeepAnalyzer deepAnalyzer;
    WaapAssetStatesManager waapAssetStatesManager;
    ReputationFeaturesAgg reputationAggregator;
    std::unordered_set<std::string> m_seen_assets_id;
};

#endif // __WAAP_COMPONENT_IMPL_H__

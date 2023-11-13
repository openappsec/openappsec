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

#pragma once

#include "../waap_clib/WaapDecision.h"
#include "../include/WaapDefines.h"
#include "../waap_clib/Csrf.h"
#include "../waap_clib/Waf2Util.h"
#include "../waap_clib/WaapOpenRedirect.h"
#include "../waap_clib/FpMitigation.h"
#include "../waap_clib/DeepParser.h"
#include "http_inspection_events.h"

enum HeaderType {
    UNKNOWN_HEADER,
    HOST_HEADER,
    USER_AGENT_HEADER,
    COOKIE_HEADER,
    REFERER_HEADER,
    CONTENT_TYPE_HEADER,
    CLEAN_HEADER,
    OTHER_KNOWN_HEADERS
};

struct AnalysisResult;
class WaapAssetState;

struct Waf2TransactionFlags {
    bool endResponseHeadersCalled;
    bool requestDataPushStarted;
    bool responseDataPushStarted;

    Waf2TransactionFlags():
        endResponseHeadersCalled(false),
        requestDataPushStarted(false),
        responseDataPushStarted(false)
    {
    }
};

class IWaf2Transaction {
public:
    virtual ~IWaf2Transaction() {}
    virtual uint64_t getIndex() const = 0;
    virtual void setIndex(uint64_t index) = 0;
    virtual std::shared_ptr<WaapAssetState> getAssetState() = 0;
    virtual IWaapConfig* getSiteConfig() = 0;
    virtual DeepParser& getDeepParser() = 0;
    virtual bool get_ignoreScore() const = 0;
    virtual void addNote(const std::string &note) = 0;
    virtual bool shouldIgnoreOverride(const Waf2ScanResult &res) = 0;
    virtual bool reportScanResult(const Waf2ScanResult &res) = 0;
    virtual const std::string getHost() const = 0;
    virtual Waap::OpenRedirect::State &getOpenRedirectState() = 0;
    virtual const std::string getLocation() const = 0;
    virtual const std::string getUserAgent() const = 0;
    virtual const std::string getParam() const = 0;
    virtual const std::vector<std::string> getKeywordMatches() const = 0;
    virtual const std::vector<std::string> getKeywordsCombinations() const = 0;
    virtual const std::string getContentTypeStr() const = 0;
    virtual Waap::Util::ContentType getContentType() const = 0;
    virtual const std::string getKeywordMatchesStr() const = 0;
    virtual const std::string getSample() const = 0;
    virtual const std::string getLastScanSample() const = 0;
    virtual const std::string& getLastScanParamName() const = 0;
    virtual const std::string getMethod() const = 0;
    virtual const std::string getHdrContent(std::string hdrName) const = 0;
    virtual const WaapDecision &getWaapDecision() const = 0;
    virtual const std::string& getRemoteAddr() const = 0;
    virtual const std::string getUri() const = 0;
    virtual const std::string getUriStr() const = 0;
    virtual const std::string& getSourceIdentifier() const = 0;
    virtual double getScore() const = 0;
    virtual const std::vector<double> getScoreArray() const = 0;
    virtual Waap::CSRF::State& getCsrfState() = 0;
    virtual ngx_http_cp_verdict_e getUserLimitVerdict() = 0;
    virtual const std::string getUserLimitVerdictStr() const = 0;
    virtual const std::string getViolatedUserLimitTypeStr() const = 0;
    virtual void checkShouldInject() = 0;
    virtual void completeInjectionResponseBody(std::string& strInjection) = 0;
    virtual void sendLog() = 0;
    virtual bool decideAfterHeaders() = 0;
    virtual int decideFinal(
        int mode,
        AnalysisResult &transactionResult,
        const std::string &poolName=KEYWORDS_SCORE_POOL_BASE,
        PolicyCounterType fpClassification = UNKNOWN_TYPE) = 0;
    virtual bool decideResponse() = 0;
    virtual void clearAllInjectionReasons() = 0;
    virtual bool shouldInspectResponse() = 0;
    virtual bool shouldInjectResponse() = 0;
    virtual bool shouldInjectCSRF() = 0;
    virtual bool shouldInjectSecurityHeaders() = 0;
    virtual void handleSecurityHeadersInjection(
        std::vector<std::pair<std::string, std::string>>& injectHeaderStrs) = 0;
    virtual void disableShouldInjectSecurityHeaders() = 0;
    virtual void handleCsrfHeaderInjection(std::string& injectStr) = 0;
    virtual bool findHtmlTagToInject(const char* data, int data_len, int& pos) = 0;
    virtual bool isHtmlType(const char* data, int data_len) = 0;

    virtual HeaderType detectHeaderType(const char* name, int name_len) = 0;

    virtual void start() = 0;
    virtual void set_transaction_time(const char* log_time) = 0;
    virtual void set_transaction_remote(const char* remote_addr, int remote_port) = 0;
    virtual void set_transaction_local(const char* local_addr, int local_port) = 0;

    // Request
    virtual void set_method(const char* method) = 0;
    virtual void set_uri(const char* uri) = 0;
    virtual void start_request_hdrs() = 0;
    virtual void add_request_hdr(const char* name, int name_len, const char* value, int value_len) = 0;
    virtual void end_request_hdrs() = 0;
    virtual void start_request_body() = 0;
    virtual void add_request_body_chunk(const char* data, int data_len) = 0;
    virtual void end_request_body() = 0;
    virtual void end_request() = 0;
    // Response
    virtual void start_response(int response_status, int http_version) = 0;
    virtual void start_response_hdrs() = 0;
    virtual void add_response_hdr(const char* name, int name_len, const char* value, int value_len) = 0;
    virtual void end_response_hdrs() = 0;
    virtual void start_response_body() = 0;
    virtual void add_response_body_chunk(const char* data, int data_len) = 0;
    virtual void end_response_body() = 0;
    virtual void end_response() = 0;

    virtual void collectFoundPatterns() = 0;
    virtual ReportIS::Severity computeEventSeverityFromDecision() const = 0;
    virtual void finish() = 0;
    virtual Waf2TransactionFlags &getTransactionFlags() = 0;
};

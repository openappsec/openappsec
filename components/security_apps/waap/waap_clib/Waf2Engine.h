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

#ifndef __WAF2_TRANSACTION_H__99e4201a
#define __WAF2_TRANSACTION_H__99e4201a

#include "Csrf.h"
#include "UserLimitsPolicy.h"
#include "ParserBase.h"
#include "DeepParser.h"
#include "WaapAssetState.h"
#include "PatternMatcher.h"
#include "Waf2Util.h"
#include "WaapConfigApplication.h"
#include "WaapConfigApi.h"
#include "WaapDecision.h"
#include "DeepAnalyzer.h"
#include <vector>
#include <map>
#include <string>
#include <set>
#include <utility>
#include <memory>
#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // uuid generators
#include <boost/tokenizer.hpp>
#include <boost/noncopyable.hpp>
#include "i_transaction.h"
#include "i_waap_telemetry.h"
#include "i_deepAnalyzer.h"
#include "table_opaque.h"
#include "WaapResponseInspectReasons.h"
#include "WaapResponseInjectReasons.h"
#include "WaapOpenRedirect.h"
#include "WaapOpenRedirectPolicy.h"
#include "WaapScanner.h"
#include "singleton.h"

struct DecisionTelemetryData;
class Waf2Transaction;

// Callback that is called upon completion of next sub transaction
typedef void(*subtransaction_cb_t)(Waf2Transaction* subTransaction, void *ctx);
#define OVERRIDE_ACCEPT "Accept"
#define OVERRIDE_DROP "Drop"

class Waf2Transaction :
    public  IWaf2Transaction,
    public  TableOpaqueSerialize<Waf2Transaction>,
    public  Singleton::Consume<I_Table>,
    private boost::noncopyable,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_Environment>
{
public:
    Waf2Transaction(std::shared_ptr<WaapAssetState> pWaapAssetState);
    Waf2Transaction();
    ~Waf2Transaction();

    // setters
    void set_transaction_time(const char *log_time);
    void set_transaction_remote(const char *remote_addr, int remote_port);
    void set_transaction_local(const char *local_addr, int local_port);
    void set_method(const char *method);
    void set_uri(const char *uri);
    void set_host(const char *host);

    // getters
    const std::string& getRemoteAddr() const;
    virtual const std::string getUri() const;
    const std::string getUriStr() const;
    const std::string& getSourceIdentifier() const;
    virtual const std::string getUserAgent() const;
    const std::string getParam() const;
    const std::string getParamKey() const;
    const std::vector<std::string> getKeywordMatches() const;
    const std::vector<std::string> getFilteredKeywords() const;
    const std::map<std::string, std::vector<std::string>> getFilteredVerbose() const;
    virtual const std::vector<std::string> getKeywordsCombinations() const;
    const std::vector<DeepParser::KeywordInfo>& getKeywordInfo() const;
    const std::vector<std::pair<std::string, std::string> >& getKvPairs() const;
    const std::string getKeywordMatchesStr() const;
    const std::string getFilteredKeywordsStr() const;
    const std::string getSample() const;
    const std::string getLastScanSample() const;
    virtual const std::string& getLastScanParamName() const;
    double getScore() const;
    const std::vector<double> getScoreArray() const;
    Waap::CSRF::State& getCsrfState();
    const std::set<std::string> getFoundPatterns() const;
    const std::string getContentTypeStr() const;
    Waap::Util::ContentType getContentType() const;
    int getRemotePort() const;
    const std::string getLocalAddress() const;
    int getLocalPort() const;
    const std::string getLogTime() const;
    ParserBase* getRequestBodyParser();
    const std::string getMethod() const;
    const std::string getHost() const;
    const std::string getCookie() const;
    const std::vector<std::string> getNotes() const;
    DeepParser& getDeepParser();
    std::vector<std::pair<std::string, std::string> > getHdrPairs() const;
    virtual const std::string getHdrContent(std::string hdrName) const;
    const std::string getRequestBody() const;
    const std::string getTransactionIdStr() const;
    const WaapDecision &getWaapDecision() const;
    virtual std::shared_ptr<WaapAssetState> getAssetState();
    virtual const std::string getLocation() const;

    ngx_http_cp_verdict_e getUserLimitVerdict();
    const std::string getUserLimitVerdictStr() const;
    const std::string getViolatedUserLimitTypeStr() const;

    virtual HeaderType detectHeaderType(const char* name, int name_len);
    HeaderType checkCleanHeader(const char* name, int name_len, const char* value, int value_len) const;

    // flow control
    void start();

    void start_request_hdrs();
    void add_request_hdr(const char *name, int name_len, const char *value, int value_len);
    void end_request_hdrs();
    void start_request_body();
    void add_request_body_chunk(const char *data, int data_len);
    void end_request_body();
    void end_request();

    void start_response(int response_status, int http_version);
    void start_response_hdrs();
    void add_response_hdr(const char* name, int name_len, const char* value, int value_len);
    void end_response_hdrs();
    void start_response_body();
    void add_response_body_chunk(const char* data, int data_len);
    void end_response_body();
    void end_response();
    void extractEnvSourceIdentifier();
    void finish();
    Waf2TransactionFlags &getTransactionFlags();

    // inject function
    void checkShouldInject();
    void completeInjectionResponseBody(std::string& strInjection);
    bool findHtmlTagToInject(const char* data, int data_len, int& pos);
    bool isHtmlType(const char* data, int data_len);

    // decision functions
    void set_ignoreScore(bool ignoreScore);
    bool get_ignoreScore() const { return m_ignoreScore; }
    void decide(
        bool& bForceBlock,
        bool& bForceException,
        int mode);
    bool decideAfterHeaders();
    int decideFinal(
        int mode,
        AnalysisResult &transactionResult,
        const std::string &poolName = KEYWORDS_SCORE_POOL_BASE,
        PolicyCounterType fpClassification = UNKNOWN_TYPE);
    bool decideAutonomousSecurity(
        const IWaapConfig& config,
        int mode,
        bool afterHeaders,
        AnalysisResult &transactionResult,
        const std::string &poolName,
        PolicyCounterType fpClassification = UNKNOWN_TYPE);
    bool decideResponse();
    void clearAllInjectionReasons();
    bool shouldInspectResponse();
    bool shouldInjectResponse();
    bool shouldInjectCSRF();
    bool shouldInjectSecurityHeaders();
    void handleCsrfHeaderInjection(std::string& injectStr);
    void handleSecurityHeadersInjection(std::vector<std::pair<std::string, std::string>>& injectHeaderStrs);
    void disableShouldInjectSecurityHeaders();

    bool shouldSendExtendedLog(const std::shared_ptr<Waap::Trigger::Log> &trigger_log) const;

    // query
    virtual bool isSuspicious() const;
    virtual uint64_t getIndex() const;
    virtual void setIndex(uint64_t index);

    //misc
    void sendLog();
    const std::string logHeadersStr() const;
    void learnScore(ScoreBuilderData& data, const std::string &poolName);
    const std::string buildAttackTypes() const;
    void collectFoundPatterns();
    ReportIS::Severity computeEventSeverityFromDecision() const;

    // LCOV_EXCL_START - sync functions, can only be tested once the sync module exists

    static std::string name() { return "Waf2Transaction"; };
    static std::unique_ptr<TableOpaqueBase> prototype() { return std::make_unique<Waf2Transaction>(); };
    static uint currVer() { return 0; }
    static uint minVer() { return 0; }

    template <typename T>
    void serialize(T& ar, uint) {
        ar(0);
    }

    // LCOV_EXCL_STOP

    bool reportScanResult(const Waf2ScanResult &res);
    bool shouldIgnoreOverride(const Waf2ScanResult &res);
    Waap::OpenRedirect::State &getOpenRedirectState() { return m_openRedirectState; }
    IWaapConfig* getSiteConfig() { return m_siteConfig; }
    void addNote(const std::string &note) { m_notes.push_back(note); }
    const std::string &getResponseBody(void) const { return m_response_body; }
    Waap::ResponseInspectReasons &getResponseInspectReasons(void) { return m_responseInspectReasons; }

private:
    int finalizeDecision(IWaapConfig *sitePolicy, bool shouldBlock);
    const std::shared_ptr<Waap::Trigger::Log> getTriggerLog(const std::shared_ptr<Waap::Trigger::Policy>&
        triggerPolicy) const;
    void sendAutonomousSecurityLog(
        const std::shared_ptr<Waap::Trigger::Log>& triggerLog,
        bool shouldBlock,
        const std::string& logOverride,
        const std::string& attackTypes) const;
    void appendCommonLogFields(LogGen& waapLog,
        const std::shared_ptr<Waap::Trigger::Log> &triggerLog,
        bool shouldBlock,
        const std::string& logOverride,
        const std::string& incidentType) const;
    std::string getUserReputationStr(double relativeReputation) const;
    bool isTrustedSource() const;


    void setCurrentAssetState(IWaapConfig* sitePolicy);
    bool setCurrentAssetContext();
    bool checkIsScanningRequired();
    Waap::Override::State getOverrideState(IWaapConfig* sitePolicy);

    // User limits functions
    void createUserLimitsState();
    bool isUrlLimitReached(size_t size);
    bool isHttpHeaderLimitReached(const std::string& name, const std::string& value);
    bool isHttpBodyLimitReached(size_t chunkSize);
    bool isObjectDepthLimitReached(size_t depth);
    bool isPreventModeValidMethod(const std::string& method);
    bool isUserLimitReached() const;
    bool isIllegalMethodViolation() const;
    const Waap::UserLimits::ViolatedStrData& getViolatedUserLimitStrData() const;
    size_t getViolatingUserLimitSize() const;

    // Internal
    void processUri(const std::string &uri, const std::string &scanStage);
    void parseContentType(const char* value, int value_len);
    void parseCookie(const char* value, int value_len);
    void parseReferer(const char* value, int value_len);
    void parseUnknownHeaderName(const char* name, int name_len);
    void parseGenericHeaderValue(const std::string &headerName, const char* value, int value_len);
    void scanSpecificHeder(const char* name, int name_len, const char* value, int value_len);
    void detectSpecificHeader(const char* name, int name_len, const char* value, int value_len);
    void detectHeaders();
    void scanHeaders();
    void clearRequestParserState();
    void scanErrDisclosureBuffer();

    std::shared_ptr<WaapAssetState> m_pWaapAssetState;
    bool m_ignoreScore; // override the scoring filter and (effectively) take the last suspicious parameter,
                        // instead of the one with highest score that is > SCORE_THRESHOLD
    boost::uuids::uuid m_transaction_id;
    std::string m_log_time;
    std::string m_remote_addr;
    std::string m_source_identifier;
    int m_remote_port;
    std::string m_local_addr;
    int m_local_port;

    // Matched override IDs
    std::set<std::string> m_matchedOverrideIds;
    std::set<std::string> m_effectiveOverrideIds;

    //csrf state
    Waap::CSRF::State m_csrfState;
    // UserLimits state
    std::shared_ptr<Waap::UserLimits::State> m_userLimitsState;

    WaapConfigAPI m_ngenAPIConfig;
    WaapConfigApplication m_ngenSiteConfig;
    IWaapConfig* m_siteConfig;

    // Current content type and (for multiplart), MIME boundary identifier
    Waap::Util::ContentType m_contentType;

    // Request body parser, type is derived from headers/ContentType.
    // May be NULL if request payload is of unknown type!
    ParserBase *m_requestBodyParser;

    // find <head> html tag
    char m_tagHist[6]; // strlen("<head>")
    size_t m_tagHistPos;
    bool m_isUrlValid;

    Waap::Scanner m_scanner;    // Receives the param+value pairs from DeepParser and scans them
    DeepParser m_deepParser;    // recursive (deep) parser that can parse deep content encodings
                                // hierarchies like XML in JSON in URLEncode in ...
    BufferedReceiver m_deepParserReceiver; // buffered receiver forwarding to m_deepParser
    Waf2ScanResult *m_scanResult;

    std::string m_methodStr;
    std::string m_uriStr;
    std::string m_uriPath;
    std::string m_uriReferer;
    std::string m_uriQuery;
    std::string m_contentTypeStr;
    std::string m_hostStr;
    std::string m_userAgentStr;
    std::string m_cookieStr;
    std::vector<std::string> m_notes;
    std::set<std::string> m_found_patterns;

    Waap::OpenRedirect::State m_openRedirectState;
    std::map<std::string, std::string> hdrs_map;
    std::string m_request_body;
    std::string m_response_body;
    std::string m_response_body_err_disclosure;
    size_t m_request_body_bytes_received;
    size_t m_response_body_bytes_received;

    bool m_processedUri;
    bool m_processedHeaders;
    bool m_isScanningRequired;
    int m_responseStatus;
    Waap::ResponseInspectReasons m_responseInspectReasons;
    Waap::ResponseInjectReasons m_responseInjectReasons;
    WaapDecision m_waapDecision;
    Waap::Override::State m_overrideState;

    uint64_t m_index;

    // Cached pointer to const triggerLog (hence mutable)
    mutable std::shared_ptr<Waap::Trigger::Log> m_triggerLog;
    Waf2TransactionFlags m_waf2TransactionFlags;

    // Grace period for logging
    int max_grace_logs;
    bool is_hybrid_mode = false;
};

#endif // __WAF2_TRANSACTION_H__99e4201a

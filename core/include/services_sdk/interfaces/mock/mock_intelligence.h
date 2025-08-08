#ifndef __MOCK_INTELLIGENCE_H__
#define __MOCK_INTELLIGENCE_H__

#include "i_intelligence_is_v2.h"
#include "cptest.h"

std::ostream &
operator<<(std::ostream &os, const Intelligence::Response &)
{
    return os;
}

std::ostream &
operator<<(std::ostream &os, const Intelligence::Invalidation &)
{
    return os;
}

std::ostream &
operator<<(std::ostream &os, const std::vector<Intelligence::Invalidation> &)
{
    return os;
}

class MockIntelligence : public Singleton::Provide<I_Intelligence_IS_V2>::From<MockProvider<I_Intelligence_IS_V2>>
{
public:
    using InvalidationCb = std::function<void(const Intelligence::Invalidation &)>;
    using Invalidation = Intelligence::Invalidation;
    using Response = Intelligence::Response;
    using TimeRangeInvalidations = Intelligence::TimeRangeInvalidations;

    MOCK_CONST_METHOD1(sendInvalidation, bool(const Invalidation &invalidation));
    MOCK_CONST_METHOD1(getInvalidations, Maybe<std::vector<Invalidation>>(TimeRangeInvalidations));
    MOCK_CONST_METHOD0(isIntelligenceHealthy, bool(void));
    MOCK_METHOD3(
        registerInvalidation,
        Maybe<uint>(
            const Invalidation &invalidation,
            const InvalidationCb &callback,
            const std::string &AgentId
        )
    );
    MOCK_METHOD1(unregisterInvalidation, void(uint id));
    MOCK_CONST_METHOD5(
        getResponse,
        Maybe<Response>(
            const std::vector<QueryRequest> &query_requests,
            bool is_pretty,
            bool is_bulk,
            bool is_proxy,
            const MessageMetadata &req_md
        )
    );
    MOCK_CONST_METHOD4(
        getResponse,
        Maybe<Response>(
            const QueryRequest &query_request,
            bool is_pretty,
            bool is_proxy,
            const MessageMetadata &req_md
        )
    );
    MOCK_CONST_METHOD0(getIsOfflineOnly, bool(void));
};

#endif // __MOCK_INTELLIGENCE_H__

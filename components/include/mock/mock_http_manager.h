#ifndef __MOCK_HTTP_MANAGER_H__
#define __MOCK_HTTP_MANAGER_H__

#include "i_http_manager.h"
#include "cptest.h"

class MockHttpManager : public Singleton::Provide<I_HttpManager>::From<MockProvider<I_HttpManager>>
{
public:
    MOCK_METHOD1(inspect, FilterVerdict(const HttpTransactionData &));
    MOCK_METHOD2(inspect, FilterVerdict(const HttpHeader &, bool is_request));
    MOCK_METHOD2(inspect, FilterVerdict(const HttpBody &, bool is_request));
    MOCK_METHOD0(inspectEndRequest, FilterVerdict());
    MOCK_METHOD1(inspect, FilterVerdict(const ResponseCode &));
    MOCK_METHOD0(inspectEndTransaction, FilterVerdict());
    MOCK_METHOD0(inspectDelayedVerdict, FilterVerdict());
};

#endif // __MOCK_HTTP_MANAGER_H__

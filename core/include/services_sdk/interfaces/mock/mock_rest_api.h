#ifndef __MOCK_REST_API_H__
#define __MOCK_REST_API_H__

#include "i_rest_api.h"
#include "cptest.h"
#include "singleton.h"

class MockRestApi : public Singleton::Provide<I_RestApi>::From<MockProvider<I_RestApi>>
{
public:
    MOCK_CONST_METHOD0(getListeningPort, uint16_t());
    // You can't mock a function with an R-value reference. So mock a slightly different one
    MOCK_METHOD3(mockRestCall, bool(RestAction, const std::string &, const std::unique_ptr<RestInit> &));

    bool
    addRestCall(RestAction oper, const std::string &uri, std::unique_ptr<RestInit> &&init)
    {
        return mockRestCall(oper, uri, init);
    }
};


#endif // __MOCK_REST_API_H__

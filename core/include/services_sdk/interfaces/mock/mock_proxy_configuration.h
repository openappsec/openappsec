#ifndef __MOCK_PROXY_CONFIGURATION_H__
#define __MOCK_PROXY_CONFIGURATION_H__

#include "i_proxy_configuration.h"

#include "cptest.h"

class MockProxyConfiguration
        :
    public Singleton::Provide<I_ProxyConfiguration>::From<MockProvider<I_ProxyConfiguration>>
{
public:
    using string = std::string;

    MOCK_CONST_METHOD1(getProxyDomain, Maybe<std::string>(ProxyProtocol protocol));
    MOCK_CONST_METHOD1(getProxyAuthentication, Maybe<std::string>(ProxyProtocol protocol));
    MOCK_CONST_METHOD1(getProxyPort, Maybe<uint16_t>(ProxyProtocol protocol));
    MOCK_CONST_METHOD1(getProxyExists, bool(ProxyProtocol protocol));
    MOCK_CONST_METHOD1(getProxyAddress, Maybe<std::string>(ProxyProtocol protocol));
    MOCK_METHOD0(loadProxy, Maybe<void>());
};

#endif // __MOCK_PROXY_CONFIGURATION_H__

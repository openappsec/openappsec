#ifndef __MOCK_MESSAGING_CONNECTION_H__
#define __MOCK_MESSAGING_CONNECTION_H__

#include "cptest.h"
#include "interfaces/i_messaging_connection.h"

// LCOV_EXCL_START Reason: No need to test mocks

class MockMessagingConnection :
    public Singleton::Provide<I_MessagingConnection>::From<MockProvider<I_MessagingConnection>>
{
public:
    using string = std::string;

    MOCK_METHOD2(establishConnection, Maybe<Connection>(const MessageMetadata &, MessageCategory));

    MOCK_METHOD3(
        establishNewConnection,
        Maybe<Connection>(MessageConnectionKey, Flags<MessageConnectionConfig>, const string &)
    );

    MOCK_METHOD2(establishNewProxyConnection, Maybe<Connection>(Flags<MessageConnectionConfig>, MessageProxySettings));

    Maybe<HTTPResponse, HTTPResponse>
    sendRequest(Connection &conn, HTTPRequest req)
    {
        return mockSendRequest(conn, req, false);
    }

    MOCK_METHOD3(mockSendRequest, Maybe<HTTPResponse, HTTPResponse>(Connection &, HTTPRequest, bool));

    MOCK_METHOD3(getPersistentConnection, Maybe<Connection>(const string &, uint16_t, MessageCategory));
    MOCK_METHOD1(getFogConnectionByCategory, Maybe<Connection>(MessageCategory));
};

// LCOV_EXCL_STOP

#endif // __MOCK_MESSAGING_CONNECTION_H__

#ifndef __MOCK_MESSAGING_H__
#define __MOCK_MESSAGING_H__

#include "i_messaging.h"
#include "cptest.h"

class MockMessaging : public Singleton::Provide<I_Messaging>::From<MockProvider<I_Messaging>>
{
public:
    using string = std::string;
    MOCK_METHOD5(
        sendSyncMessage,
        Maybe<HTTPResponse, HTTPResponse> (
            HTTPMethod,
            const string &,
            const string &,
            MessageCategory,
            MessageMetadata
        )
    );
    MOCK_METHOD6(
        sendAsyncMessage,
        void (
            HTTPMethod,
            const string &,
            const string &,
            MessageCategory,
            const MessageMetadata &,
            bool
        )
    );

    MOCK_METHOD5(
        downloadFile,
        Maybe<HTTPStatusCode, HTTPResponse> (
            HTTPMethod,
            const string &,
            const string &,
            MessageCategory,
            MessageMetadata
        )
    );

    MOCK_METHOD4(
        uploadFile,
        Maybe<HTTPStatusCode, HTTPResponse> (
            const string &,
            const string &,
            MessageCategory,
            MessageMetadata
        )
    );

    MOCK_METHOD4(setFogConnection, bool(const string &, uint16_t, bool, MessageCategory));
    MOCK_METHOD0(setFogConnection, bool());
    MOCK_METHOD1(setFogConnection, bool(MessageCategory));
};

static std::ostream &
operator<<(std::ostream &os, const HTTPResponse &)
{
    return os;
}

static std::ostream &
operator<<(std::ostream &os, const HTTPStatusCode &)
{
    return os;
}

#endif // __MOCK_MESSAGING_H__

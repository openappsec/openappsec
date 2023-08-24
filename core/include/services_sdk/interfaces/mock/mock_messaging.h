#ifndef __MOCK_MESSAGING_H__
#define __MOCK_MESSAGING_H__

#include "i_messaging.h"

#include "cptest.h"
class MockMessaging : public Singleton::Provide<I_Messaging>::From<MockProvider<I_Messaging>>
{
public:
    using string = std::string;
    MOCK_METHOD10(
        sendMessage,
        Maybe<string> (
            bool,
            const string &,
            Method,
            const string &,
            uint16_t,
            Flags<MessageConnConfig> &,
            const string &,
            const string &,
            I_Messaging::ErrorCB,
            MessageTypeTag
        )
    );

    MOCK_METHOD7(
        mockSendPersistentMessage,
        Maybe<string>(bool, const string &, Method, const string &, const string &, bool, MessageTypeTag)
    );

    Maybe<string>
    sendPersistentMessage(
        bool get_reply,
        const string &&body,
        Method method,
        const string &url,
        const string &headers,
        bool should_yield,
        MessageTypeTag tag,
        bool)
    {
        return mockSendPersistentMessage(get_reply, body, method, url, headers, should_yield, tag);
    }

    MOCK_METHOD8(
        sendMessage,
        Maybe<string> (
            bool,
            const string &,
            Method,
            const string &,
            const string &,
            I_Messaging::ErrorCB,
            bool,
            MessageTypeTag
        )
    );

    MOCK_METHOD0(setActiveFog,      bool());
    MOCK_METHOD1(setActiveFog,      bool(MessageTypeTag));
    MOCK_METHOD0(unsetFogProxy,     void());
    MOCK_METHOD0(loadFogProxy,      void());
    MOCK_METHOD4(setActiveFog,      bool(const string &, const uint16_t, const bool, MessageTypeTag));

};

#endif // __MOCK_MESSAGING_H__

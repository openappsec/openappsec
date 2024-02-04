#ifndef __MOCK_MESSAGING_BUFFER_H__
#define __MOCK_MESSAGING_BUFFER_H__

#include "cptest.h"
#include "interfaces/i_messaging_buffer.h"

// LCOV_EXCL_START Reason: No need to test mocks

class MockMessagingBuffer : public Singleton::Provide<I_MessageBuffer>::From<MockProvider<I_MessageBuffer>>
{
public:
    using string = std::string;
    MOCK_METHOD6(
        pushNewBufferedMessage,
        void(const std::string &, HTTPMethod, const std::string &, MessageCategory, MessageMetadata, bool)
    );

    MOCK_METHOD0(peekMessage, Maybe<BufferedMessage>());
    MOCK_METHOD0(popMessage, void());
    MOCK_METHOD0(cleanBuffer, void());
};

// LCOV_EXCL_STOP

#endif // __MOCK_MESSAGING_BUFFER_H__

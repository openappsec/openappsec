#ifndef __MOCK_LOGGING_H__
#define __MOCK_LOGGING_H__

#include "i_logging.h"
#include "cptest.h"
#include "common.h"

class MockLogging : public Singleton::Provide<I_Logging>::From<MockProvider<I_Logging>>
{
public:
    MOCK_METHOD1(sendLog, void (const Report &));
    MOCK_METHOD1(addStream, bool (ReportIS::StreamType));
    MOCK_METHOD3(addStream, bool (ReportIS::StreamType, const std::string &, const std::string &));
    MOCK_METHOD1(delStream, bool (ReportIS::StreamType));
    MOCK_METHOD0(getCurrentLogId, uint64_t ());
    MOCK_METHOD1(addGeneralModifier, void (const GeneralModifier &));
};

#endif // __MOCK_LOGGING_H__

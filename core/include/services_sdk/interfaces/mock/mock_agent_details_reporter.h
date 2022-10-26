#ifndef __MOCK_AGENT_DETAILS_REPORTER_H__
#define __MOCK_AGENT_DETAILS_REPORTER_H__

#include <string>

#include "i_agent_details_reporter.h"
#include "cptest.h"


class MockAgenetDetailsReporter
        :
    public Singleton::Provide<I_AgentDetailsReporter>::From<MockProvider<I_AgentDetailsReporter>>
{
public:
    MOCK_METHOD5(
        sendReport,
        void(
            const metaDataReport &,
            const Maybe<std::string> &,
            const Maybe<std::string> &,
            const Maybe<std::string> &,
            const Maybe<std::string> &
        )
    );

    MOCK_METHOD3(addAttr, bool(const std::string &key, const std::string &val, bool allow_override));
    MOCK_METHOD2(addAttr, bool(const std::map<std::string, std::string> &attr, bool allow_override));
    MOCK_METHOD1(deleteAttr, void(const std::string &key));
    MOCK_METHOD0(sendAttributes, bool());
};

#endif // __MOCK_AGENT_DETAILS_REPORTER_H__

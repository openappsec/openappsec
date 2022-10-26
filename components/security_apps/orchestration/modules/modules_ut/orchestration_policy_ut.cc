#include "orchestration_policy.h"

#include <string>
#include <memory>

#include "cptest.h"
#include "cereal/types/string.hpp"

using namespace testing;
using namespace std;

class PolicyTest : public Test
{
public:
    PolicyTest() {}

    void
    orchestrationPolicyToString(stringstream &string_stream)
    {
        cereal::JSONInputArchive archive_in(string_stream);
        orchestration_policy.serialize(archive_in);
    }

    OrchestrationPolicy orchestration_policy;
};

TEST_F(PolicyTest, doNothing)
{
}

TEST_F(PolicyTest, serialization)
{
    stringstream string_stream;
    string_stream <<    "{"
                        "   \"fog-address\": \"http://10.0.0.18:81/control/\","
                        "   \"agent-type\": \"13324sadsd2\","
                        "   \"pulling-interval\": 20,"
                        "   \"error-pulling-interval\": 15"
                        "}";
    try {
        orchestrationPolicyToString(string_stream);
    } catch (cereal::Exception &e) {
        ASSERT_TRUE(false) << "Cereal threw an exception: " << e.what();
    }

    EXPECT_EQ(15u, orchestration_policy.getErrorSleepInterval());
    EXPECT_EQ(20u, orchestration_policy.getSleepInterval());
    EXPECT_EQ("http://10.0.0.18:81/control/", orchestration_policy.getFogAddress());
}

TEST_F(PolicyTest, noAgentType)
{
    stringstream string_stream;
    string_stream <<    "{"
                        "   \"fog-address\": \"http://10.0.0.18:81/control/\","
                        "   \"agent-type\": \"\","
                        "   \"pulling-interval\": 20,"
                        "   \"error-pulling-interval\": 15"
                        "}";
    try {
        orchestrationPolicyToString(string_stream);
    } catch (cereal::Exception &e) {
        ASSERT_TRUE(false) << "Cereal threw an exception: " << e.what();
    }

    EXPECT_EQ(15u, orchestration_policy.getErrorSleepInterval());
    EXPECT_EQ(20u, orchestration_policy.getSleepInterval());
    EXPECT_EQ("http://10.0.0.18:81/control/", orchestration_policy.getFogAddress());
}

TEST_F(PolicyTest, zeroSleepIntervels)
{
    stringstream string_stream;
    string_stream <<    "{"
                        "   \"fog-address\": \"http://10.0.0.18:81/control/\","
                        "   \"agent-type\": \"13324sadsd2\","
                        "   \"pulling-interval\": 0,"
                        "   \"error-pulling-interval\": 0"
                        "}";
    try {
        orchestrationPolicyToString(string_stream);
    } catch (cereal::Exception &e) {
        ASSERT_TRUE(false) << "Cereal threw an exception: " << e.what();
    }

    EXPECT_EQ(0u, orchestration_policy.getErrorSleepInterval());
    EXPECT_EQ(0u, orchestration_policy.getSleepInterval());
    EXPECT_EQ("http://10.0.0.18:81/control/", orchestration_policy.getFogAddress());
}

TEST_F(PolicyTest, operatorEqual)
{
    stringstream string_stream;
    string_stream <<    "{"
                        "   \"fog-address\": \"http://10.0.0.18:81/control/\","
                        "   \"pulling-interval\": 20,"
                        "   \"error-pulling-interval\": 15"
                        "}";
    try {
        orchestrationPolicyToString(string_stream);
    } catch (cereal::Exception &e) {
        ASSERT_TRUE(false) << "Cereal threw an exception: " << e.what();
    }

    OrchestrationPolicy orchestration_copy_policy;
    stringstream string_stream_copy;
    string_stream_copy <<    "{"
                        "   \"fog-address\": \"http://10.0.0.18:81/control/\","
                        "   \"pulling-interval\": 20,"
                        "   \"error-pulling-interval\": 15"
                        "}";
    try{
        cereal::JSONInputArchive archive_in(string_stream_copy);
        orchestration_copy_policy.serialize(archive_in);
    } catch (cereal::Exception &e) {
        ASSERT_TRUE(false) << "Cereal threw an exception: " << e.what();
    }
    EXPECT_TRUE(orchestration_copy_policy == orchestration_policy);
    EXPECT_FALSE(orchestration_copy_policy != orchestration_policy);

    OrchestrationPolicy orchestration_new_policy;
    stringstream string_stream_new;
    string_stream_new <<    "{"
                        "   \"fog-address\": \"http://10.0.0.18:801/control/\","
                        "   \"pulling-interval\": 20,"
                        "   \"error-pulling-interval\": 15"
                        "}";
    try{
        cereal::JSONInputArchive archive_in(string_stream_new);
        orchestration_new_policy.serialize(archive_in);
    } catch (cereal::Exception &e) {
        ASSERT_TRUE(false)  << "Cereal threw an exception: " << e.what();
    }
    EXPECT_FALSE(orchestration_new_policy == orchestration_policy);
    EXPECT_TRUE(orchestration_new_policy != orchestration_policy);
}


TEST_F(PolicyTest, newOptionalFields)
{
    stringstream string_stream;
    string_stream <<    "{"
                        "  \"fog-address\": \"https://fog-api-gw-agents.cloud.ngen.checkpoint.com\","
                        "  \"pulling-interval\": 30,"
                        "  \"error-pulling-interval\": 10,"
                        "  \"agent-type\": \"arrow\""
                        "}";

    try {
        orchestrationPolicyToString(string_stream);
    } catch (cereal::Exception &e) {
        ASSERT_TRUE(false) << "Cereal threw an exception: " << e.what();
    }

    EXPECT_EQ(10u, orchestration_policy.getErrorSleepInterval());
    EXPECT_EQ(30u, orchestration_policy.getSleepInterval());
    EXPECT_EQ("https://fog-api-gw-agents.cloud.ngen.checkpoint.com", orchestration_policy.getFogAddress());
}

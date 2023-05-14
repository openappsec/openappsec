#include "ips_configuration.h"
#include "cptest.h"

TEST(configuration, basic_context)
{
    cptestPrepareToDie();

    IPSConfiguration::Context ctx1(IPSConfiguration::ContextType::HISTORY, 254);
    EXPECT_EQ(ctx1.getType(), IPSConfiguration::ContextType::HISTORY);
    EXPECT_EQ(ctx1.getHistorySize(), 254);

    IPSConfiguration::Context ctx2(IPSConfiguration::ContextType::NORMAL, 0);
    EXPECT_EQ(ctx2.getType(), IPSConfiguration::ContextType::NORMAL);
    EXPECT_DEATH(ctx2.getHistorySize(), "Try to access history size for non-history context");
}


TEST(configuration, read_configuration)
{
    cptestPrepareToDie();

    std::stringstream conf_str;
    conf_str <<
        "{"
            "\"contextsConfiguration\": ["
                "{"
                    "\"name\": \"HTTP_REQUEST_BODY\","
                    "\"type\": \"history\","
                    "\"historySize\": 100"
                "},"
                "{"
                    "\"name\": \"HTTP_REQUEST_HEADER\","
                    "\"type\": \"keep\""
                "}"
            "]"
        "}";

    cereal::JSONInputArchive ar(conf_str);

    IPSConfiguration conf;
    conf.load(ar);

    auto body = conf.getContext("HTTP_REQUEST_BODY");
    EXPECT_EQ(body.getType(), IPSConfiguration::ContextType::HISTORY);
    EXPECT_EQ(conf.getHistorySize("HTTP_REQUEST_BODY"), 100);

    auto header = conf.getContext("HTTP_REQUEST_HEADER");
    EXPECT_EQ(header.getType(), IPSConfiguration::ContextType::KEEP);
    EXPECT_DEATH(conf.getHistorySize("HTTP_REQUEST_HEADER"), "Try to access history size for non-history context");

    auto line = conf.getContext("HTTP_REQUEST_LINE");
    EXPECT_EQ(line.getType(), IPSConfiguration::ContextType::NORMAL);

    EXPECT_DEATH(conf.getHistorySize("NO_CONTEXT"), "Try to access history size for non-exiting context");
}

#include <sstream>
#include "ips_enums.h"
#include "ips_basic_policy.h"
#include "cptest.h"
#include "config.h"

using namespace testing;
using namespace std;

ostream &
operator<<(ostream &os, const RuleSelector &selector)
{
    selector.print(os);
    return os;
}

class RuleSelectorTest : public Test
{
public:
    void
    load(const string &config)
    {
        stringstream ss;
        ss << config;
        cereal::JSONInputArchive ar(ss);

        ruleSelector.load(ar);
    }

    string protection =
        "{"
            "\"defaultAction\": \"Prevent\","
            "\"rules\": ["
            "{"
                "\"action\": \"Detect\","
                "\"performanceImpact\": \"Medium or lower\","
                "\"severityLevel\": \"Low or above\","
                "\"confidenceLevel\": \"Medium\","
                "\"serverProtections\": false,"
                "\"clientProtections\": true,"
                "\"protectionsFromYear\": 2020,"
                "\"protectionTags\": ["
                    "\"tag1\","
                    "\"tag2\""
                "],"
                "\"protectionIds\": ["
                    "\"id1\","
                    "\"id2\""
                "]"
            "},"
            "{"
                "\"action\": \"Prevent\","
                "\"performanceImpact\": \"Very low\","
                "\"severityLevel\": \"Medium or above\","
                "\"confidenceLevel\": \"Low\","
                "\"serverProtections\": true,"
                "\"clientProtections\": false,"
                "\"protectionsFromYear\": 1999,"
                "\"protectionTags\": ["
                    "\"tag11\","
                    "\"tag22\""
                "],"
                "\"protectionIds\": ["
                    "\"id11\","
                    "\"id22\""
                "]"
            "}"
            "]"
        "}";

    string protection2 =
        "{"
            "\"defaultAction\": \"Inactive\","
            "\"rules\": ["
            "{"
                "\"action\": \"Detect\","
                "\"performanceImpact\": \"Medium or lower\","
                "\"severityLevel\": \"Low or above\","
                "\"confidenceLevel\": \"Medium\""
            "},"
            "{"
                "\"action\": \"Prevent\""
            "}"
            "]"
        "}";

    string protection3 =
        "{"
            "\"defaultAction\": \"Prevent\","
            "\"rules\": []"
        "}";

    string protection4 =
        "{"
            "\"rules\": ["
            "{"
                "\"action\": \"Detect\","
                "\"performanceImpact\": \"Medium or lower\","
                "\"severityLevel\": \"Low or above\","
                "\"confidenceLevel\": \"Medium\""
            "},"
            "{"
                "\"action\": \"Prevent\""
            "}"
            "]"
        "}";

    RuleSelector ruleSelector;
};

TEST_F(RuleSelectorTest, read_rules)
{
    load(protection);
    ostringstream stream;
    stream << ruleSelector;
    string str =  stream.str();
    string result =
        "[Rule] action: 1 performanceImpact: 3 severityLevel: 1 confidenceLevel: 3 serverProtections: false"
        " clientProtections: true protectionsFromYear: 2020 protectionIds: id1, id2 protectionTags: tag1, tag2;"
        "[Rule] action: 0 performanceImpact: 0 severityLevel: 3 confidenceLevel: 1 serverProtections: true"
        " clientProtections: false protectionsFromYear: 1999 protectionIds: id11, id22 protectionTags: tag11, tag22;"
        "[Rule] action: 0";

    EXPECT_EQ(result, str);
}

TEST_F(RuleSelectorTest, read_semi_rules)
{
    load(protection2);
    ostringstream stream;
    stream << ruleSelector;
    string str =  stream.str();
    string result =
        "[Rule] action: 1 performanceImpact: 3 severityLevel: 1 confidenceLevel: 3;"
        "[Rule] action: 0;"
        "[Rule] action: 2";

    EXPECT_EQ(result, str);
}

TEST_F(RuleSelectorTest, read_empty_rules)
{
    try
    {
        load(protection3);
    }
    catch(const Config::ConfigException &e)
    {
        EXPECT_EQ("rules array is empty", e.getError());
    }
}

TEST_F(RuleSelectorTest, read_no_default_action)
{
    try
    {
        load(protection4);
    }
    catch(const cereal::Exception &e)
    {
        EXPECT_EQ("JSON Parsing failed - provided NVP (defaultAction) not found", string(e.what()));
    }
}

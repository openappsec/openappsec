#include "compound_protection.h"

#include "cptest.h"
#include "ips_entry.h"
#include "mock/mock_table.h"
#include "environment.h"
#include "i_keywords_rule.h"

using namespace testing;
using namespace std;

class CompoundTest : public Test
{
public:
    CompoundTest()
    {
        ON_CALL(table, hasState(_)).WillByDefault(Return(true));
        ON_CALL(table, getState(_)).WillByDefault(Return(&ips_state));
    }

    template <typename ... PatternContextPair>
    shared_ptr<IPSSignatureSubTypes::BaseSignature>
    loadSig(const string &name, const string &operation, PatternContextPair ... pat_ctx)
    {
        stringstream ss;
        ss  << "{"
                << "\"type\": \"compound\","
                << "\"operation\": \"" << operation << "\","
                << "\"operands\": [";
        getSginatureStream(ss, pat_ctx ...);
        ss  << "]" << "}";

        cereal::JSONInputArchive ar(ss);

        return CompoundProtection::get(name, ar);
    }

    template <typename ... Strings>
    set<PMPattern>
    turnToPatternSet(const Strings & ... strings)
    {
        pat_set.clear();
        populatePatternSet(strings ...);
        return pat_set;
    }

    void setActiveContext(const string &name) { ctx.registerValue(I_KeywordsRule::getKeywordsRuleTag(), name); }

private:
    void populatePatternSet() {}

    template <typename ... Strings>
    void
    populatePatternSet(const string &pat, const Strings & ... strings)
    {
        pat_set.emplace(pat, false, false);
        populatePatternSet(strings ...);
    }

    ostream &
    getSginatureStream(ostream &ss, const string &pattern, const string &context)
    {
        ss  << "{"
                << "\"type\": \"simple\","
                << "\"SSM\": \"" << pattern << "\","
                << "\"keywords\": \"\","
                << "\"context\": ["
                    << "\"" << context << "\""
                << "]"
            << "}";
        return ss;
    }

    template <typename ... PatternContextPair>
    ostream &
    getSginatureStream(ostream &ss, const string &pattern, const string &context, PatternContextPair ... pat_ctx)
    {
        return getSginatureStream(getSginatureStream(ss, pattern, context) << ",", pat_ctx ...);
    }

    NiceMock<MockTable> table;
    IPSEntry ips_state;
    set<PMPattern> pat_set;
    ::Environment env;
    ScopedContext ctx;
};

TEST_F(CompoundTest, BasicLoading)
{
    auto sig = loadSig("Test", "and", "aaa", "HTTP_REQUEST_DATA", "bbb", "HTTP_RESPONSE_DATA");
    EXPECT_NE(sig, nullptr);
    EXPECT_EQ(sig->getSigId(), "Test");
    EXPECT_THAT(sig->getContext(), ElementsAre("HTTP_REQUEST_DATA", "HTTP_RESPONSE_DATA"));
    EXPECT_EQ(sig->patternsInSignature(),  turnToPatternSet("aaa", "bbb"));
}

TEST_F(CompoundTest, BasicOrTest)
{
    auto sig = loadSig("Test", "or", "aaa", "HTTP_REQUEST_DATA", "bbb", "HTTP_RESPONSE_DATA");

    setActiveContext("NO_CONTEXT");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("aaa")), IPSSignatureSubTypes::BaseSignature::MatchType::NO_MATCH);
    setActiveContext("HTTP_REQUEST_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("aaa")), IPSSignatureSubTypes::BaseSignature::MatchType::MATCH);
    setActiveContext("HTTP_REQUEST_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("ddd")), IPSSignatureSubTypes::BaseSignature::MatchType::CACHE_MATCH);
}

TEST_F(CompoundTest, BasicOrOrderTest)
{
    auto sig = loadSig("Test", "or", "aaa", "HTTP_REQUEST_DATA", "bbb", "HTTP_RESPONSE_DATA");

    setActiveContext("HTTP_RESPONSE_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("bbb")), IPSSignatureSubTypes::BaseSignature::MatchType::MATCH);
}

TEST_F(CompoundTest, BasicAndTest)
{
    auto sig = loadSig("Test", "and", "aaa", "HTTP_REQUEST_DATA", "bbb", "HTTP_RESPONSE_DATA");

    setActiveContext("HTTP_REQUEST_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("aaa")), IPSSignatureSubTypes::BaseSignature::MatchType::NO_MATCH);
    setActiveContext("HTTP_RESPONSE_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("bbb")), IPSSignatureSubTypes::BaseSignature::MatchType::MATCH);
}

TEST_F(CompoundTest, BasicAndOrderTest)
{
    auto sig = loadSig("Test", "and", "aaa", "HTTP_REQUEST_DATA", "bbb", "HTTP_RESPONSE_DATA");

    setActiveContext("HTTP_RESPONSE_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("bbb")), IPSSignatureSubTypes::BaseSignature::MatchType::NO_MATCH);
    setActiveContext("HTTP_REQUEST_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("aaa")), IPSSignatureSubTypes::BaseSignature::MatchType::MATCH);
}

TEST_F(CompoundTest, BasicOrderedAndTest)
{
    auto sig = loadSig("Test", "ordered_and", "aaa", "HTTP_REQUEST_DATA", "bbb", "HTTP_RESPONSE_DATA");

    setActiveContext("HTTP_REQUEST_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("aaa")), IPSSignatureSubTypes::BaseSignature::MatchType::NO_MATCH);
    setActiveContext("HTTP_RESPONSE_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("bbb")), IPSSignatureSubTypes::BaseSignature::MatchType::MATCH);
}

TEST_F(CompoundTest, BasicOrderedAndOrderTest)
{
    auto sig = loadSig("Test", "ordered_and", "aaa", "HTTP_REQUEST_DATA", "bbb", "HTTP_RESPONSE_DATA");

    setActiveContext("HTTP_RESPONSE_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("bbb")), IPSSignatureSubTypes::BaseSignature::MatchType::NO_MATCH);
    setActiveContext("HTTP_REQUEST_DATA");
    EXPECT_EQ(sig->getMatch(turnToPatternSet("aaa")), IPSSignatureSubTypes::BaseSignature::MatchType::NO_MATCH);
}

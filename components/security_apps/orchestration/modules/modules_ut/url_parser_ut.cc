#include "url_parser.h"

#include "cptest.h"
#include "mock/mock_orchestration_tools.h"

#include <string>
#include <memory>

using namespace testing;
using namespace std;

class URLParserTest : public Test
{
public:
    URLParserTest() {}

    StrictMock<MockOrchestrationTools> mock_orchestration_tools;
};

TEST_F(URLParserTest, doNothing)
{
}

TEST_F(URLParserTest, parseHTTP)
{
    URLParser link("http://172.23.92.180:180/something");

    EXPECT_FALSE(link.isOverSSL());
    EXPECT_EQ("180", link.getPort());
    EXPECT_EQ("/something", link.getQuery());
}

TEST_F(URLParserTest, parseHTTPS)
{
    URLParser link("https://172.23.92.180:180/something");

    EXPECT_TRUE(link.isOverSSL());
    EXPECT_EQ("180", link.getPort());
    EXPECT_EQ("/something", link.getQuery());
}

TEST_F(URLParserTest, parseAWS)
{
    URLParser link("https://a58efa94efdf711e8a6540620a59b447-1878332922.eu-west-1.elb.amazonaws.com/");

    EXPECT_TRUE(link.isOverSSL());
    EXPECT_EQ("443", link.getPort());
    EXPECT_EQ("a58efa94efdf711e8a6540620a59b447-1878332922.eu-west-1.elb.amazonaws.com", link.getBaseURL().unpack());
    EXPECT_EQ("", link.getQuery());
}

TEST_F(URLParserTest, parseAWSWithoutSlash)
{
    URLParser link("https://a58efa94efdf711e8a6540620a59b447-1878332922.eu-west-1.elb.amazonaws.com");

    EXPECT_TRUE(link.isOverSSL());
    EXPECT_EQ("443", link.getPort());
    EXPECT_EQ("a58efa94efdf711e8a6540620a59b447-1878332922.eu-west-1.elb.amazonaws.com", link.getBaseURL().unpack());
    EXPECT_EQ("", link.getQuery());
}

TEST_F(URLParserTest, protocolIsMissing)
{
    // HTTPS is set by default when protocol is not present in URL.
    URLParser link("a58efa94efdf711e8a6540620a59b447-1878332922.eu-west-1.elb.amazonaws.com");

    EXPECT_EQ(link.getBaseURL().unpack(), "a58efa94efdf711e8a6540620a59b447-1878332922.eu-west-1.elb.amazonaws.com");
    EXPECT_TRUE(link.isOverSSL());
    EXPECT_EQ("443", link.getPort());
    EXPECT_EQ("", link.getQuery());
}

TEST_F(URLParserTest, parseBadURL)
{
    URLParser link("http://this_is_not_https_site.com/something");

    EXPECT_FALSE(link.isOverSSL());
    EXPECT_EQ("80", link.getPort());
    EXPECT_EQ("this_is_not_https_site.com", link.getBaseURL().unpack());
    EXPECT_EQ("/something", link.getQuery());
}

TEST_F(URLParserTest, parseNothing)
{
    URLParser link("");
    EXPECT_FALSE(link.getBaseURL().ok());
    EXPECT_TRUE(link.isOverSSL());
    EXPECT_EQ("443", link.getPort());
    EXPECT_EQ("", link.getQuery());
}

TEST_F(URLParserTest, copyCtr)
{
    URLParser link("");
    URLParser copy_link = link;
    EXPECT_TRUE(copy_link.isOverSSL());
    EXPECT_EQ("443", copy_link.getPort());
    EXPECT_EQ("", copy_link.getQuery());
}

TEST_F(URLParserTest, printTest)
{
    string url_path = "this_is_test_url";
    URLParser link(url_path);
    EXPECT_EQ("https://" + url_path + ":443", link.toString());
    stringstream ss;
    ss << link;
    EXPECT_EQ("https://" + url_path + ":443", ss.str());
}
TEST_F(URLParserTest, setQuery)
{
    string url_path = "this_is_test_url/test.sh";
    URLParser link(url_path);
    EXPECT_EQ("https://" + url_path + ":443", link.toString());
    link.setQuery("/new-query");
    EXPECT_EQ("https://this_is_test_url/new-query:443", link.toString());
}

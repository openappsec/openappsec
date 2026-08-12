#include "http_manager.h"

#include <string>
#include <fstream>
#include <streambuf>

#include "cptest.h"
#include "config.h"
#include "singleton.h"
#include "environment.h"
#include "rest_server.h"
#include "table.h"
#include "time_proxy.h"
#include "mainloop.h"
#include "mock/mock_rest_api.h"
#include "i_http_manager.h"
#include "gradual_deployment.h"

using namespace std;
using namespace testing;

class GradualDeploymentTest : public Test
{
public:
    GradualDeploymentTest()
    {
        EXPECT_CALL(rest, mockRestCall(RestAction::SET, "gradual-deployment-policy", _)).WillOnce(
            WithArg<2>(Invoke(this, &GradualDeploymentTest::setGDPolicy))
        );

        gradual_deployment.init();
        i_gradual_deployment = Singleton::Consume<I_GradualDeployment>::from(gradual_deployment);
    }

    bool
    setGDPolicy(const unique_ptr<RestInit> &p)
    {
        gradual_rest_listener = p->getRest();
        return true;
    }

    unique_ptr<ServerRest> gradual_rest_listener;
    I_GradualDeployment *i_gradual_deployment;

private:
    StrictMock<MockRestApi> rest;
    GradualDeployment gradual_deployment;
};

TEST_F(GradualDeploymentTest, getPolicyTest)
{
    stringstream is;
    is << "{"
        << "\"attachment_type\":\"HTTP-Manager\","
        << "\"ip_ranges\":[\"8.8.8.8\",\"9.9.9.9-10.10.10.10\","
        << "\"0:0:0:0:0:0:0:1-0:0:0:0:0:0:0:4\""
        << "]}";
    Maybe<string> rest_call_result = gradual_rest_listener->performRestCall(is);
    EXPECT_TRUE(rest_call_result.ok());

    vector<string> expected = {"8.8.8.8-8.8.8.8", "9.9.9.9-10.10.10.10", "::1-::4"};
    vector<string> curr_policy = i_gradual_deployment->getPolicy(I_GradualDeployment::AttachmentType::NGINX);
    EXPECT_EQ(curr_policy, expected);
}

TEST_F(GradualDeploymentTest, MissingAttachmentType)
{
    stringstream is("{\"ip_ranges\":[\"8.8\"]}");
    Maybe<string> rest_call_result = gradual_rest_listener->performRestCall(is);
    EXPECT_FALSE(rest_call_result.ok());
    EXPECT_THAT(
        rest_call_result.getErr(),
        HasSubstr("Couldn't get variable attachment_type")
    );

    vector<string> expected = {};
    vector<string> curr_policy = i_gradual_deployment->getPolicy(I_GradualDeployment::AttachmentType::NGINX);
    EXPECT_EQ(curr_policy, expected);
}

TEST_F(GradualDeploymentTest, InvalidAttachmentType)
{
    stringstream is;
    is << "{"
        << "\"attachment_type\":\"unsupported-attachment-type\","
        << "\"ip_ranges\":[\"8.8.8.8\",\"9.9.9.9-10.10.10.10\","
        << "\"0:0:0:0:0:0:0:1-0:0:0:0:0:0:0:4\""
        << "]}";
    Maybe<string> rest_call_result = gradual_rest_listener->performRestCall(is);
    EXPECT_FALSE(rest_call_result.ok());
    EXPECT_THAT(
        rest_call_result.getErr(),
        HasSubstr(
            "Failed to determine attachment type. "
            "Type: unsupported-attachment-type, error: unknown attachment type"
        )
    );

    vector<string> expected = {};
    vector<string> curr_policy = i_gradual_deployment->getPolicy(I_GradualDeployment::AttachmentType::NGINX);
    EXPECT_EQ(curr_policy, expected);
}

TEST_F(GradualDeploymentTest, InvalidIPRanges)
{
    stringstream is;
    is << "{"
        << "\"attachment_type\":\"HTTP-Manager\","
        << "\"ip_ranges\":[\"8.8\"]"
        << "}";

    Maybe<string> rest_call_result = gradual_rest_listener->performRestCall(is);
    EXPECT_FALSE(rest_call_result.ok());
    EXPECT_THAT(
        rest_call_result.getErr(),
        HasSubstr(
            "Failed to set gradual deployment policy. "
            "Error: Failed to parse gradual deployment IP range: "
            "Could not create IP address, String '8.8' is not a valid IPv4/IPv6 address"
        )
    );

    vector<string> expected = {};
    vector<string> curr_policy = i_gradual_deployment->getPolicy(I_GradualDeployment::AttachmentType::NGINX);

    EXPECT_EQ(curr_policy, expected);
}

TEST_F(GradualDeploymentTest, getParsedPolicyEmpty)
{
    vector<IPRange> &parsed = i_gradual_deployment->getParsedPolicy(I_GradualDeployment::AttachmentType::NGINX);
    EXPECT_TRUE(parsed.empty());
}

TEST_F(GradualDeploymentTest, getParsedPolicyIPv4)
{
    stringstream is;
    is << "{"
        << "\"attachment_type\":\"HTTP-Manager\","
        << "\"ip_ranges\":[\"8.8.8.8\",\"9.9.9.9-10.10.10.10\"]"
        << "}";
    EXPECT_TRUE(gradual_rest_listener->performRestCall(is).ok());

    vector<IPRange> &parsed = i_gradual_deployment->getParsedPolicy(I_GradualDeployment::AttachmentType::NGINX);
    ASSERT_EQ(parsed.size(), 2u);

    // Single IP "8.8.8.8" is stored as a degenerate range [8.8.8.8, 8.8.8.8]
    EXPECT_EQ(parsed[0].start.ip_type, IP_VERSION_4);
    EXPECT_EQ(parsed[0].end.ip_type, IP_VERSION_4);
    EXPECT_EQ(parsed[0].start.ip.ipv4.s_addr, inet_addr("8.8.8.8"));
    EXPECT_EQ(parsed[0].end.ip.ipv4.s_addr, inet_addr("8.8.8.8"));

    EXPECT_EQ(parsed[1].start.ip_type, IP_VERSION_4);
    EXPECT_EQ(parsed[1].end.ip_type, IP_VERSION_4);
    EXPECT_EQ(parsed[1].start.ip.ipv4.s_addr, inet_addr("9.9.9.9"));
    EXPECT_EQ(parsed[1].end.ip.ipv4.s_addr, inet_addr("10.10.10.10"));
}

TEST_F(GradualDeploymentTest, getParsedPolicyIPv6)
{
    stringstream is;
    is << "{"
        << "\"attachment_type\":\"HTTP-Manager\","
        << "\"ip_ranges\":[\"0:0:0:0:0:0:0:1-0:0:0:0:0:0:0:4\"]"
        << "}";
    EXPECT_TRUE(gradual_rest_listener->performRestCall(is).ok());

    vector<IPRange> &parsed = i_gradual_deployment->getParsedPolicy(I_GradualDeployment::AttachmentType::NGINX);
    ASSERT_EQ(parsed.size(), 1u);

    EXPECT_EQ(parsed[0].start.ip_type, IP_VERSION_6);
    EXPECT_EQ(parsed[0].end.ip_type, IP_VERSION_6);

    struct in6_addr expected_start, expected_end;
    inet_pton(AF_INET6, "::1", &expected_start);
    inet_pton(AF_INET6, "::4", &expected_end);
    EXPECT_EQ(memcmp(&parsed[0].start.ip.ipv6, &expected_start, sizeof(in6_addr)), 0);
    EXPECT_EQ(memcmp(&parsed[0].end.ip.ipv6, &expected_end, sizeof(in6_addr)), 0);
}

TEST_F(GradualDeploymentTest, getParsedPolicyKernelType)
{
    stringstream is;
    is << "{"
        << "\"attachment_type\":\"access-control\","
        << "\"ip_ranges\":[\"192.168.1.1-192.168.1.10\"]"
        << "}";
    EXPECT_TRUE(gradual_rest_listener->performRestCall(is).ok());

    vector<IPRange> &parsed = i_gradual_deployment->getParsedPolicy(I_GradualDeployment::AttachmentType::KERNEL);
    ASSERT_EQ(parsed.size(), 1u);

    EXPECT_EQ(parsed[0].start.ip_type, IP_VERSION_4);
    EXPECT_EQ(parsed[0].end.ip_type, IP_VERSION_4);
    EXPECT_EQ(parsed[0].start.ip.ipv4.s_addr, inet_addr("192.168.1.1"));
    EXPECT_EQ(parsed[0].end.ip.ipv4.s_addr, inet_addr("192.168.1.10"));

    // NGINX type must remain independent
    EXPECT_TRUE(i_gradual_deployment->getParsedPolicy(I_GradualDeployment::AttachmentType::NGINX).empty());
}

#include "service_health_status.h"

#include "cptest.h"
#include "environment.h"
#include "config.h"
#include "config_component.h"
#include "debug.h"
#include "connkey.h"
#include "rest.h"
#include "rest_server.h"
#include "mock/mock_rest_api.h"
#include "service_health_update_event.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_GEO_DB);

class HealthCheckStatusTest : public Test
{
public:
    HealthCheckStatusTest()
    {
        EXPECT_CALL(mock_rest, mockRestCall(RestAction::SHOW, "health", _))
            .WillOnce(WithArg<2>(Invoke(this, &HealthCheckStatusTest::showHealthCheckStatus)));
        health_check_status.init();
    }

    bool
    showHealthCheckStatus(const unique_ptr<RestInit> &p)
    {
        show_health_check_status = p->getRest();
        return true;
    }

    ::Environment env;
    ConfigComponent config;
    ServiceHealthStatus health_check_status;
    NiceMock<MockRestApi> mock_rest;
    unique_ptr<ServerRest> show_health_check_status;
};

TEST_F(HealthCheckStatusTest, testHealthCheckStatus)
{
    ServiceHealthUpdateEvent().notify();

    stringstream ss("{}");
    Maybe<string> maybe_res = show_health_check_status->performRestCall(ss);
    EXPECT_TRUE(maybe_res.ok());
    EXPECT_EQ(maybe_res.unpack(),
        "{\n"
        "    \"healthy\": true,\n"
        "    \"errors\": {}\n"
        "}"
    );
}

TEST_F(HealthCheckStatusTest, testNotHealthyService)
{
    ServiceHealthUpdateEvent("test", "test description").notify();

    stringstream ss("{}");
    Maybe<string> maybe_res = show_health_check_status->performRestCall(ss);
    EXPECT_TRUE(maybe_res.ok());
    EXPECT_EQ(maybe_res.unpack(),
        "{\n"
        "    \"healthy\": false,\n"
        "    \"errors\": {\n"
        "        \"test\": \"test description\"\n"
        "    }\n"
        "}"
    );
}

#include "prometheus_comp.h"

#include <sstream>
#include <fstream>
#include <vector>

#include "cmock.h"
#include "cptest.h"
#include "maybe_res.h"
#include "debug.h"
#include "config.h"
#include "environment.h"
#include "config_component.h"
#include "agent_details.h"
#include "time_proxy.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_messaging.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_PROMETHEUS);

class PrometheusCompTest : public Test
{
public:
    PrometheusCompTest()
    {
        EXPECT_CALL(mock_rest, mockRestCall(_, "declare-boolean-variable", _)).WillOnce(Return(false));
        env.preload();
        config.preload();
        env.init();

        EXPECT_CALL(
            mock_rest,
            addGetCall("metrics", _)
        ).WillOnce(DoAll(SaveArg<1>(&get_metrics_func), Return(true)));

        prometheus_comp.init();
    }

    ::Environment            env;
    ConfigComponent          config;
    PrometheusComp           prometheus_comp;
    StrictMock<MockRestApi>  mock_rest;
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockMessaging>  mock_messaging;
    unique_ptr<ServerRest>   agent_uninstall;
    function<string()>       get_metrics_func;
    CPTestTempfile           status_file;
    string                   registered_services_file_path;

};

TEST_F(PrometheusCompTest, checkAddingMetricWithEmptyUniqueName)
{
    registered_services_file_path = cptestFnameInSrcDir(string("registered_services.json"));
    setConfiguration(registered_services_file_path, "orchestration", "Orchestration registered services");
    string metric_body = "{\n"
        "   \"metrics\": [\n"
        "       {\n"
        "           \"metric_name\": \"watchdogProcessStartupEventsSum\",\n"
        "           \"unique_name\": \"\",\n"
        "           \"metric_type\": \"counter\",\n"
        "           \"metric_description\": \"\",\n"
        "           \"labels\": \"{method=\\\"post\\\",code=\\\"200\\\"}\",\n"
        "           \"value\": \"1534\"\n"
        "       }\n"
        "   ]\n"
        "}";

    string message_body;
    EXPECT_CALL(mock_messaging, sendSyncMessage(_, "/service-metrics", _, _, _))
        .Times(2).WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, metric_body)));

    string metric_str = "# TYPE nano_service_restarts_counter counter\n"
        "nano_service_restarts_counter{method=\"post\",code=\"200\"} 1534\n\n";
    EXPECT_EQ(metric_str,  get_metrics_func());
}

TEST_F(PrometheusCompTest, checkAddingMetricWithoutUniqueName)
{
    registered_services_file_path = cptestFnameInSrcDir(string("registered_services.json"));
    setConfiguration(registered_services_file_path, "orchestration", "Orchestration registered services");
    string metric_body = "{\n"
        "   \"metrics\": [\n"
        "       {\n"
        "           \"metric_name\": \"watchdogProcessStartupEventsSum\",\n"
        "           \"unique_name\": \"watchdogProcessStartupEventsSum_Bla bla\",\n"
        "           \"metric_type\": \"counter\",\n"
        "           \"metric_description\": \"\",\n"
        "           \"labels\": \"{method=\\\"post\\\",code=\\\"200\\\"}\",\n"
        "           \"value\": \"1534\"\n"
        "       }\n"
        "   ]\n"
        "}";

    string message_body;
    EXPECT_CALL(mock_messaging, sendSyncMessage(_, "/service-metrics", _, _, _))
        .Times(2).WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, metric_body)));

    string metric_str = "# TYPE nano_service_restarts_counter counter\n"
        "nano_service_restarts_counter{method=\"post\",code=\"200\"} 1534\n\n";
    EXPECT_EQ(metric_str,  get_metrics_func());
}

TEST_F(PrometheusCompTest, checkAddingMetricWithUniqueName)
{
    registered_services_file_path = cptestFnameInSrcDir(string("registered_services.json"));
    setConfiguration(registered_services_file_path, "orchestration", "Orchestration registered services");
    string metric_body = "{\n"
        "   \"metrics\": [\n"
        "       {\n"
        "           \"metric_name\": \"reservedNgenA\",\n"
        "           \"unique_name\": \"reservedNgenA_WAAP telemetry\",\n"
        "           \"metric_type\": \"counter\",\n"
        "           \"metric_description\": \"\",\n"
        "           \"labels\": \"{method=\\\"post\\\",code=\\\"200\\\"}\",\n"
        "           \"value\": \"1534\"\n"
        "       }\n"
        "   ]\n"
        "}";

    string message_body;
    EXPECT_CALL(mock_messaging, sendSyncMessage(_, "/service-metrics", _, _, _))
        .Times(2).WillRepeatedly(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, metric_body)));

    string metric_str = "# TYPE total_requests_counter counter\n"
        "total_requests_counter{method=\"post\",code=\"200\"} 1534\n\n";
    EXPECT_EQ(metric_str,  get_metrics_func());
}


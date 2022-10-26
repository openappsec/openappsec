#include "messaging_downloader_client.h"

#include <boost/filesystem.hpp>

#include "environment.h"
#include "singleton.h"
#include "config.h"
#include "config_component.h"
#include "mainloop.h"
#include "cptest.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_messaging.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_agent_details.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;

class MessagingDownloaderClientTest : public Test
{
public:
    MessagingDownloaderClientTest()
    {
        EXPECT_CALL(
            rest,
            mockRestCall(RestAction::SHOW, "download-status", _)
        ).WillOnce(WithArg<2>(Invoke(this, &MessagingDownloaderClientTest::restHandler)));

        EXPECT_CALL(rest, mockRestCall(RestAction::ADD, "declare-boolean-variable", _)).WillOnce(Return(true));

        Debug::setUnitTestFlag(D_COMMUNICATION, Debug::DebugLevel::TRACE);
        Debug::setNewDefaultStdout(&capture_debug);

        messaging_downloader.preload();
        env.preload();
        env.init();
        messaging_downloader.init();
    }

    ~MessagingDownloaderClientTest()
    {
        boost::filesystem::remove_all("/tmp/test_download_dir/");
        messaging_downloader.fini();
    }

    bool
    restHandler(const unique_ptr<RestInit> &rest_ptr)
    {
        rest_handler = rest_ptr->getRest();
        return true;
    }

    unique_ptr<ServerRest> rest_handler;
    ostringstream capture_debug;
    I_MainLoop::Routine downloading_routine;
    MessagingDownloaderClient messaging_downloader;
    NiceMock<MockTimeGet> mock_time;
    NiceMock<MockAgentDetails> mock_agent_details;
    StrictMock<MockMessaging> mock_msg;
    StrictMock<MockRestApi> rest;
    StrictMock<MockMainLoop> mock_ml;
    ::Environment env;
    ConfigComponent conf;
};

TEST_F(MessagingDownloaderClientTest, do_nothing)
{
}

TEST_F(MessagingDownloaderClientTest, request_download)
{
    string file_name = "test_file";
    string url = "https://download_test.com/test_download";
    Singleton::Consume<I_Environment>::by<MessagingDownloaderClient>()->registerValue<int>("Listening Port", 6464);

    stringstream ss;
    ss << "{\n    \"file_name\": \"" << file_name << "\","
        << "\n    \"url\": \"" << url << "\","
        << "\n    \"port\": 0,\n    \"response_port\": 6464\n}";

    EXPECT_CALL(mock_msg, sendMessage(
        true,
        ss.str(),
        I_Messaging::Method::POST,
        "127.0.0.1",
        8164,
        _,
        "/add-download-file",
        _,
        _,
        _
    )).WillOnce(Return(Maybe<string>(string("{\"uuid\": \"111\", \"status\": true}"))));

    bool is_cb_run = false;
    bool res = Singleton::Consume<I_MessagingDownloader>::from<MessagingDownloaderClient>()->downloadFile(
        file_name,
        url,
        [&is_cb_run](const Maybe<string>& filepath)
        {
            is_cb_run = true;
            EXPECT_TRUE(filepath.ok());
            EXPECT_EQ(filepath.unpack(), "/tmp/test_download_dir/test_file");
        }
    );
    EXPECT_TRUE(res);

    stringstream is;
    is << "{\"uuid\": \"111\", \"status\": true, \"filepath\": \"/tmp/test_download_dir/test_file\"}";
    EXPECT_FALSE(is_cb_run);
    rest_handler->performRestCall(is);
    EXPECT_TRUE(is_cb_run);
}

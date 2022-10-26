#include "messaging_downloader_server.h"

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

class MessagingDownloaderServerTest : public Test
{
public:
    MessagingDownloaderServerTest()
    {
        setConfiguration(string("/tmp/test_download_dir/"), "Downloader", "Downloading Directory");
        EXPECT_CALL(
            rest,
            mockRestCall(RestAction::ADD, "download-file", _)
        ).WillOnce(WithArg<2>(Invoke(this, &MessagingDownloaderServerTest::restHandler)));

        Maybe<string> fog_addr(string("test.fog.com"));
        EXPECT_CALL(
            mock_agent_details,
            getFogDomain()
        ).WillRepeatedly(Return(fog_addr));

        Debug::setUnitTestFlag(D_COMMUNICATION, Debug::DebugLevel::TRACE);
        Debug::setNewDefaultStdout(&capture_debug);

        messaging_downloader.preload();
        messaging_downloader.init();
    }

    ~MessagingDownloaderServerTest()
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

    void
    expectRequestSuccess(
        string &test_file_name,
        string &host,
        string &url,
        string &uuid,
        unsigned int port,
        unsigned int response_port,
        string &success_msg
    )
    {
        EXPECT_CALL(
            mock_ml,
            addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, false)
        ).WillOnce(DoAll(SaveArg<1>(&downloading_routine), Return(0)));

        EXPECT_CALL(
            mock_msg,
            sendMessage(true, "", I_Messaging::Method::GET, host, port, _, url, _, _, _)
        ).WillOnce(Return(Maybe<string>(string("test_body"))));

        stringstream expected_response;
        expected_response
            << "\n    \"status\": true,"
            << "\n    \"filepath\": \"/tmp/test_download_dir/" << test_file_name << "\"\n}";

        string saved_response;

        EXPECT_CALL(mock_msg, sendMessage(
            false,
            _,
            I_Messaging::Method::POST,
            "127.0.0.1",
            response_port,
            _,
            "/show-download-status",
            _,
            _,
            _
        )).WillOnce(DoAll(SaveArg<1>(&saved_response), Return(Maybe<string>(string()))));


        stringstream is;
        is << "{\"file_name\": \"" <<  test_file_name << "\","
            << "\"response_port\": " << response_port << ","
            << "\"url\": \"" << url << "\","
            << "\"port\": " << port << ","
            << "\"uuid\": \"" << uuid << "\"}";

        rest_handler->performRestCall(is);
        downloading_routine();
        EXPECT_THAT(saved_response, HasSubstr(expected_response.str()));
        EXPECT_THAT(capture_debug.str(), HasSubstr(success_msg));
    }

    unique_ptr<ServerRest> rest_handler;
    ostringstream capture_debug;
    I_MainLoop::Routine downloading_routine;
    MessagingDownloaderServer messaging_downloader;
    NiceMock<MockTimeGet> mock_time;
    StrictMock<MockAgentDetails> mock_agent_details;
    StrictMock<MockMessaging> mock_msg;
    StrictMock<MockRestApi> rest;
    StrictMock<MockMainLoop> mock_ml;
    ::Environment env;
    ConfigComponent conf;
};

TEST_F(MessagingDownloaderServerTest, do_nothing)
{
}

TEST_F(MessagingDownloaderServerTest, add_one_secured_request)
{
    string test_file_name = "test_file_name";
    string host = "test_host";
    string url = "https://test_host/test_url";
    string uuid = "111";
    string success_msg = "Successfully downloaded the file. File name: " + test_file_name;
    unsigned int port = 443;
    unsigned int response_port = 123;
    expectRequestSuccess(test_file_name, host, url, uuid, port, response_port, success_msg);
}

TEST_F(MessagingDownloaderServerTest, add_one_non_secured_request)
{
    string test_file_name = "test_file_name";
    string host = "test_host";
    string url = "http://test_host/test_url";
    string uuid = "111";
    string success_msg = "Successfully downloaded the file. File name: " + test_file_name;
    unsigned int port = 80;
    unsigned int response_port = 123;
    expectRequestSuccess(test_file_name, host, url, uuid, port, response_port, success_msg);
}

TEST_F(MessagingDownloaderServerTest, add_multiple_requests)
{
    string test_file_name1 = "test_file_name1";
    string test_file_name2 = "test_file_name2";
    string host = "test_host";
    string url = "https://test_host/test_url";
    string uuid = "111";
    string success_msg1 = "Successfully downloaded the file. File name: " + test_file_name1;
    string success_msg2 = "Successfully downloaded the file. File name: " + test_file_name2;
    unsigned int port = 443;
    unsigned int response_port = 123;
    expectRequestSuccess(test_file_name1, host, url, uuid, port, response_port, success_msg1);
    expectRequestSuccess(test_file_name2, host, url, uuid, port, response_port, success_msg2);
}

TEST_F(MessagingDownloaderServerTest, add_same_request_twice)
{
    string test_file_name = "test_file_name";
    string host = "test_host";
    string url = "https://test_host/test_url";
    string uuid = "111";
    unsigned int response_port = 123;

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, false)
    ).WillOnce(DoAll(SaveArg<1>(&downloading_routine), Return(0)));

    EXPECT_CALL(
        mock_msg,
        sendMessage(true, "", I_Messaging::Method::GET, host, 442, _, url, _, _, _)
    ).WillOnce(Return(Maybe<string>(string("test_body"))));

    stringstream expected_response;
    expected_response
        << "\n    \"status\": true,"
        << "\n    \"filepath\": \"/tmp/test_download_dir/" << test_file_name << "\"\n}";

    string saved_response;

    EXPECT_CALL(mock_msg, sendMessage(
        false,
        _,
        I_Messaging::Method::POST,
        "127.0.0.1",
        response_port,
        _,
        "/show-download-status",
        _,
        _,
        _
    )).WillOnce(DoAll(SaveArg<1>(&saved_response), Return(Maybe<string>(string()))));

    stringstream is;
    is
        << "{\"file_name\": \"" <<  test_file_name << "\","
        << "\"response_port\": " << response_port << ","
        << "\"uuid\": \"" << uuid << "\","
        << "\"port\": 442,"
        << "\"url\": \"" << url << "\"}";

    rest_handler->performRestCall(is);
    rest_handler->doCall();
    downloading_routine();

    EXPECT_THAT(saved_response, HasSubstr(expected_response.str()));
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Failed to download the file. Similar download request already exists.")
    );
}

TEST_F(MessagingDownloaderServerTest, add_request_that_fails)
{
    string test_file_name = "test_file_name";
    string host = "test_host";
    string url = "https://test_host/test_url";
    string uuid = "111";
    unsigned int response_port = 123;
    unsigned int additional_port_test = 123;

    Maybe<string> err = genError("no");

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, false)
    ).WillOnce(DoAll(SaveArg<1>(&downloading_routine), Return(0)));

    EXPECT_CALL(
        mock_msg,
        sendMessage(true, "", I_Messaging::Method::GET, host, additional_port_test, _, url, _, _, _)
    ).WillOnce(Return(err));

    stringstream expected_response;
    expected_response
        << "\n    \"status\": false,"
        << "\n    \"error\": \"Failed during the downloading process.\"\n}";

    string saved_response;

    EXPECT_CALL(mock_msg, sendMessage(
        false,
        _,
        I_Messaging::Method::POST,
        "127.0.0.1",
        response_port,
        _,
        "/show-download-status",
        _,
        _,
        _
    )).WillOnce(DoAll(SaveArg<1>(&saved_response), Return(Maybe<string>(string()))));

    stringstream is;
    is
        << "{\"file_name\": \"" <<  test_file_name << "\","
        << "\"response_port\": " << response_port << ","
        << "\"url\": \"" << url << "\","
        << "\"port\": " << additional_port_test << ","
        << "\"uuid\": \"" << uuid << "\"}";

    rest_handler->performRestCall(is);
    downloading_routine();
    EXPECT_THAT(saved_response, HasSubstr(expected_response.str()));
    EXPECT_THAT(capture_debug.str(), HasSubstr("Failed to download file. File name: test_file_name"));
}

TEST_F(MessagingDownloaderServerTest, download_with_same_filename)
{
    string test_file_name = "test_file_name";
    string host = "test_host";
    string url1 = "https://test_host/test_url1";
    string url2 = "https://test_host/test_url2";
    string uuid = "111";
    unsigned int port = 443;
    string success_msg = "Successfully downloaded the file. File name: " + test_file_name;
    unsigned int response_port = 123;
    expectRequestSuccess(test_file_name, host, url1, uuid, port, response_port, success_msg);

    stringstream is;
    is
        << "{\"file_name\": \"" <<  test_file_name << "\","
        << "\"response_port\": " << response_port << ","
        << "\"port\": " << port << ","
        << "\"url\": \"" << url2 << "\"}";

    rest_handler->performRestCall(is);
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("The file with the name 'test_file_name' is already exist in the downloading directory")
    );
}

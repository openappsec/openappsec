#include "http_configuration.h"

#include <arpa/inet.h>
#include <fstream>
#include <boost/algorithm/string.hpp>

#include "cptest.h"
#include "c_common/ip_common.h"

using namespace std;
using namespace testing;

class HttpAttachmentUtilTest : public Test
{
public:
    string
    createIPRangesString(const vector<string> &ip_ranges)
    {
        stringstream ip_ranges_string_stream;
        ip_ranges_string_stream << "[";
        for (auto iterator = ip_ranges.begin(); iterator < ip_ranges.end() - 1; iterator++) {
            ip_ranges_string_stream << "\"" << *iterator << "\"" << ", ";
        }
        ip_ranges_string_stream << "\"" << ip_ranges.back() << "\"]";

        return ip_ranges_string_stream.str();
    }

    const string attachment_configuration_file_name = "cp_nano_http_attachment_conf";
    const vector<string> ip_ranges = { "8.8.8.8", "9.9.9.9-10.10.10.10", "0:0:0:0:0:0:0:1-0:0:0:0:0:0:0:4"};
    const string static_resources_path = "/dev/shm/static_resources/";
};

TEST_F(HttpAttachmentUtilTest, GetValidAttachmentConfiguration)
{
    string valid_configuration =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/abc\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"is_fail_open_mode_enabled\": 0,\n"
            "\"fail_open_timeout\": 1234,\n"
            "\"is_fail_open_mode_hold_enabled\": 0,\n"
            "\"fail_open_hold_timeout\": 4321,\n"
            "\"sessions_per_minute_limit_verdict\": \"Accept\",\n"
            "\"max_sessions_per_minute\": 0,\n"
            "\"num_of_nginx_ipc_elements\": 200,\n"
            "\"keep_alive_interval_msec\": 10000,\n"
            "\"dbg_level\": 2,\n"
            "\"nginx_inspection_mode\": 1,\n"
            "\"operation_mode\": 0,\n"
            "\"req_body_thread_timeout_msec\": 155,\n"
            "\"req_proccessing_timeout_msec\": 42,\n"
            "\"registration_thread_timeout_msec\": 101,\n"
            "\"res_proccessing_timeout_msec\": 420,\n"
            "\"res_header_thread_timeout_msec\": 1,\n"
            "\"res_body_thread_timeout_msec\": 80,\n"
            "\"waiting_for_verdict_thread_timeout_msec\": 60,\n"
            "\"req_header_thread_timeout_msec\": 10,\n"
            "\"ip_ranges\": " + createIPRangesString(ip_ranges) + ",\n"
            "\"static_resources_path\": \"" + static_resources_path + "\""
        "}\n";
    ofstream valid_configuration_file(attachment_configuration_file_name);
    valid_configuration_file << valid_configuration;
    valid_configuration_file.close();

    HttpAttachmentConfiguration conf_data_out;
    EXPECT_EQ(conf_data_out.init(attachment_configuration_file_name), 1);
    EXPECT_EQ(conf_data_out.getNumericalValue("is_fail_open_mode_enabled"), 0);
    EXPECT_EQ(conf_data_out.getNumericalValue("fail_open_timeout"), 1234);
    EXPECT_EQ(conf_data_out.getNumericalValue("is_fail_open_mode_hold_enabled"), 0);
    EXPECT_EQ(conf_data_out.getNumericalValue("fail_open_hold_timeout"), 4321);
    EXPECT_EQ(conf_data_out.getStringValue("sessions_per_minute_limit_verdict"), "Accept");
    EXPECT_EQ(conf_data_out.getNumericalValue("max_sessions_per_minute"), 0);
    EXPECT_EQ(conf_data_out.getNumericalValue("num_of_nginx_ipc_elements"), 200);
    EXPECT_EQ(conf_data_out.getNumericalValue("keep_alive_interval_msec"), 10000);
    EXPECT_EQ(conf_data_out.getNumericalValue("dbg_level"), 2u);
    EXPECT_EQ(conf_data_out.getNumericalValue("res_proccessing_timeout_msec"), 420);
    EXPECT_EQ(conf_data_out.getNumericalValue("req_proccessing_timeout_msec"), 42);
    EXPECT_EQ(conf_data_out.getNumericalValue("registration_thread_timeout_msec"), 101);
    EXPECT_EQ(conf_data_out.getNumericalValue("req_header_thread_timeout_msec"), 10);
    EXPECT_EQ(conf_data_out.getNumericalValue("req_body_thread_timeout_msec"), 155);
    EXPECT_EQ(conf_data_out.getNumericalValue("res_header_thread_timeout_msec"), 1);
    EXPECT_EQ(conf_data_out.getNumericalValue("res_body_thread_timeout_msec"), 80);
    EXPECT_EQ(conf_data_out.getNumericalValue("waiting_for_verdict_thread_timeout_msec"), 60);
    EXPECT_EQ(conf_data_out.getNumericalValue("nginx_inspection_mode"), 1);
}

TEST_F(HttpAttachmentUtilTest, GetMalformedAttachmentConfiguration)
{
    string malformed_configuration =
        "{\n"
            "\"is_fail_open_mode_enabled\": false,,,,,,\n"
            "\"fail_open_timeout\": 1234,\n"
            "\"num_of_nginx_ipc_elements\": 200,\n"
            "\"dbg_level\": 2,\n"
            "\"ip_ranges\": " + createIPRangesString(ip_ranges) + ",\n"
            "\"static_resources_path\": \"" + static_resources_path + "\""
        "}\n";
    ofstream valid_configuration_file(attachment_configuration_file_name);
    valid_configuration_file << malformed_configuration;
    valid_configuration_file.close();

    HttpAttachmentConfiguration conf_data_out;
    EXPECT_EQ(conf_data_out.init(attachment_configuration_file_name), 0);
}

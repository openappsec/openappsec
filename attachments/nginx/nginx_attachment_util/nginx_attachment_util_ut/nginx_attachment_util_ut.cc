#include <fstream>
#include <boost/algorithm/string.hpp>
#include <stdlib.h>
#include <arpa/inet.h>

#include "nginx_attachment_util.h"
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
    const vector<string> ip_ranges = { "8.8.8.8", "9.9.9.9-10.10.10.10", "0:0:0:0:0:0:0:2-0:0:0:0:0:0:0:5"};
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
            "\"is_fail_open_mode_hold_enabled\": 1,\n"
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
            "\"res_body_thread_timeout_msec\": 0,\n"
            "\"waiting_for_verdict_thread_timeout_msec\": 75,\n"
            "\"req_header_thread_timeout_msec\": 10,\n"
            "\"ip_ranges\": " + createIPRangesString(ip_ranges) + ",\n"
            "\"static_resources_path\": \"" + static_resources_path + "\",\n"
            "\"min_retries_for_verdict\": 1,\n"
            "\"max_retries_for_verdict\": 3,\n"
            "\"hold_verdict_retries\": 3,\n"
            "\"hold_verdict_polling_time\": 1,\n"
            "\"body_size_trigger\": 777,\n"
            "\"remove_server_header\": 1,\n"
            "\"decompression_pool_size\": 524288,\n"
            "\"recompression_pool_size\": 32768,\n"
            "\"max_decompressed_body_size\": 12345,\n"
            "\"is_paired_affinity_enabled\": 0,\n"
            "\"is_async_mode_enabled\": 0,\n"
            "\"async_body_stage_timeout_msec\": 500,\n"
            "\"is_brotli_inspection_enabled\": 1,\n"
            "\"is_websocket_stream_enabled\": 1,\n"
            "\"is_max_chunks_to_process_enabled\": 1\n"
        "}\n";
    ofstream valid_configuration_file(attachment_configuration_file_name);
    valid_configuration_file << valid_configuration;
    valid_configuration_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);
    EXPECT_EQ(getDbgLevel(), 2u);
    EXPECT_EQ(getStaticResourcesPath(), static_resources_path);
    EXPECT_EQ(isFailOpenMode(), 0);
    EXPECT_EQ(getFailOpenTimeout(), 1234u);
    EXPECT_EQ(isFailOpenHoldMode(), 1);
    EXPECT_EQ(getFailOpenHoldTimeout(), 4321u);
    EXPECT_EQ(isFailOpenOnSessionLimit(), 1);
    EXPECT_EQ(getMaxSessionsPerMinute(), 0u);
    EXPECT_EQ(getNumOfNginxIpcElements(), 200u);
    EXPECT_EQ(getKeepAliveIntervalMsec(), 10000u);
    EXPECT_EQ(getResProccessingTimeout(), 420u);
    EXPECT_EQ(getReqProccessingTimeout(), 42u);
    EXPECT_EQ(getRegistrationThreadTimeout(), 101u);
    EXPECT_EQ(getReqHeaderThreadTimeout(), 10u);
    EXPECT_EQ(getReqBodyThreadTimeout(), 155u);
    EXPECT_EQ(getResHeaderThreadTimeout(), 1u);
    EXPECT_EQ(getResBodyThreadTimeout(), 0u);
    EXPECT_EQ(getMinRetriesForVerdict(), 1u);
    EXPECT_EQ(getMaxRetriesForVerdict(), 3u);
    EXPECT_EQ(getReqBodySizeTrigger(), 777u);
    EXPECT_EQ(getWaitingForVerdictThreadTimeout(), 75u);
    EXPECT_EQ(getInspectionMode(), NanoHttpInspectionMode::BLOCKING_THREAD);
    EXPECT_EQ(getRemoveResServerHeader(), 1u);
    EXPECT_EQ(getDecompressionPoolSize(), 524288u);
    EXPECT_EQ(getRecompressionPoolSize(), 32768u);
    EXPECT_EQ(getMaxDecompressedBodySize(), 12345u);
    EXPECT_EQ(getHoldVerdictRetries(), 3u);
    EXPECT_EQ(getHoldVerdictPollingTime(), 1u);
    EXPECT_EQ(getIsBrotliInspectionEnabled(), 1u);
    EXPECT_EQ(getIsWebSocketStreamEnabled(), 1u);
    EXPECT_EQ(getIsMaxChunksToProcessEnabled(), 1u);

    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/abc"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.9", "5.6.7.8", 80, "GET", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.9", 80, "GET", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 88, "GET", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "POST", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "est", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/ab"), 0);

    EXPECT_EQ(isSkipSource("8.8.8.8"), 1);
    EXPECT_EQ(isSkipSource("8.8.8.9"), 0);
    EXPECT_EQ(isSkipSource("8.8.8.10"), 0);

    EXPECT_EQ(isSkipSource("9.9.9.8"), 0);
    EXPECT_EQ(isSkipSource("9.9.9.9"), 1);
    EXPECT_EQ(isSkipSource("9.255.0.0"), 1);
    EXPECT_EQ(isSkipSource("10.10.10.10"), 1);
    EXPECT_EQ(isSkipSource("10.10.10.11"), 0);

    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:1"), 0);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:2"), 1);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:4"), 1);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:5"), 1);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:6"), 0);

    EXPECT_EQ(isPairedAffinityEnabled(), 0u);
    EXPECT_EQ(isAsyncModeEnabled(), 0u);
    EXPECT_EQ(getAsyncBodyStageTimeoutMsec(), 500u);
}

TEST_F(HttpAttachmentUtilTest, CheckIPAddrValidity)
{
    EXPECT_EQ(isIPAddress("10.0.0.1"), 1);
    EXPECT_EQ(isIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), 1);

    EXPECT_EQ(isIPAddress("333.0.0.1"), 0);
    EXPECT_EQ(isIPAddress("2001:0gb8:85a3:0000:0000:8a2e:0370:7334"), 0);
}

TEST_F(HttpAttachmentUtilTest, ExtensiveUriMatching)
{
    // Test configurations for different URI scenarios

    // Single URI exact matching
    string single_uri_config =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/exact\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"dbg_level\": 1\n"
        "}\n";

    ofstream single_uri_file(attachment_configuration_file_name);
    single_uri_file << single_uri_config;
    single_uri_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);

    // Single URI - exact matches
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/exact"), 1);

    // Single URI - should NOT match partial, prefix, or suffix
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/exa"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/exact/more"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/exactmore"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "exact"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/"), 0);

    // Multiple URI patterns with pipe delimiter
    string multi_uri_config =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/api|/admin|/users\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"dbg_level\": 1\n"
        "}\n";

    ofstream multi_uri_file(attachment_configuration_file_name);
    multi_uri_file << multi_uri_config;
    multi_uri_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);

    // Multiple URI - exact matches for each pattern
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/api"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/admin"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/users"), 1);

    // Multiple URI - should NOT match partial matches
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/ap"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/api/v1"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/administrator"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/user"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/"), 0);

    // Multiple URI - should NOT match unrelated URIs
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/public"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/login"), 0);

    // Multiple URI with whitespace around pipes
    string whitespace_uri_config =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/path1 | /path2  |  /path3\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"dbg_level\": 1\n"
        "}\n";

    ofstream whitespace_uri_file(attachment_configuration_file_name);
    whitespace_uri_file << whitespace_uri_config;
    whitespace_uri_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);

    // Whitespace handling - should match exactly despite spaces around pipes
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/path1"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/path2"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/path3"), 1);

    // Special characters in URIs
    string special_chars_config =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/api/v1/user-profile|/api/v2/user_data|/special%20path\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"dbg_level\": 1\n"
        "}\n";

    ofstream special_chars_file(attachment_configuration_file_name);
    special_chars_file << special_chars_config;
    special_chars_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);

    // Special characters - exact matching
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/api/v1/user-profile"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/api/v2/user_data"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/special%20path"), 1);

    // Special characters - should not match similar but different URIs
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/api/v1/user_profile"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/api/v2/user-data"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/special path"), 0);

    // Empty URI pattern - should match everything
    string empty_uri_config =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"dbg_level\": 1\n"
        "}\n";

    ofstream empty_uri_file(attachment_configuration_file_name);
    empty_uri_file << empty_uri_config;
    empty_uri_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);

    // Empty URI pattern - should match any URI
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/any/path"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/api/users/123"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", ""), 1);

    // Edge cases - root path and similar patterns
    string root_path_config =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/|/root|/r\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"dbg_level\": 1\n"
        "}\n";

    ofstream root_path_file(attachment_configuration_file_name);
    root_path_file << root_path_config;
    root_path_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);

    // Root path and similar patterns - exact matching only
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/root"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/r"), 1);

    // Should NOT match longer paths that start with these patterns
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/ro"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/root/sub"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/rootuser"), 0);
}

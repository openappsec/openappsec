// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <getopt.h>

#include "agent_core_utilities.h"
#include "debug.h"
#include "internal/shell_cmd.h"
#include "mainloop.h"
#include "nginx_utils.h"
#include "time_proxy.h"
#include "fog_connection.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_MANAGER);

class MainComponent
{
public:
    MainComponent()
    {
        time_proxy.init();
        environment.init();
        mainloop.init();
        shell_cmd.init();
    }

    ~MainComponent()
    {
        shell_cmd.fini();
        mainloop.fini();
        environment.fini();
        time_proxy.fini();
    }

private:
    ShellCmd shell_cmd;
    MainloopComponent mainloop;
    Environment environment;
    TimeProxyComponent time_proxy;
};

void
printVersion()
{
#ifdef NGINX_CONF_COLLECTOR_VERSION
    cout << "Check Point NGINX configuration collector version: " << NGINX_CONF_COLLECTOR_VERSION << '\n';
#else
    cout << "Check Point NGINX configuration collector version: Private" << '\n';
#endif
}

void
printUsage(const char *prog_name)
{
    cout << "Usage: " << prog_name << " [-v] [-i /path/to/nginx.conf] [-o /path/to/output.conf]" <<
        " [--upload --token <token> [--fog <address>]]" << '\n';
    cout << "  -V              Print version" << '\n';
    cout << "  -v              Enable verbose output" << '\n';
    cout << "  -i input_file   Specify input file (default is /etc/nginx/nginx.conf)" << '\n';
    cout << "  -o output_file  Specify output file (default is ./full_nginx.conf)" << '\n';
    cout << "  -h              Print this help message" << '\n';
    cout << "  --upload        Upload configuration to FOG (requires --token)" << '\n';
    cout << "  --token <token> profile token for FOG upload" << '\n';
    cout << "  --fog <address> FOG server address (default: inext-agents.cloud.ngen.checkpoint.com)" << '\n';
    cout << "  --proxy <address> Proxy server to send the request through" << '\n';
}

int
main(int argc, char *argv[])
{
    string nginx_input_file = "/etc/nginx/nginx.conf";
    string nginx_output_file = "full_nginx.conf";
    string fog_address = "inext-agents.cloud.ngen.checkpoint.com";
    string token;
    string proxy_host;
    bool upload_flag = false;
    int opt;
    
    static struct option long_options[] = {
        {"upload", no_argument, 0, 'u'},
        {"token", required_argument, 0, 1001},
        {"fog", required_argument, 0, 1002},
        {"proxy", required_argument, 0, 1003},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "Vvhi:o:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'V':
                printVersion();
                return 0;
            case 'v':
                Debug::setUnitTestFlag(D_NGINX_MANAGER, Debug::DebugLevel::TRACE);
                break;
            case 'i':
                nginx_input_file = optarg;
                break;
            case 'o':
                nginx_output_file = optarg;
                break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case 'u':
                upload_flag = true;
                break;
            case 1001: // --token
                token = optarg;
                break;
            case 1002: // --fog
                fog_address = optarg;
                break;
            case 1003: // --proxy
                proxy_host = optarg;
                break;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    for (int i = optind; i < argc; ++i) {
        cerr << "Unknown argument: " << argv[i] << '\n';
        printUsage(argv[0]);
        return 1;
    }

    if (upload_flag && token.empty()) {
        cerr << "Error: --upload requires --token to be specified" << '\n';
        printUsage(argv[0]);
        return 1;
    }

    dbgTrace(D_NGINX_MANAGER) << "Starting nginx configuration collector";

    MainComponent main_component;
    auto validation_result = NginxUtils::validateNginxConf(nginx_input_file);
    if (!validation_result.ok()) {
        cerr
            << "Could not validate nginx configuration file: "
            << nginx_input_file
            << '\n'
            << validation_result.getErr();
        return 1;
    }

    NginxConfCollector nginx_collector(nginx_input_file, nginx_output_file);
    auto result = nginx_collector.generateFullNginxConf();
    if (!result.ok()) {
        cerr << "Could not generate full nginx configuration file, error: " << result.getErr() << '\n';
        return 1;
    }

    if (result.unpack().empty() || !NGEN::Filesystem::exists(result.unpack())) {
        cerr << "Generated nginx configuration file does not exist: " << result.unpack() << '\n';
        return 1;
    }

    validation_result = NginxUtils::validateNginxConf(result.unpack());
    if (!validation_result.ok()) {
        cerr
            << "Could not validate generated nginx configuration file: "
            << nginx_output_file
            << '\n'
            << validation_result.getErr();
        return 1;
    }

    cout << "Full nginx configuration file was successfully generated: " << result.unpack() << '\n';

    if (upload_flag) {
        cout << "Uploading configuration to FOG server: " << fog_address << '\n';
        
        string full_fog_url = fog_address;
        if (fog_address.find("http://") != 0 && fog_address.find("https://") != 0) {
            full_fog_url = "https://" + fog_address;
        }
        
        FogConnection fog_connection(token, full_fog_url);

        if (!proxy_host.empty()) {
            fog_connection.setProxy(proxy_host);
        }

        auto credentials_result = fog_connection.getCredentials();
        if (!credentials_result.ok()) {
            cerr
                << "Failed to register agent with the FOG. with error: "
                << credentials_result.getErr()
                << '\n';
            return 1;
        }

        auto jwt_result = fog_connection.getJWT();
        if (!jwt_result.ok()) {
            cerr << "Failed to get JWT token. with error:" << jwt_result.getErr() << '\n';
            return 1;
        }

        auto upload_result = fog_connection.uploadNginxConfig(result.unpack());
        if (!upload_result.ok()) {
            cerr << "Failed to upload nginx config file to FOG. with error:" << upload_result.getErr() << '\n';
            return 1;
        }

        cout << "Successfully uploaded configuration to FOG server." << '\n';
    }
    
    return 0;
}

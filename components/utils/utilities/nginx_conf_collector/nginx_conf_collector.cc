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

#include <iostream>
#include <unistd.h>

#include "agent_core_utilities.h"
#include "debug.h"
#include "internal/shell_cmd.h"
#include "mainloop.h"
#include "nginx_utils.h"
#include "time_proxy.h"

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
    cout << "Usage: " << prog_name << " [-v] [-i /path/to/nginx.conf] [-o /path/to/output.conf]" << '\n';
    cout << "  -V              Print version" << '\n';
    cout << "  -v              Enable verbose output" << '\n';
    cout << "  -i input_file   Specify input file (default is /etc/nginx/nginx.conf)" << '\n';
    cout << "  -o output_file  Specify output file (default is ./full_nginx.conf)" << '\n';
    cout << "  -h              Print this help message" << '\n';
}

int
main(int argc, char *argv[])
{
    string nginx_input_file = "/etc/nginx/nginx.conf";
    string nginx_output_file = "full_nginx.conf";

    int opt;
    while ((opt = getopt(argc, argv, "Vvhi:o:h")) != -1) {
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
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    for (int i = optind; i < argc;) {
        cerr << "Unknown argument: " << argv[i] << '\n';
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

    return 0;
}

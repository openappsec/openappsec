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

#include "central_nginx_manager.h"

#include "components_list.h"
#include "nginx_message_reader.h"

using namespace std;

int
main(int argc, char **argv)
{
    NodeComponents<CentralNginxManager, NginxMessageReader> comps;

    comps.registerGlobalValue<bool>("Is Rest primary routine", true);
    comps.registerGlobalValue<uint>("Nano service API Port Primary", 7555);
    comps.registerGlobalValue<uint>("Nano service API Port Alternative", 7556);

    return comps.run("Central NGINX Manager", argc, argv);
}

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

#include "time_print.h"
#include "components_list.h"
#include "nginx_attachment.h"
#include "gradual_deployment.h"
#include "http_manager.h"
#include "layer_7_access_control.h"
#include "rate_limit.h"
#include "waap.h"
#include "ips_comp.h"
#include "keyword_comp.h"

int
main(int argc, char **argv)
{
    NodeComponentsWithTable<
        SessionID,
        NginxAttachment,
        GradualDeployment,
        HttpManager,
        Layer7AccessControl,
        RateLimit,
        WaapComponent,
        IPSComp,
        KeywordComp
    > comps;

    comps.registerGlobalValue<bool>("Is Rest primary routine", true);
    comps.registerGlobalValue<uint>("Nano service API Port Range start", 12000);
    comps.registerGlobalValue<uint>("Nano service API Port Range end", 13000);
    return comps.run("HTTP Transaction Handler", argc, argv);
}

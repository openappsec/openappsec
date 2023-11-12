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

#ifndef __DETAILS_RESOLVER_HANDLER_CC__
#error details_resolver_handlers/details_resolver_impl.h should not be included directly.
#endif // __DETAILS_RESOLVER_HANDLER_CC__

// Retrieve artifacts by incorporating nano service names into additional metadata:
// To include a required nano service in the additional metadata sent to the manifest generator,
// add a handler in this file. The key to use is 'requiredNanoServices', and its value should be
// a string representing an array of nano service prefix names, separated by semicolons.
// For example: "httpTransactionHandler_linux;iotSnmp_gaia;"
//
// Handler example for reading the content of a configuration file:
// FILE_CONTENT_HANDLER("requiredNanoServices", "/tmp/nano_services_list", getRequiredNanoServices)

// use SHELL_CMD_HANDLER(key as string, shell command as string, ptr to Maybe<string> handler(const string&))
// to return a string value for an attribute key based on a logic executed in a handler that receives
// shell command execution output as its input
#ifdef SHELL_CMD_HANDLER
#if defined(gaia) || defined(smb)
SHELL_CMD_HANDLER("cpProductIntegrationMgmtObjectType", "cpprod_util CPPROD_IsMgmtMachine", getMgmtObjType)
SHELL_CMD_HANDLER("isCpviewRunning",
    "pidof cpview_api_service > /dev/null 2>&1 && [ -f $CPDIR/conf/cpview_api_service.version ] "
    "&& echo 'true' || echo 'false'",
    checkIsCpviewRunning)
SHELL_CMD_HANDLER("isCPotelcolGRET64",
    "grep -A 10 '(BUNDLE_CPOTELCOL_AUTOUPDATE' ${CPDIR}/registry/HKLM_registry.data | "
    "awk '/SU_Build_Take/{val = substr($2, 2, length($2)-2); if (val >=64) print \"true\"; else print \"false\" }'",
    checkIsCPotelcolGRET64)
SHELL_CMD_HANDLER("hasSDWan", "[ -f $FWDIR/bin/sdwan_steering ] && echo '1' || echo '0'", checkHasSDWan)
SHELL_CMD_HANDLER(
    "canUpdateSDWanData",
    "CPSDWAN_NOLOGS=1 cpsdwan get_data -f can_update_sdwan_data | jq -r .can_update_sdwan_data",
    checkCanUpdateSDWanData
)
SHELL_CMD_HANDLER(
    "isSdwanRunning",
    "[ -v $(pidof cp-nano-sdwan) ] && echo 'false' || echo 'true'",
    checkIfSdwanRunning)
SHELL_CMD_HANDLER(
    "IP Address",
    "cpsdwan get_data | jq -r .main_ip",
    getGWIPAddress
)
SHELL_CMD_HANDLER(
    "Version",
    "cat /etc/cp-release | grep -oE 'R[0-9]+(\\.[0-9]+)?'",
    getGWVersion
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectIP",
    "obj=\"$(cpsdwan get_data | jq -r .cluster_name)\";"
    " awk -v obj=\"$obj\" '$1 == \":\" && $2 == \"(\" obj, $1 == \":ip_address\" { if ($1 == \":ip_address\")"
    " { gsub(/[()]/, \"\", $2); print $2; exit; } }'"
    " $FWDIR/state/local/FW1/local.gateway_cluster",
    getClusterObjectIP
)
#endif //gaia || smb

#if defined(gaia)
SHELL_CMD_HANDLER("hasSupportedBlade", "enabled_blades", checkHasSupportedBlade)
SHELL_CMD_HANDLER("hasSamlPortal", "mpclient status saml-vpn", checkSamlPortal)
SHELL_CMD_HANDLER("requiredNanoServices", "ida_gaia", getIDAGaia)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectName",
    "cat $FWDIR/database/myself_objects.C "
    "| awk -F '[:()]' '/:cluster_object/ {found=1; next} found && /:Name/ {print $3; exit}'",
    getMgmtParentObjName
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectUid",
    "cat $FWDIR/database/myself_objects.C "
    "| awk -F'[{}]' '/:cluster_object/ { found=1; next } found && /:Uid/ { uid=tolower($2); print uid; exit }'",
    getMgmtParentObjUid
)
SHELL_CMD_HANDLER(
    "Hardware",
    "cat $FWDIR/database/myself_objects.C | awk -F '[:()]' '/:appliance_type/ {print $3}' | head -n 1",
    getGWHardware
)
SHELL_CMD_HANDLER(
    "Application Control",
    "cat $FWDIR/database/myself_objects.C | awk -F '[:()]' '/:application_firewall_blade/ {print $3}' | head -n 1",
    getGWApplicationControlBlade
)
SHELL_CMD_HANDLER(
    "URL Filtering",
    "cat $FWDIR/database/myself_objects.C | awk -F '[:()]' '/:advanced_uf_blade/ {print $3}' | head -n 1",
    getGWURLFilteringBlade
)
SHELL_CMD_HANDLER(
    "IPSec VPN",
    "cat $FWDIR/database/myself_objects.C | awk -F '[:()]' '/:VPN_1/ {print $3}' | head -n 1",
    getGWIPSecVPNBlade
)
#endif //gaia

#if defined(smb)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectName",
    "cpsdwan get_data | jq -r .cluster_name",
    getSmbMgmtParentObjName
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectUid",
    "cpsdwan get_data | jq -r .cluster_uuid",
    getSmbMgmtParentObjUid
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtObjectName",
    "cpprod_util FwIsLocalMgmt",
    getSmbObjectName
)
SHELL_CMD_HANDLER(
    "Application Control",
    "cat $FWDIR/conf/active_blades.txt | grep -o 'APCL [01]' | cut -d ' ' -f2",
    getSmbGWApplicationControlBlade
)
SHELL_CMD_HANDLER(
    "URL Filtering",
    "cat $FWDIR/conf/active_blades.txt | grep -o 'URLF [01]' | cut -d ' ' -f2",
    getSmbGWURLFilteringBlade
)
SHELL_CMD_HANDLER(
    "IPSec VPN",
    "cat $FWDIR/conf/active_blades.txt | grep -o 'IPS [01]' | cut -d ' ' -f2",
    getSmbGWIPSecVPNBlade
)
#endif//smb

SHELL_CMD_OUTPUT("kernel_version", "uname -r")
SHELL_CMD_OUTPUT("helloWorld", "cat /tmp/agentHelloWorld 2>/dev/null")
#endif // SHELL_CMD_OUTPUT


// use FILE_CONTENT_HANDLER(key as string, path to file as string, ptr to Maybe<string> handler(ifstream&))
// to return a string value for an attribute key based on a logic executed in a handler that receives file as input
#ifdef FILE_CONTENT_HANDLER

#if defined(gaia)

FILE_CONTENT_HANDLER("hasIdpConfigured", "/opt/CPSamlPortal/phpincs/spPortal/idpPolicy.xml", checkIDP)
FILE_CONTENT_HANDLER(
    "cpProductIntegrationMgmtObjectName",
    (getenv("FWDIR") ? string(getenv("FWDIR")) : "") + "/database/myown.C",
    getMgmtObjName
)
#endif //gaia

#if defined(alpine)
FILE_CONTENT_HANDLER("alpine_tag", "/usr/share/build/cp-alpine-tag", getCPAlpineTag)
#endif // alpine
#if defined(gaia) || defined(smb)
FILE_CONTENT_HANDLER("os_release", "/etc/cp-release", getOsRelease)
FILE_CONTENT_HANDLER(
    "cpProductIntegrationMgmtObjectUid",
    (getenv("FWDIR") ? string(getenv("FWDIR")) : "") + "/database/myown.C",
    getMgmtObjUid
)
#else // !(gaia || smb)
FILE_CONTENT_HANDLER("os_release", "/etc/os-release", getOsRelease)
#endif // gaia || smb

FILE_CONTENT_HANDLER("AppSecModelVersion", "/etc/cp/conf/waap/waap.data", getWaapModelVersion)

#endif // FILE_CONTENT_HANDLER

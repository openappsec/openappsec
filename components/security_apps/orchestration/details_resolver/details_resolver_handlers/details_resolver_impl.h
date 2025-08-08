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

#ifdef SHELL_PRE_CMD
#if defined(gaia) || defined(smb) || defined(smb_thx_v3) || defined(smb_sve_v2) || defined(smb_mrv_v1)
SHELL_PRE_CMD("read sdwan data",
    "(cpsdwan get_data > /tmp/cpsdwan_getdata_orch.json~) "
    "&& (mv /tmp/cpsdwan_getdata_orch.json~ /tmp/cpsdwan_getdata_orch.json)")
#endif //gaia || smb
#if defined(smb)
SHELL_PRE_CMD("gunzip local.cfg", "gunzip -c $FWDIR/state/local/FW1/local.cfg.gz > /tmp/local.cfg")
#endif  //smb
#endif

#ifdef SHELL_CMD_HANDLER
#if defined(gaia) || defined(smb) || defined(smb_thx_v3) || defined(smb_sve_v2) || defined(smb_mrv_v1)
SHELL_CMD_HANDLER("cpProductIntegrationMgmtObjectType", "cpprod_util CPPROD_IsMgmtMachine", getMgmtObjType)
SHELL_CMD_HANDLER("prerequisitesForHorizonTelemetry",
    "FS_PATH=<FILESYSTEM-PREFIX>; [ -f ${FS_PATH}/cp-nano-horizon-telemetry-prerequisites.log ] "
    "&& head -1 ${FS_PATH}/cp-nano-horizon-telemetry-prerequisites.log || echo ''",
    checkIsInstallHorizonTelemetrySucceeded)
SHELL_CMD_HANDLER(
    "IS_AIOPS_RUNNING",
    "FS_PATH=<FILESYSTEM-PREFIX>; "
    "PID=$(ps auxf | grep -v grep | grep -E ${FS_PATH}.*cp-nano-horizon-telemetry | awk -F' ' '{printf $2}'); "
    "[ -z \"${PID}\" ] && echo 'false' || echo 'true'",
    getIsAiopsRunning)
#endif
#if defined(gaia)
SHELL_CMD_HANDLER("GLOBAL_QUID", "[ -d /opt/CPquid ] "
    "&& python3 /opt/CPquid/Quid_Api.py -i /opt/CPotelcol/quid_api/get_global_id.json | jq -r .message || echo ''",
    getQUID)
SHELL_CMD_HANDLER("QUID", "FS_PATH=<FILESYSTEM-PREFIX>;"
    "VS_ID=$(echo \"${FS_PATH}\" | grep -o -E \"vs[0-9]+\" | grep -o -E \"[0-9]+\");"
    "[ -z \"${VS_ID}\" ] && "
    "(python3 /opt/CPquid/Quid_Api.py -i /opt/CPotelcol/quid_api/get_global_id.json | jq -r .message || echo '');"
    "[ -n \"${VS_ID}\" ] && "
    "(sed \"s|###VS_ID###|${VS_ID}|g\" /opt/CPotelcol/quid_api/get_vs_quid.json"
    " > /opt/CPotelcol/quid_api/get_vs_quid.json.${VS_ID}); "
    "[ -n \"${VS_ID}\" ] && [ -f /opt/CPotelcol/quid_api/get_vs_quid.json.${VS_ID} ] && "
    "(python3 /opt/CPquid/Quid_Api.py -i "
    "/opt/CPotelcol/quid_api/get_vs_quid.json.${VS_ID} | jq -r .message[0].QUID || echo '');",
    getQUID)
SHELL_CMD_HANDLER("SMO_QUID", "[ -d /opt/CPquid ] "
    "&& python3 /opt/CPquid/Quid_Api.py -i "
    "/opt/CPotelcol/quid_api/get_smo_quid.json | jq -r .message[0].SMO_QUID || echo ''",
    getQUID)
SHELL_CMD_HANDLER("MGMT_QUID", "[ -d /opt/CPquid ] "
    "&& python3 /opt/CPquid/Quid_Api.py -i "
    "/opt/CPotelcol/quid_api/get_mgmt_quid.json | jq -r .message[0].MGMT_QUID || echo ''",
    getQUID)
SHELL_CMD_HANDLER("AIOPS_AGENT_ROLE", "[ -d /opt/CPOtlpAgent/custom_scripts ] "
    "&& ENV_NO_FORMAT=1 /opt/CPOtlpAgent/custom_scripts/agent_role.sh",
    getOtlpAgentGaiaOsRole)
SHELL_CMD_HANDLER("ETH_MGMT_IP",
    "FS_PATH=<FILESYSTEM-PREFIX>;"
    "VS_ID=$(echo \"${FS_PATH}\" | grep -o -E \"vs[0-9]+\" | grep -o -E \"[0-9]+\");"
    "[ -z \"${VS_ID}\" ] && "
    "(eth=\"$(grep 'management:interface' /config/active | awk '{print $2}')\" &&"
    " ip addr show \"${eth}\" | grep inet | awk '{print $2}' | cut -d '/' -f1) || "
    "(ip a | grep UP | grep -v lo | head -n 1 | cut -d ':' -f2 | tr -d ' ')",
    getInterfaceMgmtIp)
#endif
#if defined(smb) || defined(smb_thx_v3) || defined(smb_sve_v2) || defined(smb_mrv_v1)
SHELL_CMD_HANDLER("GLOBAL_QUID",
    "cat $FWDIR/database/myown.C "
    "| awk -F'[()]' '/:name/ { found=1; next } found && /:uuid/ { uid=tolower($2); print uid; exit }'",
    getQUID)
SHELL_CMD_HANDLER("QUID",
    "cat $FWDIR/database/myown.C "
    "| awk -F'[()]' '/:name/ { found=1; next } found && /:uuid/ { uid=tolower($2); print uid; exit }'",
    getQUID)


SHELL_CMD_HANDLER("SMO_QUID", "echo ''", getQUID)
SHELL_CMD_HANDLER("MGMT_QUID", "echo ''", getQUID)
SHELL_CMD_HANDLER("AIOPS_AGENT_ROLE", "echo 'SMB'", getOtlpAgentGaiaOsRole)
#endif
#if defined(gaia) || defined(smb) || defined(smb_thx_v3) || defined(smb_sve_v2) || defined(smb_mrv_v1)
SHELL_CMD_HANDLER("hasSDWan", "[ -f $FWDIR/bin/sdwan_steering ] && echo '1' || echo '0'", checkHasSDWan)
SHELL_CMD_HANDLER(
    "canUpdateSDWanData",
    "jq -r .can_update_sdwan_data /tmp/cpsdwan_getdata_orch.json",
    checkCanUpdateSDWanData
)
SHELL_CMD_HANDLER(
    "isSdwanRunning",
    "[ -v $(pidof cp-nano-sdwan) ] && echo 'false' || echo 'true'",
    checkIfSdwanRunning)
SHELL_CMD_HANDLER(
    "lsmProfileName",
    "jq -r .lsm_profile_name /tmp/cpsdwan_getdata_orch.json",
    checkLsmProfileName
)
SHELL_CMD_HANDLER(
    "lsmProfileUuid",
    "jq -r .lsm_profile_uuid /tmp/cpsdwan_getdata_orch.json",
    checkLsmProfileUuid
)
SHELL_CMD_HANDLER(
    "Version",
    "cat /etc/cp-release | grep -oE 'R[0-9]+(\\.[0-9]+)?'",
    getGWVersion
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectIP",
    "obj=\"$(jq -r .cluster_name /tmp/cpsdwan_getdata_orch.json)\";"
    " awk -v obj=\"$obj\" '$1 == \":\" && $2 == \"(\" obj, $1 == \":ip_address\" { if ($1 == \":ip_address\")"
    " { gsub(/[()]/, \"\", $2); print $2; exit; } }'"
    " $FWDIR/state/local/FW1/local.gateway_cluster",
    getClusterObjectIP
)
SHELL_CMD_HANDLER(
    "isFecApplicable",
    "fw ctl get int support_fec |& grep -sq \"support_fec =\";echo $?",
    getFecApplicable
)
SHELL_CMD_HANDLER("is_legacy_qos_blade_enabled",
    "cpprod_util CPPROD_GetValue FG1 ProdActive 1 | grep -q '^1$' "
    "&& (cpprod_util CPPROD_GetValue FG1 FgSDWAN 1 | grep -q '^1$' && echo false || echo true) || "
    "echo false",
    checkQosLegacyBlade)
#endif //gaia || smb

#if defined(gaia)
SHELL_CMD_HANDLER("hasSAMLSupportedBlade", "enabled_blades", checkSAMLSupportedBlade)
SHELL_CMD_HANDLER("hasIDABlade", "enabled_blades", checkIDABlade)
SHELL_CMD_HANDLER("hasVPNBlade", "enabled_blades", checkVPNBlade)
SHELL_CMD_HANDLER("hasSAMLPortal", "mpclient status nac", checkSAMLPortal)
SHELL_CMD_HANDLER("hasInfinityIdentityEnabled",
    "cat $FWDIR/database/myself_objects.C | grep get_identities_from_infinity_identity",
    checkInfinityIdentityEnabled
)
SHELL_CMD_HANDLER("requiredNanoServices", "echo ida", getRequiredNanoServices)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtObjectName",
    "mgmt_cli --format json -r true show-session | jq -r '.[\"connected-server\"].name'",
    getMgmtObjName
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtObjectUid",
    "mgmt_cli --format json -r true show-session | jq -r '.[\"connected-server\"].uid'",
    getMgmtObjUid
)
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
    "cat $FWDIR/database/myself_objects.C | awk -F '[:()]' '/:appliance_type/ {print $3}' | head -n 1 | sed 's/\"//g'",
    getHardware
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
SHELL_CMD_HANDLER(
    "SMCBasedMgmtId",
    "domain_uuid=$(jq -r .domain_uuid /tmp/cpsdwan_getdata_orch.json);"
    "[ \"$domain_uuid\" != \"null\" ] && echo \"$domain_uuid\" ||"
    "cat $FWDIR/database/myself_objects.C "
    "| awk -F'[{}]' '/:masters/ { found=1; next } found && /:Uid/ { uid=tolower($2); print uid; exit }'",
    getSMCBasedMgmtId
)
SHELL_CMD_HANDLER(
    "SMCBasedMgmtName",
    "domain_name=$(jq -r .domain_name /tmp/cpsdwan_getdata_orch.json);"
    "[ \"$domain_name\" != \"null\" ] && echo \"$domain_name\" ||"
    "cat $FWDIR/database/myself_objects.C "
    "| awk -F '[:()]' '/:masters/ {found=1; next} found && /:Name/ {print $3; exit}'",
    getSMCBasedMgmtName
)
SHELL_CMD_HANDLER(
    "managements",
    "echo 1",
    extractManagements
)
SHELL_CMD_HANDLER(
    "IP Address",
    "( [ $(cpprod_util FwIsHighAvail) -eq 1 ] && [ $(cpprod_util FwIsVSX) -eq 1 ]"
    "&& (jq -r .cluster_main_ip /tmp/cpsdwan_getdata_orch.json) )"
    "|| ( [ $(cpprod_util FWisDAG) -eq 1 ] && echo \"Dynamic Address\" )"
    "|| (jq -r .main_ip /tmp/cpsdwan_getdata_orch.json)",
    getGWIPAddress
)
#endif //gaia

#if defined(smb) || defined(smb_thx_v3) || defined(smb_sve_v2) || defined(smb_mrv_v1)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectName",
    "jq -r .cluster_name /tmp/cpsdwan_getdata_orch.json",
    getSmbMgmtParentObjName
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtParentObjectUid",
    "jq -r .cluster_uuid /tmp/cpsdwan_getdata_orch.json",
    getSmbMgmtParentObjUid
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtObjectName",
    "cpprod_util FwIsLocalMgmt",
    getSmbObjectName
)
SHELL_CMD_HANDLER(
    "cpProductIntegrationMgmtObjectUid",
    "cpprod_util FwIsLocalMgmt",
    getSmbObjectUid
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
SHELL_CMD_HANDLER(
    "SMCBasedMgmtId",
    "domain_uuid=$(jq -r .domain_uuid /tmp/cpsdwan_getdata_orch.json);"
    "[ \"$domain_uuid\" != \"null\" ] && echo \"$domain_uuid\" ||"
    "cat /tmp/local.cfg "
    "| awk -F'[{}]' '/:masters/ { found=1; next } found && /:Uid/ { uid=tolower($2); print uid; exit }'",
    getSMCBasedMgmtId
)

SHELL_CMD_HANDLER(
    "SMCBasedMgmtName",
    "domain_name=$(jq -r .domain_name /tmp/cpsdwan_getdata_orch.json);"
    "[ \"$domain_name\" != \"null\" ] && echo \"$domain_name\" ||"
    "cat /tmp/local.cfg "
    "| awk -F '[:()]' '/:masters/ {found=1; next} found && /:Name/ {print $3; exit}'",
    getSMCBasedMgmtName
)

SHELL_CMD_HANDLER(
    "managements",
    "echo 1",
    extractManagements
)
SHELL_CMD_HANDLER(
    "IP Address",
    "[ $(cpprod_util FWisDAG) -eq 1 ] && echo \"Dynamic Address\" "
    "|| (jq -r .main_ip /tmp/cpsdwan_getdata_orch.json)",
    getGWIPAddress
)
SHELL_CMD_HANDLER(
    "Hardware",
    R"(ver | sed -E 's/^This is Check Point'\''s +([^ ]+).*$/\1/')",
    getHardware
)
#endif//smb

SHELL_CMD_OUTPUT("kernel_version", "uname -r")
SHELL_CMD_OUTPUT("helloWorld", "cat /tmp/agentHelloWorld 2>/dev/null")
#endif // SHELL_CMD_OUTPUT


// use FILE_CONTENT_HANDLER(key as string, path to file as string, ptr to Maybe<string> handler(ifstream&))
// to return a string value for an attribute key based on a logic executed in a handler that receives file as input
#ifdef FILE_CONTENT_HANDLER

#if defined(gaia)
FILE_CONTENT_HANDLER(
    "hasIdpConfigured",
    (getenv("SAMLPORTAL_HOME") ? string(getenv("SAMLPORTAL_HOME")) : "") + "/phpincs/spPortal/idpPolicy.xml",
    checkIDP
)
FILE_CONTENT_HANDLER(
    "hasVPNCidpConfigured",
    (getenv("SAMLPORTAL_HOME") ? string(getenv("SAMLPORTAL_HOME")) : "") + "/phpincs/spPortal/idpPolicy.xml",
    checkVPNCIDP
)
#endif //gaia

#if defined(alpine)
FILE_CONTENT_HANDLER("alpine_tag", "/usr/share/build/cp-alpine-tag", getCPAlpineTag)
#endif // alpine
#if defined(gaia) || defined(smb)
FILE_CONTENT_HANDLER("os_release", "/etc/cp-release", getOsRelease)
#else // !(gaia || smb)
FILE_CONTENT_HANDLER("os_release", "/etc/os-release", getOsRelease)
#endif // gaia || smb

FILE_CONTENT_HANDLER("AppSecModelVersion", "<FILESYSTEM-PREFIX>/conf/waap/waap.data", getWaapModelVersion)

#endif // FILE_CONTENT_HANDLER

#ifdef SHELL_POST_CMD
#if defined(smb) || defined(smb_thx_v3) || defined(smb_sve_v2) || defined(smb_mrv_v1)
SHELL_POST_CMD("remove local.cfg", "rm -rf /tmp/local.cfg")
#endif  //smb
#endif

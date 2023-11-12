#!/bin/sh

FILESYSTEM_PATH="/etc/cp"
LOG_FILE_PATH="/var/log"
INIT_D_PATH="/etc/init.d"
USR_LIB_PATH="/usr/lib"
USR_SBIN_PATH="/usr/sbin"
CP_NANO_CTL="open-appsec-ctl"
BIN_PATH="bin"
CP_NANO_BASE64="cpnano_base64"
INSTALL_DIR_INDEX=1
DEFAULT_PORT_INDEX=2
DISPLAY_NAME_INDEX=3

SERVICE_PORTS_LIST_INDEX=4
PACKAGE_LIST_LINE_OFFSET=5

cp_nano_conf_location="conf"

AI_UPLOAD_TOO_LARGE_FLAG=false
SPLIT_FILE_SMALL_SIZE="900K"
AI_VERBOSE=false
PROFILE_SETTINGS_JSON_PATH=$cp_nano_conf_location/settings.json
DEFAULT_HEALTH_CHECK_TMP_FILE_PATH="/tmp/cpnano_health_check_output.txt"

var_default_gem_fog_address="inext-agents.cloud.ngen.checkpoint.com"
var_default_us_fog_address="inext-agents-us.cloud.ngen.checkpoint.com"
var_default_au_fog_address="inext-agents-aus1.cloud.ngen.checkpoint.com"
var_default_in_fog_address="inext-agents-ind1.cloud.ngen.checkpoint.com"

#NOTE: open-appsec-ctl only supports nano services with name of the format cp-nano-<service>
cp_nano_service_name_prefix="cp-nano"

cp_nano_conf_suffix="conf.json"
cp_nano_debug_suffix="debug-conf.json"
cp_nano_conf_file="cp-nano-orchestration-conf.json"
cp_nano_watchdog="watchdog/cp-nano-watchdog"

CP_SCRIPTS_PATH="scripts"
CP_AGENT_INFO_NAME="cp-agent-info"
CP_NANO_PACKAGE_LIST_NAME="cp-nano-package-list"
CP_NANO_DEBUG_NAME="cpnano_debug"
CP_PICOJSON_PATH="bin/cpnano_json"

GREEN='\033[0;32m'
RED='\033[0;31m'
NO_COLOR='\033[0m'

pidof_cmd="pidof -x"
is_alpine_release=

var_last_policy_modification_time=0

ls -l /etc/ | grep release > /dev/null 2>&1
retval=$?

if [ $retval -eq 0 ]; then
    if cat /etc/*release | grep -q alpine; then
        is_alpine_release=1
        pidof_cmd="pidof"
    fi
fi

ARCHITECTURE=$(arch)
if [ -z ${ARCHITECTURE} ]; then
    ARCHITECTURE=$(uname -a | awk '{print $(NF -1) }')
fi

LD_LIBRARY_PATH_ADD=""
is_smb_release=0
if [ -f /pfrm2.0/bin/cposd ]; then
    is_smb_release=1
    pidof_cmd="/pfrm2.0/bin/nano_pidof"
    if [ `fw_printenv -n sub_hw_ver` = "THX2" ]; then
        LD_LIBRARY_PATH_ADD=":/lib64:/pfrm2.0/lib64"
    fi
fi

curl_cmd=curl
remove_curl_ld_path=false
is_gaia=
if [ $retval -eq 0 ]; then
    if [ -n "$(echo ${ARCHITECTURE} | grep "x86")" ]; then
        remove_curl_ld_path=true
    fi

    if cat /etc/*release | grep -q "Gaia"; then
        is_gaia=1
        remove_curl_ld_path=false
        curl_cmd=curl_cli
    fi
fi

get_basename()
{
    is_basename_exist=$(command -v basename)
    if [ -n $is_basename_exist ]; then
        echo $(basename $1)
    else
        echo $(echo $1 | rev | cut -d / -f 1 | rev)
    fi
}

load_paths()
{
    [ -f /etc/environment ] && . "/etc/environment"

    [ -f ${FILESYSTEM_PATH}/conf/environment-details.cfg ] && . "${FILESYSTEM_PATH}/conf/environment-details.cfg"

    if [ -n "${CP_ENV_FILESYSTEM}" ]; then
        FILESYSTEM_PATH=$CP_ENV_FILESYSTEM
    fi
    if [ -n "${CP_ENV_LOG_FILE}" ]; then
        LOG_FILE_PATH=$CP_ENV_LOG_FILE
    fi
    if [ -n "${CP_INIT_D_PATH}" ]; then
        INIT_D_PATH=$CP_INIT_D_PATH
    fi
    if [ -n "${CP_USR_LIB_PATH}" ]; then
        USR_LIB_PATH=$CP_USR_LIB_PATH
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CP_USR_LIB_PATH/cpnano
    fi
}

load_paths

AGENT_POLICY_PATH="${FILESYSTEM_PATH}/${cp_nano_conf_location}/policy.json"
CUSTOM_POLICY_CONF_FILE="${FILESYSTEM_PATH}/${cp_nano_conf_location}/custom_policy.cfg"
if [ -f ${CUSTOM_POLICY_CONF_FILE} ]; then
    . $CUSTOM_POLICY_CONF_FILE
else
    var_policy_file="${FILESYSTEM_PATH}/${cp_nano_conf_location}/local_policy.yaml"
fi

is_arm32=
if [ -n "$(uname -a | grep armv7l)" ]; then
    pidof_cmd="pidof"
    is_arm32=1
fi

# Load package variables and parse into ${all_services}
. "${FILESYSTEM_PATH}/${CP_SCRIPTS_PATH}/${CP_NANO_PACKAGE_LIST_NAME}"

all_services=""

lines_to_skip=$((PACKAGE_LIST_LINE_OFFSET))
{
    while [ $lines_to_skip -ne 0 ]; do
        read -r line
        lines_to_skip=$((lines_to_skip - 1))
    done
    while read -r line; do
        service_name="$(echo "$line" | cut -d "=" -f1 | tr "_" "-")"
        all_services="${all_services} $service_name"
    done
} <"${FILESYSTEM_PATH}/${CP_SCRIPTS_PATH}/${CP_NANO_PACKAGE_LIST_NAME}"

is_valid_var_name() # Initials - ivvn
{
    ivvn_var_name=$1
    # Check that string $ivvn_var_name is a valid variable name
    # 	[[:alnum:]] - Alphanumeric [a-z A-Z 0-9]
    if [ -z "$ivvn_var_name" ] ||                                                           # empty
        [ -n "$(printf "%s" "$ivvn_var_name" | sed 's/[[:alnum:]]//g' | sed 's/_//g')" ] || # does not contains only alnums and '_' chars
        [ -z "$(printf "%s" "$ivvn_var_name" | sed "s/[[:digit:]].*//")" ]; then            # starts with a digit
        echo false
    else
        echo true
    fi
}

get_nano_service_location_and_port() # Initials - gnslap
{
    gnslap_service_name="$(echo "$1" | tr "-" "_")"

    if [ "$(is_valid_var_name "$gnslap_service_name")" = "false" ]; then
        return
    fi
    eval "gnslap_nano_service=\"\$$gnslap_service_name\""
    if [ -z "$gnslap_nano_service" ]; then
        return
    fi
    echo "$gnslap_nano_service"
}

get_nano_service_install_dir() # Initials - gnsid
{
    gnsid_service_name="$1"
    gnsid_nano_service="$(get_nano_service_location_and_port "$gnsid_service_name")"
    if [ -z "$gnsid_nano_service" ]; then
        return
    fi
    echo "${gnsid_nano_service}" | cut -d" " -f${INSTALL_DIR_INDEX}
}

get_nano_service_display_name() # Initials - gnsdn
{
    gnsdn_service_name="$1"
    gnsdn_nano_service="$(get_nano_service_location_and_port "$gnsdn_service_name")"
    if [ -z "$gnsdn_nano_service" ]; then
        return
    fi
    echo "${gnsdn_nano_service}" | cut -sd" " -f${DISPLAY_NAME_INDEX}
}

starts_with() # Initials - sw
{
    sw_str=$1
    sw_prefix=$2
    if [ -z "$(echo "$sw_str" | sed 's|^'"$sw_prefix"'.*||')" ]; then
        echo true
    else
        echo false
    fi
}

get_nano_service_path() # Initials - gnsp
{
    gnsp_service_name=$1
    if [ -z "$gnsp_service_name" ] || [ -z "$(get_nano_service_location_and_port "$gnsp_service_name")" ]; then
        return
    fi

    gnsp_path_prefix=${FILESYSTEM_PATH}/
    gnsp_nano_service_install_dir=$(get_nano_service_install_dir "$gnsp_service_name")
    gnsp_service_path=${gnsp_path_prefix}${gnsp_nano_service_install_dir}"/"${cp_nano_service_name_prefix}-${gnsp_service_name}
    echo "$gnsp_service_path"
}

get_installed_services() # Initials - gis
{
    gis_delimiter=$1
    if [ -z "$gis_delimiter" ]; then
        gis_delimiter=' '
    fi

    gis_installed_services=""
    for service in $all_services; do
        gis_service_full_path=$(get_nano_service_path "$service")
        if [ ! -e "$gis_service_full_path" ]; then
            continue
        elif [ -z "$gis_installed_services" ]; then
            gis_installed_services="$service"
        else
            gis_installed_services="${gis_installed_services}${gis_delimiter}${service}"
        fi
    done
    echo "${gis_installed_services}"
}

max_num()
{
    if [ "$1" -gt "$2" ]; then
        echo "$1"
    else
        echo "$2"
    fi
}

usage()
{
    debug_option="-d,  --debug"
    status_option="-s,  --status [--extended]"
    proxy_option="-sp,  --set-proxy"
    start_agent_option="-r,  --start-agent"
    stop_agent_option="-q,  --stop-agent"
    start_service_option="-rs,  --start-service"
    stop_service_option="-qs,  --stop-service"
    uninstall_option="-u,  --uninstall"
    load_config_option="-lc, --load-config <$(get_installed_services '|')>"
    display_config_option="-dc, --display-config [$(get_installed_services '|')]"
    cp_agent_info_option="--info [-wd|--with_dump|-u|--upload|-fms|--file_max_size|-an|--additional_name]"
    display_policy_option="-dp, --display-policy"
    set_gradual_policy_option="-gp, --set-gradual-policy [access-control|http-manager] <ip-ranges>"
    delete_gradual_policy_option="-dg, --delete-gradual-policy [access-control|http-manager]"
    set_public_key="-pk, --set-public-key <Public key file path>"
    set_traffic_recording_policy_option="-tr, --traffic-recording-policy <off|req_hdr|req_body|resp_hdr|resp_body>"
    print_metrics_option="-pm, --print-metrics <service>"
    view_policy_option="-vp, --view-policy [policy-file]"
    edit_policy_option="-ep, --edit-policy [policy-file]"
    apply_policy_option="-ap, --apply-policy [policy-file]"
    list_policy_option="-lp, --list-policies"
    view_logs_option="-vl, --view-logs"
    # Padding makes each comment to start a specific index, increase 'line_padding' when option length is bigger than pedding.
    line_padding='                                                                                                          '
    echo "Options:"
    printf "%s %s : View and change debug configuration\n" "$debug_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#debug_option})))")"
    printf "%s %s : Print agent status and versions\n" "$status_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#status_option})))")"
    printf "%s %s : Start the agent\n" "$start_agent_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#start_agent_option})))")"
    printf "%s %s : Stop the agent\n" "$stop_agent_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#stop_agent_option})))")"
    printf "%s %s : Start a service previously stopped\n" "$start_service_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#start_service_option})))")"
    printf "%s %s : Stop service\n" "$stop_service_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#stop_service_option})))")"
    printf "%s %s : Uninstall agent\n" "$uninstall_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#uninstall_option})))")"
    printf "%s %s : Open a policy file as read only\n" "$view_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#view_policy_option})))")"
    printf "%s %s : Open and edit a policy file\n" "$edit_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#edit_policy_option})))")"
    printf "%s %s : Apply a new policy file\n" "$apply_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#apply_policy_option})))")"
    printf "%s %s : View list of used policy files\n" "$list_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#list_policy_option})))")"
    printf "%s %s : View security logs\n" "$view_logs_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#view_logs_option})))")"
   # printf "%s %s : Load configuration\n" "$load_config_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#load_config_option})))")"
   # printf "%s %s : Set proxy\n" "$proxy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#proxy_option})))")"
   # printf "%s %s : Display configuration\n" "$display_config_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#display_config_option})))")"
    printf "%s %s : Create open-appsec agent info\n" "$cp_agent_info_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#cp_agent_info_option})))")"
   # printf "%s %s : Display current policy\n" "$display_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#display_policy_option})))")"
   # printf "%s %s : Load gradual policy\n" "$set_gradual_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#set_gradual_policy_option})))")"
   # printf "%s %s : Remove gradual policy\n" "$delete_gradual_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#delete_gradual_policy_option})))")"
   # printf "%s %s : Set the SSL certificate's public key file path (PEM format)\n" "$set_public_key" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#set_public_key})))")"
   # printf "%s %s : Set traffic recording policy\n" "$set_traffic_recording_policy_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#set_traffic_recording_policy_option})))")"
   # printf "%s %s : Print metrics report\n" "$print_metrics_option" "$(printf "%s" "$line_padding" | cut -c 1-"$(max_num 1 $((${#line_padding} - ${#print_metrics_option})))")"

    exit 255
}

get_profile_setting() # Initials - gps
{
    gps_key=$1
    gps_default_value=$2
    gps_value=$(cat ${FILESYSTEM_PATH}/${PROFILE_SETTINGS_JSON_PATH} | ${FILESYSTEM_PATH}/${CP_PICOJSON_PATH} | grep "\"key\": \"${gps_key}\"" -A1 | grep \"value\")

    if [ -z "${gps_value}" ]; then
        gps_value=${gps_default_value}
    else
        gps_valueWithQuotationMarks="$(echo "$gps_value" | sed 's/\"gps_value\": \"//g')"
        gps_value=${gps_valueWithQuotationMarks%?}
    fi

    echo "${gps_value}"
}

curl_func() # Initials - cf
{
    cf_port=$1
    cf_data=$2
    if [ -z "$cf_data" ]; then
        cf_data="{}"
    fi

    if [ "${remove_curl_ld_path}" = "true" ]; then
        echo "$(LD_LIBRARY_PATH="" ${curl_cmd} -sS --noproxy "*" --header "Content-Type: application/json" --request POST --data "$cf_data" http://127.0.0.1:"$cf_port" 2>&1)"
    else
        echo "$(${curl_cmd} -sS --noproxy "*" --header "Content-Type: application/json" --request POST --data "$cf_data" http://127.0.0.1:"$cf_port" 2>&1)"
    fi
}

get_registered_services_ports() # Initails - grsp
{
    grsp_orchestration_port=$1
    grsp_ports_and_services=$(curl_func "${grsp_orchestration_port}"/show-all-service-ports)
    if echo "$grsp_ports_and_services" | grep -q "Connection refused"; then
        echo "Failed to reach orchestration" >&2
        echo ""
        return
    fi
    echo "$grsp_ports_and_services" | cut -d '"' -f"$SERVICE_PORTS_LIST_INDEX"
}

extract_default_api_port() # Initials - edap
{
    edap_service_name=$1
    edap_nano_service="$(get_nano_service_location_and_port "$edap_service_name")"
    if [ -z "$edap_nano_service" ]; then
        return
    fi
    echo "$edap_nano_service" | cut -d " " -f"$DEFAULT_PORT_INDEX"
}

is_requested_service() # Initials - irs
{
    irs_requested_service=$(echo "$1" | sed 's/-//g' | tr '[:upper:]' '[:lower:]')
    irs_possible_service=$(echo "$2" | sed 's/-//g' | tr '[:upper:]' '[:lower:]')
    if [ "$irs_requested_service" = "$irs_possible_service" ]; then
        echo true
        return
    fi
    echo false
}

extract_api_port() # Initials - eap
{
    eap_service_name=$1
    eap_orchestration_port=$(extract_default_api_port orchestration)
    if [ "$eap_service_name" = "orchestration" ]; then
        echo "$eap_orchestration_port"
        return
    fi

    for pair in $(get_registered_services_ports "$eap_orchestration_port" | tr "," " "); do
        eap_service="$(echo "$pair" | cut -d ':' -f1)"
        if [ "$(is_requested_service "$eap_service_name" "$eap_service")" = true ]; then
            echo "$pair" | cut -d ':' -f2
            return
        fi
    done

    extract_default_api_port "$eap_service_name"
}

extract_json_field_value() # Initials - ejfv
{
    ejfv_json_object="$1"
    ejfv_field_name="$2"

    ejfv_value=$(printf "%s" "$ejfv_json_object" | grep -A 3 "$ejfv_field_name" | grep "value" | cut -d : -f 2 | head -1)

    echo "$ejfv_value"
}

get_setting() # Initials - gs
{
    gs_service_name="$1"
    gs_setting_name="$2"
    gs_service_settings="$(run_display_settings "$gs_service_name")"

    gs_setting_value=$(extract_json_field_value "$gs_service_settings" "$gs_setting_name")

    echo "$gs_setting_value"
}

is_userspace_running() # Initials - iur
{
    iur_service_name=$1
    if [ -z "$iur_service_name" ]; then
        echo false
        return
    fi

    iur_full_service_name="${cp_nano_service_name_prefix}-${iur_service_name}"

    if [ "$(${pidof_cmd} "$iur_full_service_name")" ] || [ "$(${pidof_cmd} "$iur_full_service_name".bin)" ] || [ "$(${pidof_cmd} $(get_basename "$iur_full_service_name"))" ]; then
        echo true
    elif [ -n "${is_arm32}" ] && [ -n "$(ps | grep "${cp_nano_service_name_prefix}-${iur_service_name}" | grep -v grep)" ]; then
        echo true
    else
        echo false
    fi
}

signal_reload_nano_service_settings() # Initials - srnss_
{
    srnss_service_name=$1
    if [ -z "$srnss_service_name" ]; then
        echo false
        return
    fi

    srnss_full_service_name="$cp_nano_service_name_prefix-$srnss_service_name"
    srnss_service_pids="$(${pidof_cmd} "$srnss_full_service_name".bin)"
    if [ -z "$srnss_service_pids" ]; then
        srnss_service_pids="$(${pidof_cmd} "$srnss_full_service_name")"
        if [ -z "$srnss_service_pids" ]; then
            echo false
            return
        fi
    fi

    for pid in $srnss_service_pids; do
        kill -s USR2 "$pid"
    done
    echo true
}

run_prettify_json() # Initials - rpj
{
    rpj_file_paths=$(echo "$1" | sed 's/,/ /g')
    for file in $rpj_file_paths; do
        if [ -f "$file" ]; then
            echo "$file:"
            printf '%*s\n' "$((${#file} + 1))" " " | tr ' ' "-"
            cat <"$file" | ${FILESYSTEM_PATH}/$CP_PICOJSON_PATH
        fi
    done
}

read_agent_run_status() # Initials - rars
{
    # give the watchdog time to update the status
    if [ -n "${is_arm32}" ]; then
        rars_timeout_cmd="timeout -t"
    else
        rars_timeout_cmd="timeout"
    fi
    rars_waiting="${rars_timeout_cmd} 1 sh -c -- 'while [  ! -f /tmp/agent-status.txt -o ! -s /tmp/agent-status.txt  ]; do :; done;'"
    eval "$rars_waiting"

    rars_output=$(tail -n 1 /tmp/agent-status.txt)
    if [ "$1" = "start" ]; then
        if [ "$rars_output" = "running" ]; then
            echo "open-appsec Nano Agent watchdog started successfully"
        else
            echo "open-appsec Nano Agent is already running"
        fi
    else # "$1" = "stop"
        if [ "$rars_output" = "down" ]; then
            echo "open-appsec Nano Agent stopped successfully"
        else
            echo "open-appsec Nano Agent is not running"
        fi
    fi
}

run_start_agent()
{
    if [ -d ${FILESYSTEM_PATH}/watchdog ]; then
        if [ -n "${is_gaia}" ]; then
            dbset process:cp-nano-watchdog t
            dbset process:cp-nano-watchdog:path ${FILESYSTEM_PATH}/watchdog
            dbset process:cp-nano-watchdog:arg:1 --gaia
            dbset :save
            tellpm cp-nano-watchdog t
        elif [ "$is_smb_release" = "1" ]; then
            /storage/nano_agent/etc/nano_agent.init start
        else
            touch /tmp/agent-status.txt
            if [ -f $INIT_D_PATH/nano_agent.init ]; then
                $INIT_D_PATH/nano_agent.init start
            else
                service nano_agent start
            fi
            read_agent_run_status start
            rm -rf /tmp/agent-status.txt
        fi
    else
        echo "nano agent is not installed"
    fi
}

run_stop_agent()
{
    if [ -n "${is_alpine_release}" ]; then
        echo "Cannot stop the agent in container execution mode"
    elif [ -n "${is_gaia}" ]; then
        dbset process:cp-nano-watchdog
        dbset process:cp-nano-watchdog:path
        dbset :save
        tellpm cp-nano-watchdog
    elif [ "$is_smb_release" = "1" ]; then
        /storage/nano_agent/etc/nano_agent.init stop
    else
        touch /tmp/agent-status.txt
        if [ -f $INIT_D_PATH/nano_agent.init ]; then
            $INIT_D_PATH/nano_agent.init stop
        else
            service nano_agent stop
        fi
        read_agent_run_status stop
        rm -rf /tmp/agent-status.txt
    fi
}

uninstall_agent() # Initials - ua
{
    printf "Are you sure you want to uninstall open-appsec Nano Agent? (Y/N): " && read -r ua_confirm
    case $ua_confirm in
    [Yy] | [Yy][Ee][Ss]) ;;
    *) exit 1 ;;
    esac
    AGENT_UNINSTALL="cp-agent-uninstall.sh"
    ua_uninstall_script="${FILESYSTEM_PATH}/$CP_SCRIPTS_PATH/$AGENT_UNINSTALL"
    if [ ! -f "$ua_uninstall_script" ]; then
        echo "Failed to uninstall Orchestration Nano Service, uninstall script was not found in: $ua_uninstall_script "
        exit 1
    fi
    ${ua_uninstall_script}
    if test "$?" = "0"; then
        echo "open-appsec Nano Agent successfully uninstalled"
    else
        echo "Failed to uninstall open-appsec Nano Agent"
        exit 1
    fi
}

run_update_gradual_policy() # Initials - rugp
{
    # set/delete
    rugp_mod=$1
    shift

    rugp_service_name=$1
    shift

    rugp_gp_usage="Usage: open-appsec-ctl -gp|--set-gradual-policy [access-control|http-manager] <ip-ranges>"
    rugp_success_message="Gradual policy for $rugp_service_name was set successfully"
    if [ "$rugp_mod" = "delete" ]; then
        rugp_gp_usage="Usage: open-appsec-ctl -dg|--delete-gradual-policy [access-control|http-manager]"
        rugp_success_message="Gradual policy for $rugp_service_name was deleted successfully"
    fi

    if [ -z "$rugp_service_name" ]; then
        echo "Error: no service provided"
        echo "$rugp_gp_usage"
        return
    fi
    if [ "$rugp_service_name" != "access-control" ] && [ "$rugp_service_name" != "http-manager" ]; then
        echo "Error: wrong service provided"
        echo "$rugp_gp_usage"
        return
    fi

    rugp_ip_ranges=""
    if [ "$rugp_mod" = "set" ]; then
        for parameter; do
            rugp_ip_ranges=$rugp_ip_ranges\"$parameter\",
        done
        rugp_ip_ranges=${rugp_ip_ranges%?}
        if [ -z "$rugp_ip_ranges" ]; then
            echo "Error: no ip-range provided"
            echo "$rugp_gp_usage"
            return
        fi
    fi

    rugp_data='{"attachment_type":"'${1}'", "ip_ranges":['${rugp_ip_ranges}']}'
    rugp_service_api_port=$(extract_api_port "$rugp_service_name")

    # Load gradual policy configuration
    rugp_errors=$(curl_func "${rugp_service_api_port}/set-gradual-deployment-policy" "${rugp_data}")
    sleep 1
    if [ -n "$(echo "$rugp_errors" | sed "s/$(printf '\r')//g")" ]; then
        echo "Failed to set gradual policy. Error: $rugp_errors"
        return
    fi
    if [ "$rugp_service_name" = "access-control" ]; then
        # Load policy to kernel
        rugp_errors=$(curl_func "${rugp_service_api_port}"/set-gradual-policy-to-kernel)
        if [ -n "$(echo "$rugp_errors" | sed "s/$(printf '\r')//g")" ]; then
            echo "Failed to set gradual policy. Error: $rugp_errors"
        else
            echo "$rugp_success_message"
        fi
        return
    fi
    # Reload NGINX
    rugp_errors=$(nginx -t 2>&1)
    if echo "$rugp_errors" | grep -q "failed"; then
        echo "Could not load nginx - configuration test failed"
        echo "Error: $rugp_errors"
        return
    fi
    nginx -s reload
    echo "$rugp_success_message"
}

run_set_traffic_recording_policy() # Initials - rstrp
{
    if [ "$1" != "off" ] && [ "$1" != "req_hdr" ] && [ "$1" != "req_body" ] && [ "$1" != "resp_hdr" ] && [ "$1" != "resp_body" ]; then
        printf "Error: Could not set up traffic recording.\nUsage: open-appsec-ctl <-tr|--traffic-recording> <off|req_hdr|req_body|resp_hdr|resp_body>\n"
        exit 1
    fi

    # Send signal to http_manager to update the traffic recording policy
    rstrp_data='{"traffic_recording_flags":["'$1'"]}'
    if [ "${remove_curl_ld_path}" = "true" ]; then
        LD_LIBRARY_PATH="" ${curl_cmd} --noproxy "*" --header "Content-Type: application/json" --request POST --data "$rstrp_data" http://127.0.0.1:"$(extract_api_port 'http-manager')"/set-traffic-recording-policy
    else
    ${curl_cmd} --noproxy "*" --header "Content-Type: application/json" --request POST --data "$rstrp_data" http://127.0.0.1:"$(extract_api_port 'http-manager')"/set-traffic-recording-policy
    fi
    sleep 1
}

is_policy_file()
{
    if [ ! -f "$maybe_policy_file" ] || [ -n "$(printf "%s" "$maybe_policy_file" | sed 's|'"${FILESYSTEM_PATH}/$cp_nano_conf_location"'.*\.json||')" ]; then
        echo "false"
    else
        echo "true"
    fi
}

display_single_service_policy_files() # Initials - dsspf
{
    dsspf_service_name=$1
    dsspf_service_full_path=$(get_nano_service_path "$dsspf_service_name")
    if [ ! -e "$dsspf_service_full_path" ]; then
        return
    fi

    execution_flags=""
    . "$dsspf_service_full_path".cfg

    for maybe_policy_file in $execution_flags; do
        if [ "$(is_policy_file "$maybe_policy_file")" = "false" ]; then
            continue
        else
            run_prettify_json "$maybe_policy_file"
        fi
    done
}

run_display_policy() # Initials - rdp
{
    for service in $all_services; do
        rdp_service_full_path=$(get_nano_service_path "$service")
        if [ -e "$rdp_service_full_path" ]; then
            display_single_service_policy_files "$service"
        fi
    done
}

format_nano_service_name() # Initials - fnsn
{
    fnsn_raw_service_name=$1
    fnsn_final_service_name=""

    fnsn_nano_service_display_name=$(get_nano_service_display_name "$fnsn_raw_service_name")
    if [ -n "$fnsn_nano_service_display_name" ]; then
        echo "$fnsn_nano_service_display_name" | tr '_' ' '
        return
    fi

    #Convert first character per word to uppercase
    fnsn_formated_service_name=$(echo "$fnsn_raw_service_name" | tr '-' '\n')
    for word in ${fnsn_formated_service_name}; do
        #Get and convert the first character to uppercase
        firstChar=$(echo ${word} | sed 's/\(.\).*/\1/' | tr '[a-z]' '[A-Z]')
        restCharacters=$(echo ${word} | sed 's/.\(.*\)/\1/')
        #Concatenate
        fnsn_final_service_name="${fnsn_final_service_name}${firstChar}${restCharacters} "
    done

    #Remove last space
    echo "$fnsn_final_service_name" | sed -r 's/.$//'
}

print_volatile_service_count() # Initials - pvsc
{
    pvsc_service_full_path=$1

    if [ ! -f ${FILESYSTEM_PATH}/watchdog/wd.volatile_services ]; then
        return
    fi

    pvsc_maybe_volotile_list=$(grep "$pvsc_service_full_path" ${FILESYSTEM_PATH}/watchdog/wd.volatile_services)
    if [ -z "$pvsc_maybe_volotile_list" ]; then
        return
    fi

    pvsc_prev_family_name="no-such-family-ever-exist"
    pvsc_registered_services_list=""
    for item in $pvsc_maybe_volotile_list; do
        pvsc_cur_family_name=$(echo "$item" | cut -d";" -f2)
        if [ "$pvsc_prev_family_name" = "$pvsc_cur_family_name" ]; then
            continue
        fi
        pvsc_prev_family_name="$pvsc_cur_family_name"
        pvsc_cur_family_count=$(echo "$pvsc_maybe_volotile_list" | tr " " "\n" | grep -c "${pvsc_service_full_path};${pvsc_cur_family_name};")
        if [ -z "$pvsc_registered_services_list" ]; then
            pvsc_registered_services_list="Registered Instances: ${pvsc_cur_family_count}"
        else
            pvsc_registered_services_list="${pvsc_registered_services_list}, ${pvsc_cur_family_count}"
        fi
    done
    echo "${pvsc_registered_services_list}"
}

print_metrics() # Initials - pm
{
    pm_service_name=$1
    pm_port=$2

    pm_errors=$(curl_func "${pm_port}"/show-metrics)
    if [ -n "$(echo "$pm_errors" | sed "s/$(printf '\r')//g")" ]; then
        return
    fi
    echo "--- $pm_service_name ---"
    cat /tmp/metrics_output.txt
    rm -rf /tmp/metrics_output.txt
}

run_print_metrics() # Initials - rpm
{
    rpm_service_name=$1
    if [ -n "${rpm_service_name}" ]; then
        rpm_is_userspace_process_running=$(is_userspace_running "$rpm_service_name")
        if [ "$rpm_is_userspace_process_running" = false ]; then
            echo "${rpm_service_name} is not running"
            return
        fi
    fi

    rpm_orchestration_port=$(extract_default_api_port orchestration)

    if [ -z "$rpm_service_name" ]; then
        print_metrics "Orchestration" "$rpm_orchestration_port"
        rpm_list=$(get_registered_services_ports "$rpm_orchestration_port" | tr "," " ")
        for pair in ${rpm_list}; do
            rpm_service=$(echo "$pair" | cut -d ':' -f1)
            print_metrics "$rpm_service" "$(echo "$pair" | cut -d ':' -f2)"
        done
    elif [ "$rpm_service_name" = "orchestration" ]; then
        print_metrics "Orchestration" "$rpm_orchestration_port"
    else
        rpm_port=$(extract_api_port "$rpm_service_name")
        print_metrics "$rpm_service_name" "$rpm_port"
    fi
}

run_health_check() # Initials - rhc
{
    rhc_orchestration_port=$(extract_default_api_port orchestration)

    rhc_errors=$(curl_func "${rhc_orchestration_port}"/show-health-check-on-demand)
    if [ -n "$(echo "$rhc_errors" | sed "s/$(printf '\r')//g")" ]; then
        return
    fi

    rhc_health_check_tmp_file_path=$(get_profile_setting agent.healthCheckOnDemandOutputTmpFile ${DEFAULT_HEALTH_CHECK_TMP_FILE_PATH})
    echo "---- Check Point extended health check status ----"
    cat "${rhc_health_check_tmp_file_path}"
    printf "\n"
    rm -rf "${rhc_health_check_tmp_file_path}"
}

print_link_information() # Initials - pli
{
    echo ""
    echo "For release notes and known limitations check: https://docs.openappsec.io/release-notes"
    echo "For troubleshooting and support: https://openappsec.io/support"
}

should_add_color_to_status() # Initials - sacts
{
    sacts_ps_cmd="ps aux"
    if [ -n "${is_arm32}" ]; then
        sacts_ps_cmd="ps"
    fi
    sacts_watch_commands="$(${sacts_ps_cmd} | grep "watch" | grep -E "cp-?nano" | grep "\-s")"
    if [ "$(printf "%b" "$sacts_watch_commands" | sed 's/\s//g')" ]; then
        if ! echo "$sacts_watch_commands" | grep -q -Ei "(\-\-color|\-c)\b"; then
            echo false
            return
        fi
    fi
    echo true
}

format_colored_status_line() # Initials - fcsl
{
    if [ "$(should_add_color_to_status)" = "true" ]; then
        fcsl_color=""
        if echo "$1" | grep -q "Not"; then fcsl_color="$RED"; else fcsl_color="$GREEN"; fi
        printf "$fcsl_color%s$NO_COLOR\n" "$1"
    else
        printf "%s\n" "$1"
    fi
}

print_single_service_status() # Initials - psss
{
    psss_service_name=$1
    psss_service_full_path=$(get_nano_service_path "$psss_service_name")

    if [ ! -e "$psss_service_full_path" ]; then
        return
    fi

    echo "---- open-appsec $(format_nano_service_name "$psss_service_name") Nano Service ----"

    psss_is_userspace_process_running=$(is_userspace_running "$psss_service_name")

    psss_maybe_version=$(LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$USR_LIB_PATH/cpnano"$LD_LIBRARY_PATH_ADD" $psss_service_full_path --version 2>&1)
    if echo "$psss_maybe_version" | grep -q "error"; then
        echo "Version: Temporarily unavailable"
        return
    fi
    echo "$psss_maybe_version"

    print_volatile_service_count "$psss_service_full_path"

    if [ "$psss_is_userspace_process_running" = false ]; then
        format_colored_status_line "Status: Ready"
    else
        format_colored_status_line "Status: Running"
    fi

    echo ""

    if [ "$psss_service_name" = "access-control" ]; then
        psss_mod_version=""
        psss_test=$(ls ${FILESYSTEM_PATH}/accessControl/cp-nano-netfilter-attachment-module.ko 2>/dev/null | wc -l)
        if [ "$psss_test" -gt 0 ]; then
            echo '---- Check Point Netfilter Attachment kernel module ----'
            psss_mod_version=$(modinfo ${FILESYSTEM_PATH}/accessControl/cp-nano-netfilter-attachment-module.ko | sed 's/GPL/TBD/g' | grep -e ^version: | cut -d':' -f2)
            printf "Version: "
            echo "$psss_mod_version"
            if [ "$(lsmod | grep -c cp_nano_netfilter_attachment_module)" -gt 0 ]; then
                format_colored_status_line "Status: Loaded"
            else
                format_colored_status_line "Status: Not loaded"
            fi
            echo ""
        fi

        if [ "$(ls ${FILESYSTEM_PATH}/accessControl/cp-nano-connection-table-module.ko 2>/dev/null | wc -l)" -gt 0 ]; then
            echo '---- Check Point Connection Table kernel module ----'
            psss_mod_version=$(modinfo ${FILESYSTEM_PATH}/accessControl/cp-nano-connection-table-module.ko | sed 's/GPL/TBD/g' | grep -e ^version: | cut -d':' -f2)
            printf "Version: "
            echo "$psss_mod_version"
            if [ "$(lsmod | grep -c cp_nano_connection_table_module)" -gt 0 ]; then
                format_colored_status_line "Status: Loaded"
            else
                format_colored_status_line "Status: Not loaded"
            fi
            echo ""
        fi

        if [ "$(ls ${FILESYSTEM_PATH}/accessControl/cp-nano-access-control-module.ko 2>/dev/null | wc -l)" -gt 0 ]; then
            echo '---- Check Point Access Control kernel module ----'
            psss_mod_version=$(modinfo ${FILESYSTEM_PATH}/accessControl/cp-nano-access-control-module.ko | sed 's/GPL/TBD/g' | grep -e ^version: | cut -d':' -f2)
            printf "Version: "
            echo "$psss_mod_version"
            if [ "$(lsmod | grep -c cp_nano_access_control)" -gt 0 ]; then
                format_colored_status_line "Status: Loaded"
            else
                format_colored_status_line "Status: Not loaded"
            fi
            echo ""
        fi
        echo ""
    fi
}

get_status_content()
{
    if [ "${remove_curl_ld_path}" = "true" ]; then
        gsc_orch_status=$(LD_LIBRARY_PATH="" ${curl_cmd} -sS -m 1 --noproxy "*" --header "Content-Type: application/json" --request POST --data {} http://127.0.0.1:"$(extract_api_port 'orchestration')"/show-orchestration-status 2>&1)
    else
        gsc_orch_status=$(${curl_cmd} -sS -m 1 --noproxy "*" --header "Content-Type: application/json" --request POST --data {} http://127.0.0.1:"$(extract_api_port 'orchestration')"/show-orchestration-status 2>&1)
    fi

    if echo "$gsc_orch_status" | grep -q "update status"; then
        gsc_line_count=$(echo "$gsc_orch_status" | grep -c '^')

        gsc_temp_old_status=$(echo "$gsc_orch_status" | sed -r "${gsc_line_count},${gsc_line_count}d; "' 1,1d; s/^\s*//g; s/^\n//g; s/\"//g; s/\\n/\n/g; s/\,//g')
    else
        gsc_temp_old_status=$(sed 's/{//g' <${FILESYSTEM_PATH}/$cp_nano_conf_location/orchestration_status.json | sed 's/}//g' | sed 's/"//g' | sed 's/,//g' | sed -r '/^\s*$/d' | sed -r 's/^    //g')
    fi

    echo ${gsc_temp_old_status}
}

run_status() # Initials - rs
{
    rs_orch_service_full_path=$(get_nano_service_path 'orchestration')
    rs_agent_version=$(LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$USR_LIB_PATH/cpnano"$LD_LIBRARY_PATH_ADD" $rs_orch_service_full_path --version)
    if echo "$rs_agent_version" | grep -q "Public"; then
        rs_agent_version=$(printf "%s" "$rs_agent_version" | cut -d',' -f 2 | sed 's/^ //')
    else
        rs_agent_version="Version $rs_agent_version"
    fi

    echo "---- open-appsec Nano Agent ----"
    echo "$rs_agent_version"
    if [ "$(is_userspace_running "watchdog")" = true ] || [ "$(is_userspace_running "agent")" = true ]; then
        format_colored_status_line "Status: Running"
    else
        format_colored_status_line "Status: Not running"
    fi

    if [ "${remove_curl_ld_path}" = "true" ]; then
        rs_orch_status=$(LD_LIBRARY_PATH="" ${curl_cmd} -sS -m 1 --noproxy "*" --header "Content-Type: application/json" --request POST --data {} http://127.0.0.1:"$(extract_api_port 'orchestration')"/show-orchestration-status 2>&1)
    else
        rs_orch_status=$(${curl_cmd} -sS -m 1 --noproxy "*" --header "Content-Type: application/json" --request POST --data {} http://127.0.0.1:"$(extract_api_port 'orchestration')"/show-orchestration-status 2>&1)
    fi

    if echo "$rs_orch_status" | grep -q "update status"; then
        rs_line_count=$(echo "$rs_orch_status" | grep -c '^')
        rs_policy_load_time="$(echo "${rs_orch_status}" | grep "Last policy update"| sed "s|\"||g" | sed "s|,||g")"

        rs_temp_old_status=$(echo "$rs_orch_status" | sed -r "${rs_line_count},${rs_line_count}d; "' 1,1d; s/^\s*//g; s/^\n//g; s/\"//g; s/\\n/\n/g; s/\,//g')
    else
        rs_temp_old_status=$(sed 's/{//g' <${FILESYSTEM_PATH}/$cp_nano_conf_location/orchestration_status.json | sed 's/}//g' | sed 's/"//g' | sed 's/,//g' | sed -r '/^\s*$/d' | sed -r 's/^    //g')
        rs_policy_load_time="$(cat ${FILESYSTEM_PATH}/conf/orchestration_status.json | grep "Last policy update" | sed "s|\"||g" | sed "s|,||g")"
    fi

    if [ -f ${FILESYSTEM_PATH}/conf/waap/waap.data ]; then
        rs_ai_model_ver="$(cat ${FILESYSTEM_PATH}/conf/waap/waap.data | ${FILESYSTEM_PATH}/${CP_PICOJSON_PATH} | grep 'model_version')"

        if [ -z "$rs_ai_model_ver" ]; then
            echo "AI model version: None"
        else
            echo "$rs_ai_model_ver" | sed "s/\"//g; s/,//g; s/model_version/AI model version/g; s/^[ \t]*//"
        fi
    fi

    if [ -n "$(cat ${FILESYSTEM_PATH}/conf/agent_details.json | grep "hybrid_mode")" ]; then
        add_policy_file=true
        rs_mgmt_mode_text="Local management"
    else
        if [ -n "$(cat ${FILESYSTEM_PATH}/conf/settings.json | grep "\"profileManagedMode\":\"management\"")" ]; then
            add_policy_file=false
            rs_mgmt_mode_text="Cloud management (Fully managed)"
        else
            add_policy_file=true
            rs_mgmt_mode_text="Cloud management (Visibility mode)"
        fi
    fi
    echo "Management mode: ${rs_mgmt_mode_text}"

    if [ "${add_policy_file}" = "true" ]; then
        echo "Policy files: "
        echo "    ${var_policy_file}"
    else
        policy=`cat ${AGENT_POLICY_PATH}`
        version="version"
        policy_version=${policy#*version}
        policy_version=`echo $policy_version | cut -d"\"" -f3`

        if [ -n "$policy_version" ] && [ "$policy_version" -eq "$policy_version" ] 2>/dev/null; then
            echo "Policy version: ${policy_version}"
        else
            echo "Policy version: Updating policy. Please try again in a few seconds"
        fi
    fi

    if [ -n "$(echo ${rs_temp_old_status} | grep "Last update status" | grep "Fail")" ]; then
        rs_policy_load_status="Error"
    else
        rs_policy_load_status="Success"
    fi
    echo "Policy load status: ${rs_policy_load_status}"
    echo ${rs_policy_load_time}
    echo ""

    for service in $all_services; do
        print_single_service_status "$service"
    done
}

run_load_settings() # Initials - rls
{
    rls_service_to_update=$1
    if [ -z "$rls_service_to_update" ] || [ -z "$(get_nano_service_location_and_port "$rls_service_to_update")" ]; then
        echo "Error: Could not load configuration"
        printf "Usage: open-appsec-ctl <-lc|--load-config> <%b>\n" "$(get_installed_services '|')"
        exit 1
    fi

    if [ "$(is_userspace_running "${rls_service_to_update}")" = "false" ]; then
        echo "Error: $rls_service_to_update is not running"
        return
    fi

    if [ "$(signal_reload_nano_service_settings "$rls_service_to_update")" = false ]; then
        echo "$rls_service_to_update configuration update failed"
        return
    fi
    rls_service_formatted=$(format_nano_service_name "$rls_service_to_update")
    echo "$rls_service_formatted configuration updated successfully"
}

set_proxy() # Initials - sp
{
    sp_proxy="$1"

    if [ -z "$sp_proxy" ]; then
        echo "Error: Proxy was not provided."
        ech "Usage: open-appsec-ctl <-sp|--set-proxy> <proxy>"
        exit 1
    fi

    if [ "${remove_curl_ld_path}" = "true" ]; then
        sp_curl_output=$(LD_LIBRARY_PATH="" ${curl_cmd} -w "%{http_code}\n" -sS -m 60 --noproxy "*" --header "Content-Type: application/json" --request POST --data '{"proxy":"'"$sp_proxy"'"}' http://127.0.0.1:"$(extract_api_port 'orchestration')"/add-proxy)
    else
    sp_curl_output=$(${curl_cmd} -w "%{http_code}\n" -sS -m 60 --noproxy "*" --header "Content-Type: application/json" --request POST --data '{"proxy":"'"$sp_proxy"'"}' http://127.0.0.1:"$(extract_api_port 'orchestration')"/add-proxy)
    fi
    if echo "$sp_curl_output" | grep -q "200"; then
        echo "Proxy successfully changed to $sp_proxy"
    else
        echo "Failed to set proxy: Error code ${sp_curl_output}"
        exit 1
    fi
}

run_display_single_service_settings() # Initials - rdsss
{
    rdsss_service_name=$1
    if [ -z "$rdsss_service_name" ]; then
        echo "Error: service name not provided"
        exit 255
    fi

    if [ "$(is_userspace_running "$rdsss_service_name")" = false ]; then
        echo "---- $rdsss_service_name service is not running ----"
    else
        echo "---- $rdsss_service_name Service Configuration ----"
        rdsss_service_conf_path="${FILESYSTEM_PATH}/${cp_nano_conf_location}/$cp_nano_service_name_prefix-$rdsss_service_name-$cp_nano_conf_suffix"
        run_prettify_json "$rdsss_service_conf_path"
        rdsss_service_debug_path="${FILESYSTEM_PATH}/${cp_nano_conf_location}/$cp_nano_service_name_prefix-$rdsss_service_name-$cp_nano_debug_suffix"
        run_prettify_json "$rdsss_service_debug_path"
    fi
}

run_display_settings() # Initials - rds
{
    rds_service_name=$1

    if [ -n "$rds_service_name" ]; then
        run_display_single_service_settings "$rds_service_name"
        return
    fi

    for service in $all_services; do
        rds_service_full_path=$(get_nano_service_path "$service")
        if [ -e "$rds_service_full_path" ]; then
            run_display_single_service_settings "$service"
        fi
    done
}

update_service_ca_dir_conf() # Initials - uscdc
{
    uscdc_ca_dir_path=$1
    uscdc_service_name=$2
    uscdc_settings_path=$3

    if [ ! -f "$uscdc_settings_path" ]; then
        return
    fi

    uscdc_current_ca_path=$(get_setting "$uscdc_service_name" "Trusted CA directory")
    if [ -n "$uscdc_current_ca_path" ]; then
        sed -i "s|$uscdc_current_ca_path|$uscdc_ca_dir_path|g" "$uscdc_settings_path"
    else
        if ! grep -q "message" "$uscdc_settings_path"; then
            sed -i -e "0,/{/ s|{|{\"message\": {\"Trusted CA directory\": [{\"value\": \"$uscdc_ca_dir_path\"}]},|" "$uscdc_settings_path"
        else
            sed -i -e "0,/\"message\"/ s|\"message\".*:.*{|\"message\": {\"Trusted CA directory\": [{\"value\": \"$uscdc_ca_dir_path\"}],|" "$uscdc_settings_path"
        fi
    fi

    run_load_settings "$2"
}

run_set_ca_directory() # Initials - rscd
{
    rscd_ca_dir_path=$1

    if [ ! -d "$rscd_ca_dir_path" ]; then
        printf "Error: '%s' is not a directory\n" "$rscd_ca_dir_path"
        exit 1
    fi

    for service in $all_services; do
        rscd_service_conf_path="${FILESYSTEM_PATH}/${cp_nano_conf_location}/$cp_nano_service_name_prefix-$service-$cp_nano_conf_suffix"
        update_service_ca_dir_conf "$rscd_ca_dir_path" "$service" "$rscd_service_conf_path"
    done
}

run_set_publick_key() # Initials - rspk
{
    rspk_public_key=$1
    if [ -z "${rspk_public_key}" ]; then
        printf "Error: public key file path is missing\n"
        exit 1
    elif [ ! -f "${rspk_public_key}" ]; then
        printf "Error: '%b' is not a file" "$rspk_public_key"
        exit 1
    fi

    ln -sf "${rspk_public_key}" ${FILESYSTEM_PATH}/certs/public-key.pem
}

run_cpnano_debug() # Initials - rcd
{
    CP_ENV_FILESYSTEM=${FILESYSTEM_PATH} CP_ENV_LOG_FILE=${LOG_FILE_PATH} ${FILESYSTEM_PATH}/${CP_SCRIPTS_PATH}/${CP_NANO_DEBUG_NAME} "${@}"
    rcd_script_exit_code=$?
    # exit code of -1 from the script becomes 255 here
    if [ $rcd_script_exit_code -eq 0 ]; then
        exit 0
    elif [ $rcd_script_exit_code -eq 255 ]; then
        exit 255
    fi

    rcd_load_all_settings=true
    while true; do
        if [ -z "$1" ]; then
            break
        elif [ "$1" != "--service" ]; then
            shift
        else
            rcd_load_all_settings=false
            shift
            break
        fi
    done

    if [ "$rcd_load_all_settings" = "true" ]; then
        for service in $all_services; do
            if [ "$(is_userspace_running "${service}")" = "true" ]; then
                run_load_settings "$service"
            fi
        done

        return
    fi

    while true; do
        if [ -z "$1" ]; then
            return
        elif [ -n "$(get_nano_service_location_and_port "$1")" ]; then
            run_load_settings "$1"
        fi
        shift
    done
}

char_to_ascii()
{
    printf '%d' "'$1"
}

hex_to_dec()
{
    printf '%d' "0x$1"
}

xor_decrypt() # Initials - xd
{
    xd_key="CHECKPOINT"
    xd_data="$1"
    xd_index=
    xd_res=
    xd_delta=0
    for xd_index in $(seq 0 $((${#xd_data} / 2 - 1))) ; do
        xd_dec_val_base="$(echo ${xd_data} | cut -c $((${xd_delta} + 1)))$(echo ${xd_data} | cut -c $((${xd_delta} + 2)))"
        xd_dec_val="$(hex_to_dec "${xd_dec_val_base}")"
        xd_ascii_val=$(char_to_ascii "$(echo ${xd_key} | cut -c  $((xd_index % ${#xd_key} + 1)))")
        xd_xor_res=$((xd_dec_val ^ xd_ascii_val))
        xd_delta=$((xd_delta + 2))
        xd_res=${xd_res}$(printf \\$(printf "%o" "$xd_xor_res"))
    done
    echo $xd_res
}

run_ai() # Initials - ra
{
    ra_tenant_id=
    ra_agent_id=
    ra_token=
    ra_upload_to_fog=false
    # we use this address as default and replace later if needed
    ra_fog_address="inext-agents.cloud.ngen.checkpoint.com"

    for arg; do
        if [ "$arg" = "--upload" ] || [ "$arg" = "-u" ]; then
            ra_upload_to_fog=true
            shift
            continue
        elif [ "$arg" = "--verbose" ] || [ "$arg" = "-v" ]; then
            AI_VERBOSE=true
        elif [ -z "$1" ]; then
            break
        fi
        set -- "$@" "$arg"
        shift
    done

    if [ "$ra_upload_to_fog" = "false" ]; then
        printf "Would you like to upload the file to be inspected by the product support team? [y/n] " && read -r ra_should_upload
        case $ra_should_upload in
        [Yy] | [Yy][Ee][Ss]) ra_upload_to_fog=true ;;
        *) ;;
        esac
    fi

    ra_https_prefix="https://"
    ra_agent_details=$(cat ${FILESYSTEM_PATH}/$cp_nano_conf_location/agent_details.json)
    if echo "$ra_agent_details" | grep -q "Fog domain"; then
        [ -f ${FILESYSTEM_PATH}/$cp_nano_conf_location/orchestrations_status.json ] && ra_orch_status=$(cat ${FILESYSTEM_PATH}/$cp_nano_conf_location/orchestration_status.json)
        ra_tenant_id=$(printf "%s" "$ra_agent_details" | grep "Tenant ID" | cut -d '"' -f4)
        ra_agent_id=$(printf "%s" "$ra_agent_details" | grep "Agent ID" | cut -d '"' -f4)
    else
        ra_orch_status=$(curl_func "$(extract_api_port orchestration)"/show-orchestration-status)
        if ! echo "$ra_orch_status" | grep -q "update status"; then
            [ -f ${FILESYSTEM_PATH}/$cp_nano_conf_location/orchestrations_status.json ] && ra_orch_status=$(cat ${FILESYSTEM_PATH}/$cp_nano_conf_location/orchestration_status.json)
        fi
        if [ -n "${ra_orch_status}" ]; then
            ra_fog_address=$(printf "%s" "$ra_orch_status" | grep "Fog address" | cut -d '"' -f4)
            ra_tenant_id=$(printf "%s" "$ra_orch_status" | grep "Tenant ID" | cut -d '"' -f4)
            ra_agent_id=$(printf "%s" "$ra_orch_status" | grep "Agent ID" | cut -d '"' -f4)
        fi
    fi
    if [ -z "$(echo "$ra_fog_address" | grep "$ra_https_prefix")" ]; then
        ra_fog_address="${ra_https_prefix}${ra_fog_address}"
    fi

    ra_current_time=$(date "+%Y.%m.%d-%H.%M.%S")
    ra_dir_name=cp-nano-info-"$ra_agent_id"-"$ra_current_time"
    ra_cp_info_path=/tmp/$ra_dir_name

    cp_nano_info_args="${@} -sd ${ra_cp_info_path}"
    . "${FILESYSTEM_PATH}/${CP_SCRIPTS_PATH}/${CP_AGENT_INFO_NAME}"
    if [ $? -ne 0 ]; then
        echo "Failed to calculate agent-info data."
        exit 1
    fi
    if [ "$ra_upload_to_fog" = "true" ]; then
        ra_token_data="$(curl_func "$(extract_api_port orchestration)"/show-access-token)"
        ra_token_hex=$(echo "$ra_token_data" | grep "token" | cut -d '"' -f4 | base64 -d | od -t x1 -An)
        ra_token_hex_formatted=$(echo $ra_token_hex | tr -d ' ')
        ra_token="$(xor_decrypt "${ra_token_hex_formatted}")"

        ra_proxy_val=""
        if [ -n "${is_gaia}" ]; then
            ra_gaia_proxy_address=$(dbget proxy:ip-address | tr -d '\n')
            ra_gaia_proxy_ip=$(dbget proxy:port | tr -d '\n')

            if [ -n "$ra_gaia_proxy_address" ] && [ -n "$ra_gaia_proxy_ip" ]; then
                ra_proxy_val="--proxy http://${ra_gaia_proxy_address}:${ra_gaia_proxy_ip}"
            fi
        fi
        if [ "$is_smb_release" = "1" ]; then
            is_proxy_enabled=$(pt proxySettings | awk '{if ($1 == "useProxy") printf("%s", $3)}')
            if [ "$is_proxy_enabled" = "true" ]; then
                ra_smb_proxy_address=$(pt proxySettings | awk '{if ($1 == "ipAddress") printf("%s", $3)}')
                ra_smb_proxy_port=$(pt proxySettings | awk '{if ($1 == "port") printf("%s", $3)}')

                if [ ! -z $ra_smb_proxy_address ] && [ ! -z $ra_smb_proxy_port ]; then
                    ra_proxy_val="--proxy http://${ra_smb_proxy_address}:${ra_smb_proxy_port}"
                fi
            fi
        fi

        echo "---- Uploading agent information to Check Point ----"
        sleep 1

        upload_ai "$ra_cp_info_path" "$ra_token" "$ra_fog_address" "$ra_tenant_id" "$ra_agent_id" "$ra_current_time" "$ra_file_dir"
        if [ "$AI_UPLOAD_TOO_LARGE_FLAG" = "true" ]; then
            echo "Files are too large - splitting to files of size of $SPLIT_FILE_SMALL_SIZE"
            cat "$ra_cp_info_path"/* >"$ra_cp_info_path"/temp_reassembled_files
            rm "$ra_cp_info_path"/*.*
            split -b "$SPLIT_FILE_SMALL_SIZE" "$ra_cp_info_path"/temp_reassembled_files "$ra_cp_info_path"/cp-nano-info-"$ra_agent_id"-"$ra_current_time".tar.gz
            rm "$ra_cp_info_path"/temp_reassembled_files
            upload_ai "$ra_cp_info_path" "$ra_token" "$ra_fog_address" "$ra_tenant_id" "$ra_agent_id" "$ra_current_time" "$ra_file_dir"
        fi
        echo "File upload to cloud: Succeeded"
        echo "Reference Id: " "$ra_tenant_id"/"$ra_agent_id"/"$ra_current_time"
    else
        echo "ignore uploading file to the Fog."
    fi
}

create_entries_file() # Initials - cef
{
    cef_cp_info_path="$1"
    cef_entries_file_path="$cef_cp_info_path/entries.json"
    if [ -f "$cef_entries_file_path" ]; then
        rm "$cef_entries_file_path"
    fi
    echo "{" >>"$cef_entries_file_path"
    echo "  \"entries\": [" >>"$cef_entries_file_path"
    cef_is_first=true
    for file in $(ls "$cef_cp_info_path"/* | sort); do
        if [ "$file" = "$cef_entries_file_path" ]; then
            continue
        fi
        if [ "$cef_is_first" = "false" ]; then
            echo "," >>"$cef_entries_file_path"
        fi
        printf "    {\"url\":\"%s\", \"mandatory\":true}" "$file" >>"$cef_entries_file_path"
        cef_is_first=false
    done
    {
        echo ""
        echo "  ]"
        echo "}"
    } >>"$cef_entries_file_path"
}

upload_ai() # Initials - uai
{
    uai_cp_info_path="$1"
    uai_token="$2"
    uai_fog_address="$3"
    uai_tenant_id="$4"
    uai_agent_id="$5"
    uai_current_time="$6"
    uai_file_dir="$7"
    create_entries_file "$uai_cp_info_path"
    for file in "$uai_cp_info_path"/*; do
        if [ "$AI_VERBOSE" = "true" ]; then
            echo "Uploading file $file"
        fi
        if [ -z "${is_gaia}" -o "$is_smb_release" = "1" ]; then
            uai_curl_output=$(${curl_cmd} -o /dev/null -s -w "%{http_code}\n" --progress-bar --request PUT -T "${file}" -H "user-agent: Infinity Next (a7030abf93a4c13)" -H "Content-Type: application/json" -H "Authorization: Bearer ${uai_token}" "$uai_fog_address"/agents-core/storage/"$uai_tenant_id"/"$uai_agent_id"/"$uai_current_time"/"$uai_file_dir" 2>&1)
        elif [ "${remove_curl_ld_path}" = "true" ]; then
            uai_curl_output=$(LD_LIBRARY_PATH="" ${curl_cmd} --cacert ${FILESYSTEM_PATH}/certs/fog.pem "${uai_proxy_val}" -o /dev/null -s -w "%{http_code}\n" --progress-bar --request PUT -T "${file}" -H "user-agent: Infinity Next (a7030abf93a4c13)" -H "Content-Type: application/json" -H "Authorization: Bearer ${uai_token}" "$uai_fog_address"/agents-core/storage/"$uai_tenant_id"/"$uai_agent_id"/"$uai_current_time"/"$uai_file_dir" 2>&1)
        else
            uai_curl_output=$(${curl_cmd} --cacert ${FILESYSTEM_PATH}/certs/fog.pem "${uai_proxy_val}" -o /dev/null -s -w "%{http_code}\n" --progress-bar --request PUT -T "${file}" -H "user-agent: Infinity Next (a7030abf93a4c13)" -H "Content-Type: application/json" -H "Authorization: Bearer ${uai_token}" "$uai_fog_address"/agents-core/storage/"$uai_tenant_id"/"$uai_agent_id"/"$uai_current_time"/"$uai_file_dir" 2>&1)
        fi
        if [ "$AI_UPLOAD_TOO_LARGE_FLAG" = "false" ] && [ "$uai_curl_output" = "413" ]; then
            AI_UPLOAD_TOO_LARGE_FLAG=true
            return
        fi
        if test "$uai_curl_output" != "200"; then
            echo "File upload to cloud: Failed Error code ${uai_curl_output}"
            exit 1
        fi
    done
}

set_mode_usage_message()
{
    echo "Usage:"
    echo "--online_mode|--offline_mode|--standalone  : Orchestration mode (Required)"
    echo "--force                                     : force mode change (Optional)"
    echo "--token  <token>                             : Token (Required for online mode, optional otherwise)"
    echo "--fog    <fog URL>                           : Fog Address (Optional)"
    echo "--ignore <ignore packages list>             : List of ignored packages"
    exit 255
}

set_mode()
{
    fog_address=""
    token=""
    mode=""
    force_new_mode=false
    while true; do
        if [ -z "$1" ]; then
            break
        fi
        current_var=$1
        shift
        if [ "$current_var" = "--online_mode" ] || [ "$current_var" = "--offline_mode" ] || [ "$current_var" = "--standalone" ]; then
            mode=$(echo $current_var | sed 's/-//g')
            if [ "$mode" = "standalone" ]; then
                mode="hybrid_mode"
            fi
        elif [ "$current_var" = "--fog" ]; then
            if [ -n "$1" ]; then
                fog_address=$1
                shift
            else
                set_mode_usage_message
            fi
        elif [ "$current_var" = "--token" ]; then
            if [ -n "$1" ]; then
                token=$1
                shift
            else
                set_mode_usage_message
            fi
        elif [ "$current_var" = "--ignore" ]; then
            if [ -n "$1" ]; then
                ignore_packages=$1
                shift
            else
                set_mode_usage_message
            fi
        elif [ "$current_var" = "--force" ]; then
            force_new_mode=true
        else
            set_mode_usage_message
        fi
    done

    if [ -z "$mode" ]; then
        printf "Orchestration mode was not set"
        exit 255
    fi

    cp_nano_mode=$(cat ${FILESYSTEM_PATH}/orchestration/cp-nano-orchestration.cfg | grep "orchestration-mode" | cut -d = -f 3 | head -1 | sed -e 's/\s.*\|".*//')

    if [ "$mode" = "$cp_nano_mode" ] && [ "$force_new_mode" = false ]; then
        echo "Already in ${mode}, no action needed\n"
        exit 0
    fi

    # token
    if [ "$mode" = "online_mode" ]; then
        if [ -z "$token" ]; then
            printf "Must have a valid token in order to switch to online mode.\n"
            exit 255
        fi

        printf '{\n   "registration type": "token",\n   "registration data": "%b"\n}' "$token" | ${FILESYSTEM_PATH}/${BIN_PATH}/${CP_NANO_BASE64} -e > ${FILESYSTEM_PATH}/${cp_nano_conf_location}/registration-data.json
    fi

    # fog address
    if [ "$mode" != "offline_mode" ]; then
        if [ -n "$token" ] && [ -z "$fog_address" ]; then
            var_token=$token
            gem_prefix="cp-"
            gem_prefix_uppercase="CP-"
            us_prefix="cp-us-"
            us_prefix_uppercase="CP-US-"
            au_prefix="cp-au-"
            au_prefix_uppercase="CP-AU-"
            in_prefix="cp-in-"
            in_prefix_uppercase="CP-IN-"

            if [ "${var_token#"$us_prefix"}" != "${var_token}" ] || [ "${var_token#"$us_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_us_fog_address"
            elif [ "${var_token#$au_prefix}" != "${var_token}" ] || [ "${var_token#"$au_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_au_fog_address"
            elif [ "${var_token#$in_prefix}" != "${var_token}" ] || [ "${var_token#"$in_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_in_fog_address"
            elif [ "${var_token#"$gem_prefix"}" != "${var_token}" ] || [ "${var_token#"$gem_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_gem_fog_address"
            else
                echo "Failed to get fog address from token: ${var_token} - check if token is legal"
            fi
            fog_address=$var_fog_address
        elif [ -z "$token" ]; then
            fog_address="https://dev-latest-fog-gw.dev.i2.checkpoint.com"
        fi
    else
        fog_address=""
    fi

    old_fog=$(cat ${FILESYSTEM_PATH}/${cp_nano_conf_location}/orchestration/orchestration.policy | grep -A 3 "fog-address" | grep "fog-address" | cut -d : -f 2- | head -1 | sed -e 's/"//' -e 's/".*//')
    sed -i "s,\"fog-address\":\"$old_fog\",\"fog-address\":\"$fog_address\"," ${FILESYSTEM_PATH}/${cp_nano_conf_location}/orchestration/orchestration.policy

    rm ${FILESYSTEM_PATH}/${cp_nano_conf_location}/agent_details.json
    rm ${FILESYSTEM_PATH}/${cp_nano_conf_location}/orchestration_status.json
    echo '{}'>${AGENT_POLICY_PATH}

    if [ -f ${FILESYSTEM_PATH}/data/data5.a ]; then
        rm ${FILESYSTEM_PATH}/data/data5.a
    fi

    if [ -f ${FILESYSTEM_PATH}/${cp_nano_conf_location}/orchestration/orchestration.policy.bk ]; then
       echo '{}'>${FILESYSTEM_PATH}/${cp_nano_conf_location}/orchestration/orchestration.policy.bk
    fi

    if [ -f ${FILESYSTEM_PATH}/${cp_nano_conf_location}/ignore-packages.txt ]; then
        rm ${FILESYSTEM_PATH}/${cp_nano_conf_location}/ignore-packages.txt
    fi

    if [ -n "$ignore_packages" ]; then
        echo "The following packages will be ignored: $ignore_packages"
        echo "$ignore_packages" | tr ',' '\n' >> ${FILESYSTEM_PATH}/${cp_nano_conf_location}/ignore-packages.txt
    fi

    # set mode
    sed -i "s/$cp_nano_mode/$mode/" ${FILESYSTEM_PATH}/orchestration/cp-nano-orchestration.cfg

    ret=$(curl_func "$(extract_api_port orchestration)"/set-orchestration-mode)

    if [ "$mode" = "online_mode" ]; then
        time_sleep=2
        time_out=60
        echo "Registering open-appsec Nano Agent to Fog.."
        until get_status_content | grep -q "Registration status: Succeeded"; do
            time_out=$(( time_out - time_sleep ))
            if [ $time_out -le 0 ]; then
                echo "open-appsec Nano Agent registration failed. Failed to register to Fog: $fog_address"
                exit 1
            fi
            sleep ${time_sleep}
        done
        echo "open-appsec Nano Agent is registered to $fog_address"
        echo "Orchestration mode changed successfully"
    else
        echo "Orchestration mode was changed successfully"
    fi
}

start_service() # Initials - starts
{
    if [ -z "$1" ]; then
        printf "Usage: open-appsec-ctl <-rs|--start-service> <%b>\n" "$(get_installed_services '|')"
        exit 255
    fi
    starts_persistance_arg=""
    if [ "$1" = "--persistent" ]; then
        starts_persistance_arg="$1"
        shift
    fi
    starts_service_to_start=$(get_nano_service_path "$1")
    if [ -z "$starts_service_to_start" ]; then
        echo "Service $1 is not installed"
        exit 255
    fi
    if ps -ef | grep -vw grep | grep -q "$starts_service_to_start"; then
        echo "Service $starts_service_to_start is already running"
        exit 0
    fi
    starts_cmd="${FILESYSTEM_PATH}/${cp_nano_watchdog} --start ${starts_persistance_arg} ${starts_service_to_start}"
    eval "$starts_cmd"
    starts_exit_code=$?
    if [ $starts_exit_code -eq 0 ]; then
        echo "Successfully started the $starts_service_to_start service"
        exit 0
    elif [ $starts_exit_code -eq 2 ]; then
        echo "Service $starts_service_to_start is already started"
        exit 0
    elif [ $starts_exit_code -eq 3 ]; then
        echo "Service $starts_service_to_start is installed but not registered to watchdog"
        exit 0
    fi
    echo "Failed to start the $starts_service_to_start service"
    exit 255
}

stop_service() # Initials - stops
{
    if [ -z "$1" ]; then
        printf "Usage: open-appsec-ctl <-qs|--stop-service> <%b>\n" "$(get_installed_services '|')"
        exit 255
    fi
    stops_persistance_arg=""
    if [ "$1" = "--persistent" ]; then
        stops_persistance_arg="$1"
        shift
    fi
    stops_service_to_stop=$(get_nano_service_path "$1")
    if [ -z "$stops_service_to_stop" ]; then
        echo "Service $1 is not installed"
        exit 255
    fi
    if ! ps -ef | grep -vw grep | grep -q "$stops_service_to_stop"; then
        echo "Service $stops_service_to_stop is not running"
        exit 0
    fi
    stops_cmd="${FILESYSTEM_PATH}/${cp_nano_watchdog} --stop ${stops_persistance_arg} ${stops_service_to_stop}"
    eval "$stops_cmd"
    stops_exit_code=$?
    if [ $stops_exit_code -eq 0 ]; then
        echo "Successfully stoped the $stops_service_to_stop service"
        exit 0
    fi
    echo "Failed to stop the $stops_service_to_stop service"
    exit 255
}

record_command() # Initials - rc
{
    touch ${LOG_FILE_PATH}/nano_agent/operations.log
    echo "$(tail -99 ${LOG_FILE_PATH}/nano_agent/operations.log)" > ${LOG_FILE_PATH}/nano_agent/operations.log
    echo $(date "+%Y.%m.%d-%H.%M.%S") ": " $0 $@ >> ${LOG_FILE_PATH}/nano_agent/operations.log
}

is_apply_policy_needed()
{
    if [ "${var_policy_file}" != "${var_new_policy_file}" ]; then
        var_policy_file=$var_new_policy_file
        return 0
    fi
    local_policy_modification_time=$(stat -c %Y ${var_policy_file})
    if [ "${local_policy_modification_time}" -eq "${last_local_policy_modification_time}" ] || [ -z ${last_local_policy_modification_time} ]; then
        return 1
    fi
    return 0
}

is_policy_file_changed()
{
    new_modification_time=$(stat -c %Y ${AGENT_POLICY_PATH})
    if [ "${new_modification_time}" -gt "${var_last_policy_modification_time}" ]; then
        return 1
    fi
    return 0
}

run() # Initials - r
{
    r_deprecated_msg="Option ${1} is deprecated. Please use"
    if [ -z "$1" ]; then
        usage
    elif [ "--debug" = "$1" ] || [ "-d" = "$1" ]; then
        record_command $@
        run_cpnano_debug "cpnano" "$@"
    elif [ "--display-policy" = "$1" ] || [ "-dp" = "$1" ]; then
        record_command $@
        run_display_policy
    elif [ "--status" = "$1" ] || [ "-s" = "$1" ]; then
        record_command $@
        run_status
        if [ "--extended" = "$2" ]; then
            shift
            run_health_check "${@}"
        fi
        print_link_information
    elif [ "--start-agent" = "$1" ] || [ "-r" = "$1" ]; then
        record_command $@
        run_start_agent
    elif [ "--stop-agent" = "$1" ] || [ "-q" = "$1" ]; then
        record_command $@
        run_stop_agent
    elif [ "--uninstall" = "$1" ] || [ "-u" = "$1" ]; then
        record_command $@
        uninstall_agent
    elif [ "--display-settings" = "$1" ]; then
        echo "${r_deprecated_msg} --display-config"
    elif [ "-ds" = "$1" ]; then
        echo "${r_deprecated_msg} -dc"
    elif [ "--load-settings" = "$1" ]; then
        echo "${r_deprecated_msg} --load-config"
    elif [ "-ls" = "$1" ]; then
        echo "${r_deprecated_msg} -lc"
    elif [ "--display-config" = "$1" ] || [ "-dc" = "$1" ]; then
        record_command $@
        shift
        run_display_settings "${@}"
    elif [ "--load-config" = "$1" ] || [ "-lc" = "$1" ]; then
        record_command $@
        shift
        run_load_settings "${@}"
    elif [ "--set-proxy" = "$1" ] || [ "-sp" = "$1" ]; then
        record_command $@
        shift
        set_proxy "${@}"
    elif [ "--set-gradual-policy" = "$1" ] || [ "-gp" = "$1" ]; then
        record_command $@
        shift
        run_update_gradual_policy "set" "${@}"
    elif [ "--delete-gradual-policy" = "$1" ] || [ "-dg" = "$1" ]; then
        record_command $@
        shift
        run_update_gradual_policy "delete" "${@}"
    elif [ "--set-traffic-recording-policy" = "$1" ] || [ "-tr" = "$1" ]; then
        record_command $@
        shift
        run_set_traffic_recording_policy "${@}"
    elif [ "--cp-agent-info" = "$1" ] || [ "-ai" = "$1" ]; then
        echo "This option has been replaced by '--info' - please run again using the new flag"
    elif [ "--info" = "$1" ]; then
        record_command $@
        shift
        run_ai "${@}"
    elif [ "--update-certs" = "$1" ] || [ "-uc" = "$1" ]; then
        record_command $@
        run_set_ca_directory "$2"
    elif [ "--set-public-key" = "$1" ] || [ "-pk" = "$1" ]; then
        record_command $@
        run_set_publick_key "$2"
    elif [ "--print-metrics" = "$1" ] || [ "-pm" = "$1" ]; then
        record_command $@
        run_print_metrics "$2"
    elif [ "--stop-service" = "$1" ] || [ "-qs" = "$1" ]; then
        record_command $@
        shift
        stop_service "${@}"
    elif [ "--start-service" = "$1" ] || [ "-rs" = "$1" ]; then
        record_command $@
        shift
        start_service "${@}"
    elif [ "--set-mode" = "$1" ] || [ "-sm" = "$1" ]; then
        record_command $@
        shift
        set_mode "${@}"
    elif [ "-vp" = "$1" ] || [ "--view-policy" = "$1" ]; then
        record_command $@
        shift
        if [ ! -z $1 ]; then
            var_policy_file=$1
        fi
        less ${var_policy_file}
    elif [ "-ep" = "$1" ] || [ "--edit-policy" = "$1" ]; then
        record_command $@
        shift
        if [ ! -z $1 ]; then
            var_policy_file=$1
        fi
        vi ${var_policy_file}
    elif [ "-ap" = "$1" ] || [ "--apply-policy" = "$1" ]; then
        record_command $@
        shift
        if [ ! -z $1 ]; then
            if [ "-d" = "$1" ] || [ "--default-policy" = "$1" ]; then
                var_new_policy_file="${FILESYSTEM_PATH}/${cp_nano_conf_location}/local_policy.yaml"
            elif [ -f $1 ]; then
                var_new_policy_file=$1
            else
                echo "Invalid policy path: $1"
                exit 1
            fi
        else
            var_new_policy_file="${FILESYSTEM_PATH}/${cp_nano_conf_location}/local_policy.yaml"
        fi

        is_apply_policy_needed
        if [ $? -eq 1 ]; then
            echo "Policy didn't changed. Policy path: ${var_policy_file}"
            exit 0
        fi
        echo "Applying new policy. Policy path: ${var_policy_file}"
        var_last_policy_modification_time=$(stat -c %Y ${AGENT_POLICY_PATH})
        curl_apply_policy=$(${curl_cmd} -S  -w "%{http_code}\n" -m 1 --noproxy "*" \
            --header "Content-Type: application/json" --request POST --data '{"policy_path":"'"${var_policy_file}"'"}' \
            http://127.0.0.1:"$(extract_api_port 'orchestration')"/set-apply-policy 2>&1)
        is_policy_file_changed
        is_changed=$?
        while [ ${is_changed} -eq 0 ]; do
            echo -n "."
            sleep 3
            is_policy_file_changed
            is_changed=$?
        done

        var_last_policy_modification_time=$(stat -c %Y ${AGENT_POLICY_PATH})
        echo "var_policy_file=${var_policy_file}" > ${CUSTOM_POLICY_CONF_FILE}
        echo "last_local_policy_modification_time=$(stat -c %Y ${var_policy_file})" >> ${CUSTOM_POLICY_CONF_FILE}
        echo "New policy applied."
        exit 1
    elif [ "-lp" = "$1" ] || [ "--list-policies" = "$1" ]; then
        record_command $@
        echo $var_policy_file
    elif [ "-vl" = "$1" ] || [ "--view-logs" = "$1" ]; then
        record_command $@
        less $LOG_FILE_PATH/nano_agent/cp-nano-http-transaction-handler.log?
    else
        usage
    fi
}

load_paths
run "${@}"

exit 0

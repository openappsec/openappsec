#!/bin/sh

FILESYSTEM_PATH="/etc/cp"
LOG_FILE_PATH="/var/log"
CP_INFO_DIR="/tmp/cp-agent-info-temp"
CP_UNSPLITED_DIR="/tmp/cp-agent-info-unsplited-temp"
SPLIT_FILE_SIZE="99M"
FILE_PREFIX=
SHORT_VERSION=false
VERBOSE=false

cp_print()
{
    printf "%b\n" "$1"
}

listFilesToSave()
{
    if [ "$SHORT_VERSION" = "true" ];then
        ls -d -p "$1/*" | grep -v .gz | grep -v '/$'
        ls -d "$1/*" | grep -E '\S*.[1|2].gz'
        return
    fi
    echo "$1/."
}

checkNginx() {
    IS_NGINX_EXISTS=false
    if service nginx status | grep -q 'Loaded: loaded' ; then
        IS_NGINX_EXISTS=true
    fi
}

collectLogs() { # initials - cl
    cp_print "---- Collecting log files ----"
    cl_LOGS_DIR="$CP_INFO_DIR/logs"
    cl_nginx_rpm_dir=${LOG_FILE_PATH}/nano_agent/rpmanager/nginx_log
    cl_files_to_save=$(listFilesToSave ${LOG_FILE_PATH}/nano_agent)
    mkdir -p "$cl_LOGS_DIR"/nano_agent  && cp -r "$cl_files_to_save" "$cl_LOGS_DIR"/nano_agent
    cp_print "Saving dmesg logs..."
    dmesg >> "$cl_LOGS_DIR/dmesg.log" 2>&1
    if [ "$WITH_DUMP" = "true" ]; then
        cp_print "Saving crash logs..."
        mkdir -p "$cl_LOGS_DIR"/crash  && cp -r /var/crash/. "$cl_LOGS_DIR"/crash
    fi
    if [ "$IS_NGINX_EXISTS" = "true" ]; then
        cp_print "Saving nginx logs..."
        cl_files_to_save=$(listFilesToSave /var/log/nginx)
        mkdir -p "$cl_LOGS_DIR"/nginx  && cp -r "$cl_files_to_save" "$cl_LOGS_DIR"/nginx
    fi
    mkdir -p "$cl_LOGS_DIR"/nginx  && cp -r $cl_nginx_rpm_dir/. "$cl_LOGS_DIR"/nginx 2>/dev/null
}

printTopProgress() { # Initials - ptp
    ptp_frame_counter=1
    ptp_curr_stat="$(stat "$SYSTEM_STATE_FILE")"
    ptp_prev_stat="$ptp_curr_stat"
    printf "Saving frame number %b out of 20" "$ptp_frame_counter"
    while [ $ptp_frame_counter -le 20 ]
    do
        ptp_curr_stat="$(stat "$SYSTEM_STATE_FILE")"
        if [ ! "$ptp_curr_stat" = "$ptp_prev_stat" ]; then
            printf "\r\033[0KSaving frame number %b out of 20" "$ptp_frame_counter"
            ptp_frame_counter=$((ptp_frame_counter+1))
            ptp_prev_stat="$ptp_curr_stat"
        fi
    done
    printf "\n"
}

collectSystemState() {
    cp_print "---- Collecting system state ----"
    SYSTEM_STATE_FILE="$CP_INFO_DIR/system_state.txt"

    printTopProgress &
    writeCommandTofile "top -b -n 20" "Saving processes resources status..."
    writeCommandTofile "df -h" "Saving filesystem status..."
    writeCommandTofile "ps -ef" "Saving running processes status..."
    writeCommandTofile "netstat -an" "Saving network connections status..."
    writeCommandTofile "ifconfig -a" "Saving network interfaces status..."
    writeCommandTofile "cat /proc/cpuinfo" "Saving CPU status..."
    writeCommandTofile "cat /proc/meminfo" "Saving memory status..."
    writeCommandTofile "cpnano -s" "Saving cpnano status..."
    writeCommandTofile "cpnano -pm" "Saving metrics information..."

    if [ $IS_NGINX_EXISTS = true ]; then
        writeCommandTofile "nginx -V" "Saving nginx details..."
    fi

    # Get all active interfaces have both an inet entry and a broadcast (brd) address
    interfaces=$(ip addr show | awk '/inet.*brd/{print $NF}' | tr '\n' ' ')

    for i in ${interfaces}; do
        writeCommandTofile "ethtool $i" "Saving network interfaces details for interface $i..."
        writeCommandTofile "ethtool -S $i"
    done
}

writeCommandTofile() { # Initials - wctf
    wctf_msg_to_user=$2
    if [ -n "$wctf_msg_to_user" ]; then
        cp_print "$wctf_msg_to_user"
    fi
    cp_print "\n*******************************   Command: $1   *******************************\n" >> "$SYSTEM_STATE_FILE"
    $1 >> "$SYSTEM_STATE_FILE" 2>&1
}

helpMenu() {
    cp_print "Usage: cpnano <--info> [options]"
    cp_print "Options:"
    cp_print "-h,  --help                                                   : This help text."
    cp_print "-o,  --output                                                 : Output file path."
    cp_print "-wd, --with_dump                                              : Collect dump files."
    cp_print "-sd, --split_dir                                              : Target directory for compressed files with $SPLIT_FILE_SIZE maximum size each."
    cp_print "-fms, --file_max_size                                         : Maximum size for each splited file in kb"
    cp_print "-an, --additional_name                                        : Additional string for output file name"
    cp_print "-sh, --short                                                  : Save only the most necessary files"
    cp_print "-v, --verbose                                                 : Use verbose mode"
}

get_setting() # Initials - gs
{
    gs_service_name="$1"
    gs_setting_name="$2"
    gs_service_settings="$(run_display_settings "$gs_service_name")"

    gs_setting_value=$(extract_json_field_value "$gs_service_settings" "$gs_setting_name")

    echo "$gs_setting_value"
}

[ -f /etc/environment ] && . "/etc/environment"
if [ -n "${CP_ENV_FILESYSTEM}" ] ; then
    FILESYSTEM_PATH=$CP_ENV_FILESYSTEM
fi
if [ -n "${CP_ENV_LOG_FILE}" ] ; then
    LOG_FILE_PATH=$CP_ENV_LOG_FILE
fi

IS_SMB=0
if [ -f /pfrm2.0/bin/cposd ]; then
    IS_SMB=1
    SPLIT_FILE_SIZE="99m"
    mkdir -p /storage/tmp
    CP_INFO_DIR="/storage/tmp/cp-agent-info-temp"
    CP_UNSPLITED_DIR="/storage/tmp/cp-agent-info-unsplited-temp"
fi

SPLIT_DIR=""
WITH_DUMP=false

set -- ${cp_nano_info_args}
while true
do
    if [ "$1" = "--with_dump" ] || [ "$1" = "-wd" ]; then
        WITH_DUMP=true
    elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        helpMenu
        exit 0
    elif [ "$1" = "--split_dir" ] || [ "$1" = "-sd" ]; then
        shift
        SPLIT_DIR=$1
    elif [ "$1" = "--file_max_size" ] || [ "$1" = "-fms" ]; then
        shift
        SPLIT_FILE_SIZE="$1k"
    elif [ "$1" = "--additional_name" ] || [ "$1" = "-an" ]; then
        shift
        FILE_PREFIX="-$1"
    elif [ "$1" = "--short" ] || [ "$1" = "-sh" ]; then
        SHORT_VERSION=true
    elif [ "$1" = "--verbose" ] || [ "$1" = "-v" ]; then
        VERBOSE=true
    elif [ -z "$1" ]; then
        break
    else
        helpMenu
        exit 1
    fi
    shift
done

cp_print "---- Starting to collect Check Point Nano Agent data ----"
mkdir -p "$CP_INFO_DIR"
mkdir -p "$CP_UNSPLITED_DIR"
checkNginx
collectLogs
collectSystemState

curl_cmd=curl
if cat /etc/*release | grep -q "Gaia"; then
    curl_cmd=curl_cli
fi

cp_print "---- Compressing cp-agent-info ----"
CURRENT_TIME=$(date "+%Y.%m.%d-%H.%M.%S")
agent_id=
orch_status=$(${curl_cmd} -sS -m 1 --noproxy "*" --header "Content-Type: application/json" --request POST --data {} http://127.0.0.1:"$(extract_api_port 'orchestration')"/show-orchestration-status 2>&1)
if echo "$orch_status" | grep -q "update status" ; then
    orch_status=$(cat ${FILESYSTEM_PATH}/conf/orchestrations_status.json)
fi

if [ -n "${orch_status}" ]; then
    agent_id=$(printf "%b\n" "$orch_status" | grep "Agent ID" | cut -d '"' -f4)
fi
AGENT_INFO_FILE_NAME=cp-nano-info-$agent_id-$CURRENT_TIME$FILE_PREFIX.tar.gz
if [ "$IS_SMB" != "1" ]; then
    CP_INFO_PATH=/tmp/$AGENT_INFO_FILE_NAME
else
    CP_INFO_PATH=/storage/tmp/$AGENT_INFO_FILE_NAME
fi
TAR_FAILED=false

conf_to_save=${FILESYSTEM_PATH}/conf
inner_conf_file_to_save=""
if [ "$SHORT_VERSION" = "true" ];then
    conf_to_save="$(ls -d ${FILESYSTEM_PATH}/conf/* | grep -E '\.json|\.policy')"
    inner_conf_file_to_save="$(ls -d ${FILESYSTEM_PATH}/conf/*/* | grep -E '\.json|\.policy|\.conf')"
fi
cp_print "Compressing and saving the next files and directories:\n    $CP_INFO_DIR\n    ${FILESYSTEM_PATH}/conf\n    ${FILESYSTEM_PATH}/watchdog"
verbose_tar=""
if [ "$VERBOSE" = "true" ];then
    verbose_tar="v"
fi
if [ -n "${SPLIT_DIR}" ]; then
    mkdir -p "$SPLIT_DIR"
    unsplited_tar="${CP_UNSPLITED_DIR}/agent-info.tar.gz"
    if [ `tar --help | grep absolute-names | wc -l` = "1" ]; then
        TAR_EXTRA_PARAMS="--absolute-names"
    else
        TAR_EXTRA_PARAMS=""
    fi
    
    cmd="tar ${verbose_tar}czf ${unsplited_tar} ${TAR_EXTRA_PARAMS} ${CP_INFO_DIR} ${conf_to_save} ${inner_conf_file_to_save} ${FILESYSTEM_PATH}/watchdog"
    if ! ${cmd}; then
        TAR_FAILED=true
    else
        split -b "$SPLIT_FILE_SIZE" "$unsplited_tar" "$SPLIT_DIR/$AGENT_INFO_FILE_NAME."
        cat "$SPLIT_DIR"/* > "$CP_INFO_PATH"
    fi
else
    cmd="tar -${verbose_tar}zcf ${CP_INFO_PATH} ${TAR_EXTRA_PARAMS} ${CP_INFO_DIR} ${conf_to_save} ${inner_conf_file_to_save} ${FILESYSTEM_PATH}/watchdog"
    if ! ${cmd}; then
        TAR_FAILED=true
    fi
fi

rm -rf "$CP_INFO_DIR"
rm -rf "$CP_UNSPLITED_DIR"
if [ $TAR_FAILED = true ]; then
    echo "Failed to create $CP_INFO_PATH"
    exit 1
fi

cp_print "cp-agent-info was successfully created in $CP_INFO_PATH"

# tar generation completed successfully - returning to cp-nano-cli.sh

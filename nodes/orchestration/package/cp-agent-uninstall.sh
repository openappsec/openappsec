#!/bin/sh

FILESYSTEM_PATH="/etc/cp"
LOG_FILE_PATH="/var/log"
USR_LIB_PATH="/usr/lib"
USR_SBIN_PATH="/usr/sbin"
INIT_D_PATH="/etc/init.d"
PACKAGES_DIR_PATH="packages"
ORCHESTRATION_NAME="orchestration"
LOG_PATH="nano_agent"
DEFAULT_EVENT_BUFFER_PATH="event_buffer"
CP_NANO_CTL="cpnano"
FORCE_STDOUT=true
CP_NANO_CTL_DEPRECATED="cp-ctl"
UNINSTALLATION_LOG_FILE="cp-nano-agent-uninstall.log"
var_arch="x86"
var_arch_flag=
var_gaia_release=1
var_mds_release=1

get_basename()
{
    if command -v basename &>/dev/null; then
        echo $(basename $1)
    else
        echo $(echo $1 | rev | cut -d / -f 1 | rev)
    fi
}

load_paths()
{
    [ -f /etc/environment ] && . "/etc/environment"
    if [ -n "${CP_ENV_FILESYSTEM}" ]; then
        FILESYSTEM_PATH=$CP_ENV_FILESYSTEM
    fi
    if [ -n "${CP_ENV_LOG_FILE}" ]; then
        LOG_FILE_PATH=$CP_ENV_LOG_FILE
    fi
    if [ -n "${CP_USR_LIB_PATH}" ]; then
        USR_LIB_PATH=$CP_USR_LIB_PATH
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CP_USR_LIB_PATH/cpnano
    fi
    if [ -n "${CP_USR_SBIN_PATH}" ]; then
        USR_SBIN_PATH=$CP_USR_SBIN_PATH
        export PATH=$PATH:$CP_USR_SBIN_PATH
    fi
    if [ -n "${CP_INIT_D_PATH}" ]; then
        INIT_D_PATH=$CP_INIT_D_PATH
    fi
}

load_paths

cp_print()
{
    if [ -n "$2" ] && [ "$2" = "true" ]; then
        printf "%b" "$1"
    fi
    time_stamp=$(date)
    printf "%b" "$1 [$time_stamp]" >>${LOG_FILE_PATH}/${LOG_PATH}/${UNINSTALLATION_LOG_FILE}
}

# Prerequisites for uninstallation
cur_uid=$(id -u)
if [ $cur_uid -ne 0 ]; then
    cp_print "Error, cp-nano-agent service uninstallation requires root permissions, please re-run as root" ${FORCE_STDOUT}
    exit 1
fi

ls -l /etc/ | grep release > /dev/null 2>&1
retval=$?

if [ $retval -eq 0 ]; then
    cat /etc/*release | grep -q "Gaia"
    var_gaia_release=$?
    cat /etc/*release | grep -q "Multi-Domain Security Management"
    var_mds_release=$?
fi

if [ $var_gaia_release -eq 0 ] || [ $var_mds_release -eq 0 ]; then
    var_arch="gaia"
    var_arch_flag="--gaia"
fi

cp_exec()
{
    var_cmd=$1
    var_std_out=$2
    # Send exec output to RES
    RES=$($var_cmd 2>&1)
    if ! [ -z "$RES" ]; then
        cp_print "$RES" $var_std_out
    fi
}

uninstall_services()
{
    for service in "${FILESYSTEM_PATH}/$PACKAGES_DIR_PATH"/*; do
        SERVICE_NAME=$(get_basename $service)
        UNINSTALL_FILE="$service/$SERVICE_NAME"
        if [ "$SERVICE_NAME" = "${ORCHESTRATION_NAME}" ]; then
            continue
        fi
        if [ ! -f "$UNINSTALL_FILE" ]; then
            cp_print "Uninstall file for service $service does not exist. File: $UNINSTALL_FILE"
        else
            cp_print "Uninstalling $SERVICE_NAME" ${FORCE_STDOUT}
            chmod +x "$UNINSTALL_FILE"
            "$UNINSTALL_FILE" --uninstall
        fi
    done
}

remove_event_buffer()
{
    cp_print "Removing event buffer directory.."
    if [ -d ${LOG_FILE_PATH}/${LOG_PATH}/$DEFAULT_EVENT_BUFFER_PATH ]; then
        cp_exec "rm -rf ${LOG_FILE_PATH}/${LOG_PATH}/$DEFAULT_EVENT_BUFFER_PATH"
    else
        cp_print "Event buffer directory was not found"
    fi
}

is_smb=0
if [ -f /pfrm2.0/bin/cposd ]; then
    is_smb=1
fi

INSTALLATION_TIME=$(date)
cp_print "Uninstalling Check Point Nano Agent [$INSTALLATION_TIME]" ${FORCE_STDOUT}
uninstall_services
${FILESYSTEM_PATH}/watchdog/cp-nano-watchdog --un-register ${FILESYSTEM_PATH}/${ORCHESTRATION_NAME}/cp-nano-orchestration $var_arch_flag
init_type="$INIT_D_PATH/nano_agent.init"
if [ $var_arch = "gaia" ]; then
    cp_exec "rm -f ${FWDIR}/bin/curl"
    cp_exec "rm -f ${CPDIR}/bin/openssl"
    dbset process:cp-nano-watchdog
    dbset process:cp-nano-watchdog:path
    dbset process:cp-nano-watchdog:arg:1
    dbset process:cp-nano-watchdog:runlevel
    dbset :save
    tellpm cp-nano-watchdog
    chkconfig --del $INIT_D_PATH/access_pre_init
elif [ -f "$init_type" ]; then
    cp_exec "$init_type stop"
    cp_exec "rm -f $init_type"
else
    cp_exec "service nano_agent stop"
    cp_exec "rm -f /etc/systemd/system/nano_agent.service"
    cp_exec "rm /sys/fs/cgroup/pids/system.slice/nano_agent.service"
    cp_exec "rm /sys/fs/cgroup/devices/system.slice/nano_agent.service"
    cp_exec "rm /etc/systemd/system/multi-user.target.wants/nano_agent.service"
fi

cp_exec "rm -rf ${FILESYSTEM_PATH}"
cp_exec "rm -f $USR_SBIN_PATH/cp_nano_agent_status"
cp_exec "rm -rf $USR_LIB_PATH/cpnano"
cp_exec "rm -f $USR_SBIN_PATH/cp-nano-agent-ctl"
cp_exec "rm -f $USR_SBIN_PATH/${CP_NANO_CTL}"
cp_exec "rm -f $USR_SBIN_PATH/${CP_NANO_CTL_DEPRECATED}"

if [ "$is_smb" = "1" ]; then
    cp_print "Removing SMB specific dirs..."
    cp_exec "rm -rf /storage/nano_agent/"
    cp_exec "rm -rf /var/log/nano_agent/"
    cp_exec "rm -f /pfrm2.0/etc/nano-egg-args"

    cp_print "Done."
fi

remove_event_buffer
exit 0

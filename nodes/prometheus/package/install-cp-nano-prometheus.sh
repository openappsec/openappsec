#!/bin/sh

#Nano Service Details
NANO_SERVICE_NAME="prometheus"
NANO_SERVICE_BIN_NAME="cp-nano-prometheus"
NANO_SERVICE_INSTALLATION_FOLDER="prometheus"
ATTACHMENT_BIN_NAME="cp-nano-prometheus"

#Installable Names
CFG_FILE_NAME="cp-nano-prometheus.cfg"
DBG_CONF_FILE_NAME="cp-nano-prometheus-debug-conf.json"
SERVICE_CONF_FILE_NAME="cp-nano-prometheus-conf.json"
NANO_SERVICE_BIN="prometheus"
ATTACHMENT_BIN="prometheus_attachment"

#Const variables
FORCE_STDOUT=true
INSTALLATION_TIME=$(date)
CP_NANO_LOG_PATH="/var/log/nano_agent"
CP_NANO_CONF_PATH="/etc/cp/conf"
NANO_SERVICE_INSTALLATION_PATH="/etc/cp/${NANO_SERVICE_INSTALLATION_FOLDER}"
NANO_SERVICE_BIN_PATH=${NANO_SERVICE_INSTALLATION_PATH}/${NANO_SERVICE_BIN_NAME}
NANO_SERVICE_CFG_PATH=${NANO_SERVICE_BIN_PATH}.cfg
ATTACHMENT_BIN_PATH=${NANO_SERVICE_INSTALLATION_PATH}/${ATTACHMENT_BIN_NAME}
DBG_CONF_PATH=${CP_NANO_CONF_PATH}/${NANO_SERVICE_BIN_NAME}-debug-conf.json
SERVICE_CONF_PATH=${CP_NANO_CONF_PATH}/${NANO_SERVICE_BIN_NAME}-conf.json
DBG_FILE_PATH=${CP_NANO_LOG_PATH}/${NANO_SERVICE_BIN_NAME}.dbg
INSTALLATION_LOG_FILE=${CP_NANO_LOG_PATH}/${NANO_SERVICE_BIN_NAME}-install.log

mkdir -p ${CP_NANO_LOG_PATH}
touch ${DBG_FILE_PATH}

cp_print()
{
    var_text=$1
    var_std_out=$2
    touch $INSTALLATION_LOG_FILE
    if [ -n "$var_std_out" ]; then
        if [ "$var_std_out" = "true" ]; then
            printf "%b\n" "$var_text"
        fi
    fi
    printf "%b\n" "$var_text" >> $INSTALLATION_LOG_FILE
}

cp_exec()
{
    var_cmd=$1
    var_std_out=$2
    # Send exec output to RES
    RES=$($var_cmd 2>&1)
    if [ -n "$RES" ]; then
        cp_print "$RES" "$var_std_out"
    fi
}

set_configuration()
{
    cp_exec "cp -n conf/${DBG_CONF_FILE_NAME} $DBG_CONF_PATH"
    cp_exec "/etc/cp/scripts/cpnano_debug --default --service prometheus"
    cp_exec "cp -n conf/${SERVICE_CONF_FILE_NAME} $SERVICE_CONF_PATH"
}

run_installation()
{
    cp_print "Starting installation of Check Point ${NANO_SERVICE_NAME} Nano service [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register ${ATTACHMENT_BIN_PATH}"
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register ${NANO_SERVICE_BIN_PATH}"
    
    att_path=$ATTACHMENT_BIN_PATH
    cmd_pid_att=$(ps -eo pid,cmd,args | awk -v srv=${att_path} '{if($2 ~ srv || $3 ~ srv) print $1}')
    srv_path=$NANO_SERVICE_BIN_NAME
    cmd_pid_srv=$(ps -eo pid,cmd,args | awk -v srv=${srv_path} '{if($2 ~ srv || $3 ~ srv) print $1}')
    
    if [ -n "$cmd_pid_att"  ]; then
        cp_print "Killing running instance(pid=$cmd_pid_att) of the prometheus attachment on installation"
        kill -9 "$cmd_pid_att"
    fi
    if [ -n "$cmd_pid_srv"  ]; then
        cp_print "Killing running instance(pid=$cmd_pid_srv) of the prometheus service on installation"
        kill -9 "$cmd_pid_srv"
    fi

    cp_exec "mkdir -p ${NANO_SERVICE_INSTALLATION_PATH}"
    cp_exec "cp -f bin/${NANO_SERVICE_BIN} ${NANO_SERVICE_BIN_PATH}"
    cp_exec "chmod +x ${NANO_SERVICE_BIN_PATH}"
    cp_exec "cp -f conf/${CFG_FILE_NAME} ${NANO_SERVICE_CFG_PATH}"
    cp_exec "chmod 600 ${NANO_SERVICE_CFG_PATH}"

    set_configuration

    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --register ${NANO_SERVICE_BIN_PATH}"
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --register ${ATTACHMENT_BIN_PATH}"

    cp_print "Installation completed successfully." $FORCE_STDOUT
}

usage()
{
    echo "Check Point: available flags are"
    echo "--install           : install ${NANO_SERVICE_NAME} Nano Service"
    echo "--uninstall         : remove ${NANO_SERVICE_NAME} Nano Service"
    echo "--pre_install_test  : run Pre-installation test for ${NANO_SERVICE_NAME} Nano Service install package"
    echo "--post_install_test : run Post-installation test for ${NANO_SERVICE_NAME} Nano Service install package"
    exit 255
}

run_uninstall()
{
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register ${ATTACHMENT_BIN_PATH}"
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register ${NANO_SERVICE_BIN_PATH}"

    cp_exec "rm -rf ${NANO_SERVICE_INSTALLATION_PATH}"
    cp_exec "rm -rf ${NANO_SERVICE_CONF_DIR}"
}

run_pre_install_test()
{
    cp_print "Starting Pre-installation test of Check Point ${NANO_SERVICE_NAME} Nano service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    cp_print "Successfully finished pre-installation test for Check Point ${NANO_SERVICE_NAME} Nano service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    exit 0
}

run_post_install_test()
{
    cp_print "Starting Post-installation test of Check Point ${NANO_SERVICE_NAME} Nano service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    if ! cat /etc/cp/watchdog/wd.services | grep -q ${NANO_SERVICE_BIN_PATH}; then
    	    cp_print "Failed to register ${NANO_SERVICE_NAME} Nano service to the watchdog\n" $FORCE_STDOUT
    	    exit 255
    fi

    cp_print "Successfully finished post-installation test for Check Point ${NANO_SERVICE_NAME} Nano service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    exit 0

}

run()
{
    if [ '--install' = "$1" ]; then
        run_installation "${@}"
    elif [ '--uninstall' = "$1" ]; then
        run_uninstall
    elif [ '--pre_install_test' = "$1" ]; then
        run_pre_install_test
    elif [ '--post_install_test' = "$1" ]; then
        run_post_install_test
    else
        usage
        exit 1
    fi
}

if [ "$(id -u)" != "0" ]; then
    echo "Administrative privileges required for this Package (use su or sudo)"
    exit 1
fi

shift
run "${@}"

exit 0

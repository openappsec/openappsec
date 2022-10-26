#!/bin/sh

#Nano Service Detials
NANO_SERVICE_NAME="Attachment Registrator"
NANO_SERVICE_BIN_NAME="cp-nano-attachment-registrator"
NANO_SERVICE_INSTALLATION_FOLDER="attachmentRegistrator"

#Installable Names
CFG_FILE_NAME="cp-nano-attachment-registration-manager.cfg"
BDG_CONF_FILE_NAME="debug-conf.json"
SERVICE_CONF_FILE_NAME="service-conf.json"
NANO_SERVICE_BIN="attachment_registration_manager"

#Const variables
FORCE_STDOUT=true
INSTALLATION_TIME=$(date)
CP_NANO_LOG_PATH="/var/log/nano_agent"
CP_NANO_CONF_PATH="/etc/cp/conf"
CP_NANO_SHARED_PATH="/dev/shm/check-point"
NANO_SERVICE_INSTALLATION_PATH="/etc/cp/${NANO_SERVICE_INSTALLATION_FOLDER}"
NANO_SERVICE_BIN_PATH=${NANO_SERVICE_INSTALLATION_PATH}/${NANO_SERVICE_BIN_NAME}
NANO_SERVICE_CFG_PATH=${NANO_SERVICE_BIN_PATH}.cfg
DBG_CONF_PATH=${CP_NANO_CONF_PATH}/${NANO_SERVICE_BIN_NAME}-debug-conf.json
SERVICE_CONF_PATH=${CP_NANO_CONF_PATH}/${NANO_SERVICE_BIN_NAME}-conf.json
DBG_FILE_PATH=${CP_NANO_LOG_PATH}/${NANO_SERVICE_BIN_NAME}.dbg
INSTALLATION_LOG_FILE=${CP_NANO_LOG_PATH}/${NANO_SERVICE_BIN_NAME}-install.log

mkdir -p ${CP_NANO_LOG_PATH}
mkdir -p ${CP_NANO_SHARED_PATH}
chmod 777 ${CP_NANO_SHARED_PATH}
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
    cp_exec "cp -n conf/${BDG_CONF_FILE_NAME} $DBG_CONF_PATH"
    cp_exec "/etc/cp/scripts/cpnano_debug --default --service attachment-registrator"
    cp_exec "cp -n conf/${SERVICE_CONF_FILE_NAME} $SERVICE_CONF_PATH"
    if cat $SERVICE_CONF_PATH | grep -q '"/agents/log'; then
        sed -i 's|"/agents/log|"/api/v1/agents/events|' $SERVICE_CONF_PATH
    fi
}

run_installation()
{
    cp_print "Starting installation of Check Point ${NANO_SERVICE_NAME} Nano service [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register ${NANO_SERVICE_BIN_PATH}"
    
    ARCH=$(cat /etc/cp/watchdog/platform)
    srv_path=$NANO_SERVICE_INSTALLATION_PATH/$NANO_SERVICE_BIN_NAME
    if [ "$ARCH" = "arm" ]; then
        cmd_pid=$(ps | awk -v srv=${srv_path} '{if($5==srv) print $1}')
    elif [ "$ARCH" = "alpine" ]; then
        cmd_pid=$(ps -ef | awk -v srv=${srv_path} '{if($4 ~ srv || $3 ~ srv) print $1}')
    else
        cmd_pid=$(ps -eo pid,cmd,args | awk -v srv=${srv_path} '{if($2 ~ srv || $3 ~ srv) print $1}')
    fi
    
    if [ -n "$cmd_pid"  ]; then
        cp_print "Killing running instance(pid=$cmd_pid) of the attachment registrator service on installation"
        kill -9 "$cmd_pid"
    fi
    
    cp_exec "mkdir -p ${NANO_SERVICE_INSTALLATION_PATH}"
    cp_exec "cp -f bin/${NANO_SERVICE_BIN} ${NANO_SERVICE_BIN_PATH}"
    cp_exec "chmod +x ${NANO_SERVICE_BIN_PATH}"
    cp_exec "cp -f conf/${CFG_FILE_NAME} ${NANO_SERVICE_CFG_PATH}"
    cp_exec "chmod 600 ${NANO_SERVICE_CFG_PATH}"

    set_configuration

    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --register ${NANO_SERVICE_BIN_PATH}"

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
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register ${NANO_SERVICE_BIN_PATH}"

    cp_exec "rm -rf ${NANO_SERVICE_INSTALLATION_PATH}"
    cp_exec "rm -rf ${NANO_SERVICE_CONF_DIR}"
    cp_exec "rm -rf ${CP_NANO_SHARED_PATH}"
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

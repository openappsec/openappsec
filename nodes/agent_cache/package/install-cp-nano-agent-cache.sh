#!/bin/sh

FORCE_STDOUT=true
INSTALLATION_LOG_FILE="/var/log/nano_agent/install-cp-nano-agent-cache.log"
INSTALLATION_TIME=$(date)
CONF_PATH=/etc/cp/conf
CACHE_SERVICE_PATH=/etc/cp/agentCache
WATCHDOG_PATH=/etc/cp/watchdog/cp-nano-watchdog
USR_LIB_PATH="/usr/lib"

export INSTALL_COMMAND
is_install="$(command -v install)"
if [ -z ${is_install} ]; then
    INSTALL_COMMAND="cp -f"
    cp_print "[WARNING]: install command not found - using cp instead" ${FORCE_STDOUT}
else
    INSTALL_COMMAND=install
fi

mkdir -p /var/log/nano_agent

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

run_installation()
{
    cp_print "Starting installation of Check Point Cache service [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    cp_exec "${WATCHDOG_PATH} --un-register ${CACHE_SERVICE_PATH}/cp-nano-agent-cache"
    cp_exec "mkdir -p ${CACHE_SERVICE_PATH}"
    cp_exec "mkdir -p ${USR_LIB_PATH}/cpnano"
    cp_exec "cp -rf lib/* ${USR_LIB_PATH}/cpnano"
    cp_exec "cp -rf bin/redis-server ${CACHE_SERVICE_PATH}/"
    cp_exec "cp -rf bin/redis-cli ${CACHE_SERVICE_PATH}/"
    cp_exec "cp -f cp-nano-agent-cache.cfg ${CACHE_SERVICE_PATH}/cp-nano-agent-cache.cfg"
    cp_exec "cp -f cache.conf ${CONF_PATH}/redis.conf"
    cp_exec "mv ${CACHE_SERVICE_PATH}/redis-server ${CACHE_SERVICE_PATH}/cp-nano-agent-cache"
    cp_exec "mv ${CACHE_SERVICE_PATH}/redis-cli ${CACHE_SERVICE_PATH}/cp-nano-cache-cli"
    cp_exec "chmod +x ${CACHE_SERVICE_PATH}/cp-nano-agent-cache"
    cp_exec "chmod +x ${CACHE_SERVICE_PATH}/cp-nano-cache-cli"
    cp_exec "chmod 600 ${CACHE_SERVICE_PATH}/cp-nano-agent-cache.cfg"
    cp_exec "chmod 600 ${CONF_PATH}/redis.conf"

    cp_exec "${WATCHDOG_PATH} --register ${CACHE_SERVICE_PATH}/cp-nano-agent-cache"
    cp_print "Installation completed successfully." $FORCE_STDOUT
}

usage()
{
    echo "Check Point: available flags are"
    echo "--install           : install agent inteligence Service"
    echo "--uninstall         : remove agent inteligenceService"
    echo "--pre_install_test  : run Pre-installation test for agent inteligence Service install package"
    echo "--post_install_test : run Post-installation test for agent inteligence Service install package"
    exit 255
}

run_uninstall()
{
    cp_print "Starting uninstall of Check Point Cache service [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    cp_exec "${WATCHDOG_PATH} --un-register ${CACHE_SERVICE_PATH}/cp-nano-agent-cache"
    cp_exec "rm -rf ${CACHE_SERVICE_PATH}/"
    cp_exec "rm -rf ${CONF_PATH}/redis.conf"

    cp_print "Check Point Cache service was removed successfully\n" $FORCE_STDOUT
}

run_pre_install_test()
{
    cp_print "Successfully finished pre-installation test for Check Point Cache service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    exit 0
}

run_post_install_test()
{
    if [ ! -d ${CACHE_SERVICE_PATH} ]; then
        cp_print "Failed post-installation test for Check Point Cache service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
        exit 1
    fi

    cp_print "Successfully finished post-installation test for Check Point Cache service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
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

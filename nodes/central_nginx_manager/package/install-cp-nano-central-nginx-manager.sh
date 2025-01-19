#!/bin/sh

FORCE_STDOUT=true
INSTALLATION_LOG_FILE="/var/log/nano_agent/install-cp-nano-central-nginx-manager.log"
INSTALLATION_TIME=$(date)
CONF_PATH=/etc/cp/conf
SERVICE_PATH=/etc/cp/centralNginxManager
WATCHDOG_PATH=/etc/cp/watchdog/cp-nano-watchdog
NGINX_CONF_PATH="/etc/nginx/nginx.conf"
CENTRAL_NGINX_CONF_PATH="/tmp/central_nginx.conf"

export INSTALL_COMMAND
is_install="$(command -v install)"
if [ -z ${is_install} ]; then
    INSTALL_COMMAND="cp -f"
    cp_print "[WARNING]: install command not found - using cp instead" ${FORCE_STDOUT}
else
    INSTALL_COMMAND=install
fi

mkdir -p /var/log/nano_agent
mkdir -p /tmp/

cp_print()
{
    var_text=${1}
    var_std_out=${2}
    touch ${INSTALLATION_LOG_FILE}
    if [ -n "${var_std_out}" ]; then
        if [ "${var_std_out}" = "true" ]; then
            printf "%b\n" "${var_text}"
        fi
    fi
    printf "%b\n" "${var_text}" >> ${INSTALLATION_LOG_FILE}
}

cp_exec()
{
    var_cmd=${1}
    var_std_out=${2}
    # Send exec output to RES
    RES=$(${var_cmd} 2>&1)
    if [ -n "${RES}" ]; then
        cp_print "${RES}" "${var_std_out}"
    fi
}

is_nginx_installed()
{
    if [ -x "$(command -v nginx)" ]; then
        return 0
    fi

    return 1
}

get_nginx_conf_path()
{
    if ! is_nginx_installed; then
        return
    fi

    NGINX_CONF_PATH=$(nginx -V 2>&1 | grep -o '\--conf-path=[^ ]*' | cut -d= -f2)
    if [ -z "${NGINX_CONF_PATH}" ]; then
        NGINX_CONF_PATH="/etc/nginx/nginx.conf"
    fi
}

run_installation()
{
    cp_print "Starting installation of Check Point Central NGINX Manager [${INSTALLATION_TIME}]\n" ${FORCE_STDOUT}
    cp_exec "${WATCHDOG_PATH} --un-register ${SERVICE_PATH}/cp-nano-central-nginx-manager"
    cp_exec "mkdir -p ${SERVICE_PATH}"
    cp_exec "mkdir -p ${CONF_PATH}/centralNginxManager/shared"

    cp_exec "touch ${CONF_PATH}/centralNginxManager/shared/central_nginx_shared.conf"
    cp_exec "${INSTALL_COMMAND} bin/cp-nano-central-nginx-manager ${SERVICE_PATH}/cp-nano-central-nginx-manager"
    cp_exec "${INSTALL_COMMAND} bin/cp-nano-nginx-conf-collector ${SERVICE_PATH}/cp-nano-nginx-conf-collector"
    cp_exec "${INSTALL_COMMAND} conf/cp-nano-central-nginx-manager.cfg ${CONF_PATH}/cp-nano-central-nginx-manager.cfg"
    cp_exec "${INSTALL_COMMAND} conf/cp-nano-central-nginx-manager-conf.json ${CONF_PATH}/cp-nano-central-nginx-manager-conf.json"
    cp_exec "${INSTALL_COMMAND} conf/cp-nano-central-nginx-manager-debug-conf.json ${CONF_PATH}/cp-nano-central-nginx-manager-debug-conf.json"
    cp_exec "chmod +x ${SERVICE_PATH}/cp-nano-central-nginx-manager"
    cp_exec "chmod +x ${SERVICE_PATH}/cp-nano-nginx-conf-collector"
    cp_exec "chmod 600 ${CONF_PATH}/cp-nano-central-nginx-manager.cfg"
    cp_exec "chmod 600 ${CONF_PATH}/cp-nano-central-nginx-manager-conf.json"

    cp_exec "${WATCHDOG_PATH} --register ${SERVICE_PATH}/cp-nano-central-nginx-manager"
    cp_print "Installation completed successfully." ${FORCE_STDOUT}
}

usage()
{
    echo "Check Point: available flags are"
    echo "--install           : install central nginx manager"
    echo "--uninstall         : remove central nginx manager"
    echo "--pre_install_test  : run Pre-installation test for central nginx manager install package"
    echo "--post_install_test : run Post-installation test for central nginx manager install package"
    exit 255
}

run_uninstall()
{
    cp_print "Starting uninstall of Check Point Central NGINX Manager service [${INSTALLATION_TIME}]\n" ${FORCE_STDOUT}

    cp_exec "${WATCHDOG_PATH} --un-register ${SERVICE_PATH}/cp-nano-central-nginx-manager"
    cp_exec "rm -rf ${SERVICE_PATH}/"
    cp_exec "rm -f ${CONF_PATH}/cp-nano-central-nginx-manager.cfg"
    cp_exec "rm -f ${CONF_PATH}/cp-nano-central-nginx-manager-conf.json"

    if [ -f "${CENTRAL_NGINX_CONF_PATH}.base" ]; then
        cp_print "Restoring central NGINX configuration file" ${FORCE_STDOUT}
        cp_exec "${INSTALL_COMMAND} ${CENTRAL_NGINX_CONF_PATH}.base ${NGINX_CONF_PATH}"
        if is_nginx_installed; then
            if nginx -t > /dev/null 2>&1; then
                cp_exec "nginx -s reload"
            else
                cp_print "Could not reload central NGINX configuration, run 'nginx -t' for more details." ${FORCE_STDOUT}
            fi
        fi
    fi

    if [ -f "${NGINX_CONF_PATH}.orig" ]; then
        cp_print "Original (pre Check Point Nano Agent deployment) NGINX configuration file can be found at: ${NGINX_CONF_PATH}.orig" ${FORCE_STDOUT}
    fi
    cp_print "Check Point Central NGINX Manager service was removed successfully\n" ${FORCE_STDOUT}
}

run_pre_install_test()
{
    cp_print "Successfully finished pre-installation test for Check Point Central NGINX Manager service installation package [${INSTALLATION_TIME}]\n" ${FORCE_STDOUT}
    exit 0
}

run_post_install_test()
{
    if [ ! -d ${SERVICE_PATH} ]; then
        cp_print "Failed post-installation test for Check Point Central NGINX Manager service installation package [${INSTALLATION_TIME}]\n" ${FORCE_STDOUT}
        exit 1
    fi

    cp_print "Successfully finished post-installation test for Check Point Central NGINX Manager service installation package [${INSTALLATION_TIME}]\n" ${FORCE_STDOUT}
    exit 0
}


run()
{
    get_nginx_conf_path
    if [ '--install' = "${1}" ]; then
        run_installation "${@}"
    elif [ '--uninstall' = "${1}" ]; then
        run_uninstall
    elif [ '--pre_install_test' = "${1}" ]; then
        run_pre_install_test
    elif [ '--post_install_test' = "${1}" ]; then
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

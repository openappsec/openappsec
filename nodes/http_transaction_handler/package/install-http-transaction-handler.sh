#!/bin/sh

FORCE_STDOUT=true
INSTALLATION_LOG_FILE="/var/log/nano_agent/cp-nano-http-transaction-handler-install.log"
SERVICE_DBG_CONF_PATH="/etc/cp/conf/cp-nano-http-transaction-handler-debug-conf.json"
INSTALLATION_TIME=$(date)

WAAP_POLICY_FOLDER_PATH=/etc/cp/conf/waap
IPS_POLICY_FOLDER_PATH=/etc/cp/conf/ips
SNORT_SCRIPTS_PATH=/etc/cp/scripts/

DEFAULT_HTTP_TRANSACTION_HANDLER_EVENT_BUFFER=/var/log/nano_agent/event_buffer/HTTP_TRANSACTION_HANDLER_events

HTTP_TRANSACTION_HANDLER_PATH=/etc/cp/HttpTransactionHandler
HTTP_TRANSACTION_HANDLER_FILE=cp-nano-http-transaction-handler

env_details_file=/etc/cp/conf/environment-details.cfg

if [ -f "$env_details_file" ]; then
    . $env_details_file
fi

IS_K8S_ENV=false
K8S_TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
if [ -f $K8S_TOKEN_PATH ]; then
    IS_K8S_ENV=true
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

export INSTALL_COMMAND
is_install="$(command -v install)"
if [ -z ${is_install} ]; then
    INSTALL_COMMAND="cp -f"
    cp_print "[WARNING]: install command not found - using cp instead" ${FORCE_STDOUT}
else
    INSTALL_COMMAND=install
fi

handle_upgrade_from_http_manager()
{
    if [ -f "/etc/cp/conf/cp-nano-http-manager-debug-conf.json" ]; then
        cp_exec "mv /etc/cp/conf/cp-nano-http-manager-debug-conf.json $SERVICE_DBG_CONF_PATH"
        cp_exec "sed -i 's|cp-nano-http-manager.dbg|cp-nano-http-transaction-handler.dbg|g' $SERVICE_DBG_CONF_PATH"

        cp_exec "/etc/cp/scripts/cpnano_debug --default --service http-transaction-handler"
    fi

    if [ -f "/var/logs/nano_agent/event_buffer/http_manager_events" ]; then
        cp_exec "mv /var/logs/nano_agent/event_buffer/http_manager_events /var/logs/nano_agent/event_buffer/http_transaction_handler_events"
    fi
}

install_waap()
{
    cp_exec "mkdir -p /etc/waf2_engine/conf"
    cp_exec "mkdir -p /var/waf2_engine/current"
    cp_exec "mkdir -p /var/waf2_engine/baseline"
    cp_exec "mkdir -p /var/waf2_engine/baseline/signatures"
    cp_exec "mkdir -p /var/waf2_engine/waf2_engine"
    cp_exec "mkdir -p /usr/share/waf2_engine"
    # /etc/cp/conf/waap/ is created in install_policy
    cp_exec "cp -f resources/waap.data /etc/cp/conf/waap/"
    cp_exec "cp -f resources/cp-ab.js /etc/cp/conf/waap/"
    cp_exec "cp -f resources/cp-csrf.js /etc/cp/conf/waap/"
    cp_exec "chmod 777 /etc/cp/conf/waap/cp-ab.js"
    cp_exec "chmod 777 /etc/cp/conf/waap/cp-csrf.js"

    # use advanced model if exist as data for waap
    ADVANCED_MODEL_FILE=/advanced-model/open-appsec-advanced-model.tgz
    if [ -f "$ADVANCED_MODEL_FILE" ]; then
        cp_exec "tar -xzf $ADVANCED_MODEL_FILE -C /etc/cp/conf/waap"
    fi
}

set_debug_configuration()
{
    cp_exec "cp conf/cp-nano-http-transaction-handler-debug-conf.json $SERVICE_DBG_CONF_PATH"
    cp_exec "chmod 600 $SERVICE_DBG_CONF_PATH"

    cp_exec "/etc/cp/scripts/cpnano_debug --default --service http-transaction-handler"
}

install_configuration_files()
{
    # This file defines $execution_flags
    . conf/cp-nano-http-transaction-handler.cfg

    for conf_file in $execution_flags ; do
        if [ -f "$conf_file" ]; then
            continue
        fi
        mkdir -p "$(dirname "$conf_file")"
        echo "{}" > "$conf_file"
    done
}

install_policy()
{
    debug_mode=$1
    certs_dir=$2

    if [ -z "$IS_CONTAINER_ENV" ]; then
        [ -f /etc/cp/conf/cp-nano-http-transaction-handler-conf.json ] || cp_exec "cp conf/cp-nano-http-transaction-handler-conf.json /etc/cp/conf/cp-nano-http-transaction-handler-conf.json"
    else
        [ -f /etc/cp/conf/cp-nano-http-transaction-handler-conf.json ] || cp_exec "cp conf/cp-nano-http-transaction-handler-conf-container.json /etc/cp/conf/cp-nano-http-transaction-handler-conf.json"
    fi
    cp_exec "chmod 600 /etc/cp/conf/cp-nano-http-transaction-handler-conf.json"
    if cat /etc/cp/conf/cp-nano-http-transaction-handler-conf.json | grep -q '"/agents/log'; then
        cp_print "upgrading link is working" $FORCE_STDOUT
        sed -i 's|"/agents/log|"/api/v1/agents/events|' /etc/cp/conf/cp-nano-http-transaction-handler-conf.json
    fi

    install_configuration_files

    set_debug_configuration

    if [ -n "$certs_dir" ] && ! cat /etc/cp/conf/cp-nano-http-transaction-handler-conf.json | grep -q "Trusted CA directory"; then
        if [ -d "$certs_dir" ]; then
            if ! cat /etc/cp/conf/cp-nano-http-transaction-handler-conf.json | grep -q "message"; then
                sed -ie "0,/{/ s|{|{\"message\": {\"Trusted CA directory\": [{\"value\": \"$certs_dir\"}]},|" /etc/cp/conf/cp-nano-http-transaction-handler-conf.json
            else
                sed -ie "0,/\"message\"/ s|\"message\".*:.*{|\"message\": {\"Trusted CA directory\": [{\"value\": \"$certs_dir\"}],|" /etc/cp/conf/cp-nano-http-transaction-handler-conf.json
            fi
        else
            cp_print "Ignoring non existing certs directory '$certs_dir'" $FORCE_STDOUT
        fi
    fi

    handle_upgrade_from_http_manager
}

unregister_from_watchdog()
{
    cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register $HTTP_TRANSACTION_HANDLER_PATH/$HTTP_TRANSACTION_HANDLER_FILE --all"
    if [ "$IS_K8S_ENV" = "true" ]; then
        cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register $HTTP_TRANSACTION_HANDLER_PATH/k8s-log-file-handler.sh"
    fi
}

restart_service()
{
    if [ -z "$(which nginx)" ]; then
    	cp_exec "/etc/cp/watchdog/cp-nano-watchdog --restart $HTTP_TRANSACTION_HANDLER_PATH/$HTTP_TRANSACTION_HANDLER_FILE"
    else
        cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register $HTTP_TRANSACTION_HANDLER_PATH/$HTTP_TRANSACTION_HANDLER_FILE --all"
        cp_exec "nginx -s reload"
    fi

    if [ "$IS_K8S_ENV" = "true" ]; then
        cp_exec "/etc/cp/watchdog/cp-nano-watchdog --un-register $HTTP_TRANSACTION_HANDLER_PATH/k8s-log-file-handler.sh"
        cp_exec "/etc/cp/watchdog/cp-nano-watchdog --register $HTTP_TRANSACTION_HANDLER_PATH/k8s-log-file-handler.sh"
    fi
}

run_installation()
{
    cp_print "Starting installation of Check Point HTTP Transaction Handler service [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    is_debug_mode=false
    var_certs_dir=
    while true; do
        if [ "$1" = "--debug_on" ]; then
            is_debug_mode=true
        elif [ "$1" = "--certs-dir" ]; then
            shift
            var_certs_dir=$1
        elif [ -z "$1" ]; then
            break
        fi
        shift
    done

    cp_exec "mkdir -p $WAAP_POLICY_FOLDER_PATH"
    cp_exec "mkdir -p $IPS_POLICY_FOLDER_PATH"

    cp_exec "mkdir -p $HTTP_TRANSACTION_HANDLER_PATH"
    cp_exec "install bin/cp-nano-http-transaction-handler $HTTP_TRANSACTION_HANDLER_PATH/$HTTP_TRANSACTION_HANDLER_FILE"

    if [ "$IS_K8S_ENV" = "true" ]; then
        cp_exec "cp -f bin/k8s-log-file-handler.sh $HTTP_TRANSACTION_HANDLER_PATH/k8s-log-file-handler.sh"
        cp_exec "chmod +x $HTTP_TRANSACTION_HANDLER_PATH/k8s-log-file-handler.sh"
    fi

    cp_exec "chmod +x $HTTP_TRANSACTION_HANDLER_PATH/$HTTP_TRANSACTION_HANDLER_FILE"
    cp_exec "mkdir -p /usr/lib/cpnano"
    ${INSTALL_COMMAND} lib/* /usr/lib/cpnano/
    cp_exec "cp -f conf/cp-nano-http-transaction-handler.cfg $HTTP_TRANSACTION_HANDLER_PATH/$HTTP_TRANSACTION_HANDLER_FILE.cfg"
    cp_exec "chmod 600 $HTTP_TRANSACTION_HANDLER_PATH/$HTTP_TRANSACTION_HANDLER_FILE.cfg"
    cp_exec "cp -f conf/cp-nano-ips-protections.json /etc/cp/conf/data/cp-nano-ips-protections.data"
    cp_exec "rm -f /etc/cp/conf/cp-nano-ips-protections.json"
    cp_exec "chmod 600 /etc/cp/conf/data/cp-nano-ips-protections.data"

    install_policy $is_debug_mode "$var_certs_dir"
    install_waap

    cp_exec "cp -fr scripts/snort3_to_ips $SNORT_SCRIPTS_PATH/snort3_to_ips"
    cp_exec "cp -f  scripts/exception.py $SNORT_SCRIPTS_PATH/exception.py"
    cp_exec "cp -f scripts/snort_to_ips_local.py $SNORT_SCRIPTS_PATH/snort_to_ips_local.py"

    ${INSTALL_COMMAND} lib/libshmem_ipc.so /usr/lib/cpnano/
    ${INSTALL_COMMAND} lib/libcompression_utils.so /usr/lib/
    cp_exec "ldconfig"

    restart_service

    cp_print "Installation completed successfully." $FORCE_STDOUT
}

usage()
{
    echo "Check Point: available flags are"
    echo "--install           : install HTTP Transaction Handler Nano Service"
    echo "--uninstall         : remove HTTP Transaction Handler Nano Service"
    echo "--pre_install_test  : run Pre-installation test for HTTP Transaction Handler Nano Service install package"
    echo "--post_install_test : run Post-installation test for HTTP Transaction Handler Nano Service install package"
    exit 255
}

remove_event_buffer()
{
    if [ -f $DEFAULT_HTTP_TRANSACTION_HANDLER_EVENT_BUFFER ]; then
        cp_exec "rm -f $DEFAULT_HTTP_TRANSACTION_HANDLER_EVENT_BUFFER"
    else
        cp_print "Event buffer was not found"
    fi
}

run_uninstall()
{
    unregister_from_watchdog
    cp_exec "rm -rf $HTTP_TRANSACTION_HANDLER_PATH"
    remove_event_buffer
}

run_pre_install_test()
{
    cp_print "Starting Pre-installation test of Check Point HTTP Transaction Handler service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    # Nothing to test for HTTP Transaction Handler pre-installation

    cp_print "Successfully finished pre-installation test for Check Point HTTP Transaction Handler service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    exit 0
}

run_post_install_test()
{
    cp_print "Starting Post-installation test of Check Point HTTP Transaction Handler service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    # Nothing to test for HTTP Transaction Handler post-installation

    cp_print "Successfully finished post-installation test for Check Point HTTP Transaction Handler service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    exit 0
}

run()
{
    if [ '--install' = "$1" ]; then
        shift
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
    echo "Administrative privileges required for this package (use su or sudo)"
    exit 1
fi

shift
run "${@}"

exit 0

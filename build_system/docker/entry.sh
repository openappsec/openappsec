#!/bin/bash

INTELLIGENCE_INSTALLATION_SCRIPT="install-cp-agent-intelligence-service.sh"
CROWDSEC_INSTALLATION_SCRIPT="install-cp-crowdsec-aux.sh"
HTTP_TRANSACTION_HANDLER_SERVICE="install-cp-nano-service-http-transaction-handler.sh"
ATTACHMENT_REGISTRATION_SERVICE="install-cp-nano-attachment-registration-manager.sh"
ORCHESTRATION_INSTALLATION_SCRIPT="install-cp-nano-agent.sh"
CACHE_INSTALLATION_SCRIPT="install-cp-nano-agent-cache.sh"

var_fog_address=
var_proxy=
var_mode=
var_token=
init=

if [ ! -f /nano-service-installers/$ORCHESTRATION_INSTALLATION_SCRIPT ]; then
    echo "Error: agent installation package doesn't exist."
    exit 1
fi

while true; do
    if [ -z "$1" ]; then
        break
    elif [ "$1" == "--fog" ]; then
        shift
        var_fog_address="$1"
    elif [ "$1" == "--proxy" ]; then
        shift
        var_proxy="$1"
    elif [ "$1" == "--hybrid-mode" ]; then
        var_mode="--hybrid_mode"
    elif [ "$1" == "--token" ]; then
        shift
        var_token="$1"
    elif [ "$1" == "--standalone" ]; then
        var_mode="--hybrid_mode"
        var_token="cp-3fb5c718-5e39-47e6-8d5e-99b4bc5660b74b4b7fc8-5312-451d-a763-aaf7872703c0"
    fi
    shift
done

if [ -z $var_token ]; then
    echo "Error: Token was not provided as input argument."
    exit 1
fi

orchestration_service_installation_flags="--token $var_token --container_mode --skip_registration"
if [ ! -z $var_fog_address ]; then
    orchestration_service_installation_flags="$orchestration_service_installation_flags --fog $var_fog_address"
fi
if [ ! -z $var_proxy ]; then
    orchestration_service_installation_flags="$orchestration_service_installation_flags --proxy $var_proxy"
fi

if [ ! -z $var_mode ]; then
    orchestration_service_installation_flags="$orchestration_service_installation_flags $var_mode"
fi


/nano-service-installers/$ORCHESTRATION_INSTALLATION_SCRIPT --install $orchestration_service_installation_flags

if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    /etc/cp/orchestration/k8s-check-update-listener.sh &
fi

/nano-service-installers/$ATTACHMENT_REGISTRATION_SERVICE --install
/nano-service-installers/$CACHE_INSTALLATION_SCRIPT --install
/nano-service-installers/$HTTP_TRANSACTION_HANDLER_SERVICE --install

if [ ! -z $CROWDSEC_ENABLED ]; then
    /nano-service-installers/$INTELLIGENCE_INSTALLATION_SCRIPT --install
    /nano-service-installers/$CROWDSEC_INSTALLATION_SCRIPT --install
fi

# use advanced model if exist as data for agent
FILE=/advanced-model/open-appsec-advanced-model.tgz
if [ -f "$FILE" ]; then
    tar -xzvf $FILE -C /etc/cp/conf/waap
fi

touch /etc/cp/watchdog/wd.startup
while true; do
    if [ -z "$init" ]; then
        init=true
        /etc/cp/watchdog/cp-nano-watchdog >/dev/null 2>&1 &
        sleep 5
        active_watchdog_pid=$(pgrep -f -x -o "/bin/bash /etc/cp/watchdog/cp-nano-watchdog")
    fi

    current_watchdog_pid=$(pgrep -f -x -o "/bin/bash /etc/cp/watchdog/cp-nano-watchdog")
    if [ ! -f /tmp/restart_watchdog ] && [ "$current_watchdog_pid" != "$active_watchdog_pid" ]; then
        echo "Error: Watchdog exited abnormally"
        exit 1
    elif [ -f /tmp/restart_watchdog ]; then
        rm -f /tmp/restart_watchdog
        kill -9 "$(pgrep -f -x -o "/bin/bash /etc/cp/watchdog/cp-nano-watchdog")"
        /etc/cp/watchdog/cp-nano-watchdog >/dev/null 2>&1 &
        sleep 5
        active_watchdog_pid=$(pgrep -f -x -o "/bin/bash /etc/cp/watchdog/cp-nano-watchdog")
    fi

    sleep 5
done

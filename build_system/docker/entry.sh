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
var_ignore=
init=

if [ ! -f /nano-service-installers/$ORCHESTRATION_INSTALLATION_SCRIPT ]; then
    echo "Error: agent installation package doesn't exist."
    exit 1
fi

if [ -z $1 ]; then
    var_mode="--hybrid_mode"
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
    elif [ "$1" == "--hybrid-mode" ] || [ "$1" == "--standalone" ]; then
        var_mode="--hybrid_mode"
    elif [ "$1" == "--no-upgrade" ]; then
        var_ignore="--ignore all"
    elif [ "$1" == "--token" ]; then
        shift
        var_token="$1"
    fi
    shift
done

if [ -z $var_token ] && [ $var_mode != "--hybrid_mode" ]; then
    var_token=$(env | grep 'AGENT_TOKEN=' | cut -d'=' -f2-)
    if  [ -z $var_token ]; then
        echo "Error: Token was not provided as input argument."
        exit 1
    fi
fi

orchestration_service_installation_flags="--container_mode --skip_registration"
if [ ! -z $var_token ]; then
    export AGENT_TOKEN="$var_token"
    orchestration_service_installation_flags="$orchestration_service_installation_flags --token $var_token"
fi
if [ ! -z $var_fog_address ]; then
    orchestration_service_installation_flags="$orchestration_service_installation_flags --fog $var_fog_address"
fi
if [ ! -z $var_proxy ]; then
    orchestration_service_installation_flags="$orchestration_service_installation_flags --proxy $var_proxy"
fi

if [ ! -z $var_mode ]; then
    orchestration_service_installation_flags="$orchestration_service_installation_flags $var_mode"
fi
if [ ! -z "$var_ignore" ]; then
    orchestration_service_installation_flags="$orchestration_service_installation_flags $var_ignore"
fi


/nano-service-installers/$ORCHESTRATION_INSTALLATION_SCRIPT --install $orchestration_service_installation_flags

if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    /etc/cp/orchestration/k8s-check-update-listener.sh &
fi

/nano-service-installers/$ATTACHMENT_REGISTRATION_SERVICE --install
/nano-service-installers/$CACHE_INSTALLATION_SCRIPT --install
/nano-service-installers/$HTTP_TRANSACTION_HANDLER_SERVICE --install

if [ "$CROWDSEC_ENABLED" == "true" ]; then
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
        active_watchdog_pid=$(pgrep -f -x -o "/bin/(bash|sh) /etc/cp/watchdog/cp-nano-watchdog")
    fi

    current_watchdog_pid=$(pgrep -f -x -o "/bin/(bash|sh) /etc/cp/watchdog/cp-nano-watchdog")
    if [ ! -f /tmp/restart_watchdog ] && [ "$current_watchdog_pid" != "$active_watchdog_pid" ]; then
        echo "Error: Watchdog exited abnormally"
        exit 1
    elif [ -f /tmp/restart_watchdog ]; then
        rm -f /tmp/restart_watchdog
        kill -9 "$(pgrep -f -x -o "/bin/(bash|sh) /etc/cp/watchdog/cp-nano-watchdog")"
        /etc/cp/watchdog/cp-nano-watchdog >/dev/null 2>&1 &
        sleep 5
        active_watchdog_pid=$(pgrep -f -x -o "/bin/(bash|sh) /etc/cp/watchdog/cp-nano-watchdog")
    fi

    sleep 5
done

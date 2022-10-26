#!/bin/bash

APISERVER=https://kubernetes.default.svc
SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat ${SERVICEACCOUNT}/token)
NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
CACERT=${SERVICEACCOUNT}/ca.crt

PID_LIST_BACKUP_PATH=/etc/cp/orchestration/hybrid-check-update.pid

UPON_UPDATE=/etc/cp/orchestration/k8s-check-update-trigger.sh

ingress_pid=uninitialized
practice_pid=uninitialized
trigger_pid=uninitialized
web_user_respond_pid=uninitialized
exception_pid=uninitialized
policy_pid=uninitialized

function runGetResourceListener()
{
    if [ "$1" = "ingress" ]; then
        curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/apis/networking.k8s.io/v1/ingresses?watch=1 | ${UPON_UPDATE} &
    else
        curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/apis/openappsec.io/v1beta1/${1}?watch=1 | ${UPON_UPDATE} &
    fi
}

function saveRuningPids()
{
    echo -e "${ingress_pid}\n${practice_pid}\n${trigger_pid}\n${web_user_respond_pid}\n${exception_pid}\n${policy_pid}\n" > ${PID_LIST_BACKUP_PATH}
}

for pid in $(cat ${PID_LIST_BACKUP_PATH}) ; do
    if [ -f /proc/${pid}/cmdline ] && [ -n "$(cat /proc/${pid}/cmdline | grep curl)" ] &&  [ -n "$(cat /proc/${pid}/cmdline | grep kubernetes | grep watch)" ]; then
        kill -9 ${pid}
    fi
done

while true; do
    var_is_hybrid_mode="$(cat /etc/cp/conf/agent_details.json | grep "Orchestration mode" | grep "hybrid_mode")"
    var_is_openappsec="$(cat /etc/cp/conf/agent_details.json | grep "Tenant ID" | grep "org_")"
    if [ -z "${var_is_hybrid_mode}" ] && [ -z "${var_is_openappsec}" ]; then
        sleep 5
        continue
    fi
    if [ ! -d /proc/${ingress_pid} ]; then
        runGetResourceListener ingress
        ingress_pid=$!
        saveRuningPids
    fi
    if [ ! -d /proc/${practice_pid} ]; then
        runGetResourceListener practices
        practice_pid=$!
        saveRuningPids
    fi
    if [ ! -d /proc/${trigger_pid} ]; then
        runGetResourceListener logtriggers
        trigger_pid=$!
        saveRuningPids
    fi
    if [ ! -d /proc/${web_user_respond_pid} ]; then
        runGetResourceListener customresponses
        web_user_respond_pid=$!
        saveRuningPids
    fi
    if [ ! -d /proc/${exception_pid} ]; then
        runGetResourceListener exceptions
        exception_pid=$!
        saveRuningPids
    fi
        if [ ! -d /proc/${exception_pid} ]; then
        runGetResourceListener policies
        policy_pid=$!
        saveRuningPids
    fi
    sleep 5
done


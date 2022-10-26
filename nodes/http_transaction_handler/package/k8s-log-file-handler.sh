#!/bin/bash

while true; do
    var_is_hybrid_mode="$(cat /etc/cp/conf/agent_details.json | grep "Orchestration mode" | grep "hybrid_mode")"
    var_is_openappsec="$(cat /etc/cp/conf/agent_details.json | grep "Tenant ID" | grep "org_")"
    if [ -z "${var_is_hybrid_mode}" ] && [ -z "${var_is_openappsec}" ]; then
        sleep 5
        continue
    fi
    tail -q -f /var/log/nano_agent/cp-nano-http-transaction-handler.log? >> /proc/1/fd/1
done
